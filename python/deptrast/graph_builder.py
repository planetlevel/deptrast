"""Builds dependency graphs from package lists."""

import logging
from typing import List, Dict, Set, Optional, Collection
from collections import defaultdict

from .models import Package, DependencyNode
from .api_client import DepsDevClient

logger = logging.getLogger(__name__)


class DependencyGraphBuilder:
    """Builds complete dependency trees from a list of packages."""

    def __init__(self):
        """Initialize the graph builder."""
        self.api_client = DepsDevClient()
        self.complete_trees: Dict[str, DependencyNode] = {}
        self.all_packages: Dict[str, Package] = {}
        self.dependency_management: Dict[str, str] = {}
        self.exclusions: Dict[str, Set[str]] = {}

    def set_dependency_management(self, management: Dict[str, str]) -> None:
        """Set dependency management versions."""
        self.dependency_management = management or {}
        logger.info(f"DependencyManagement set with {len(self.dependency_management)} entries")

    def set_exclusions(self, exclusions: Dict[str, Set[str]]) -> None:
        """Set dependency exclusions."""
        self.exclusions = exclusions or {}
        logger.info(f"Exclusions set with {len(self.exclusions)} entries")

    def build_dependency_trees(self, input_packages: List[Package]) -> List[DependencyNode]:
        """
        Build dependency trees from input packages.

        Algorithm:
        1. Fetch complete dependency graph for each input package
        2. Track which INPUT packages appear as dependencies in OTHER trees
        3. Roots = input packages NOT appearing as dependencies
        """
        logger.info(f"Building dependency trees for {len(input_packages)} packages")

        # Step 1: Create set of input package names for quick lookup
        input_package_names = {pkg.full_name for pkg in input_packages}
        logger.debug(f"Input packages: {input_package_names}")

        # Step 2: Fetch complete dependency graph for each package
        packages_already_in_trees: Set[str] = set()
        skipped_count = 0

        for pkg in input_packages:
            pkg_name = pkg.full_name

            # Skip if already in another tree
            if pkg_name in packages_already_in_trees:
                logger.debug(f"Skipping {pkg_name} - already found in another dependency tree")
                skipped_count += 1
                continue

            tree = self._fetch_complete_dependency_tree(pkg, input_package_names)
            if tree:
                self.complete_trees[pkg_name] = tree
                self._collect_all_package_names(tree, packages_already_in_trees)

        if skipped_count > 0:
            logger.info(
                f"⚡ Optimization: Skipped {skipped_count} packages already found in other trees "
                f"({skipped_count} fewer API calls)"
            )

        # Step 2.5: Version reconciliation
        observed_versions = {
            f"{pkg.system}:{pkg.name}": pkg.version
            for pkg in input_packages
        }

        for tree in self.complete_trees.values():
            self._reconcile_tree_versions(tree, observed_versions, input_package_names)

        # Step 3: Find which INPUT packages appear as dependencies in OTHER trees
        input_packages_appearing_as_children: Set[str] = set()
        for tree_root_name, tree in self.complete_trees.items():
            self._find_input_packages_in_tree(
                tree, input_package_names, input_packages_appearing_as_children, tree_root_name
            )

        # Step 4: Roots = input packages that DON'T appear as children
        root_package_names = input_package_names - input_packages_appearing_as_children
        logger.info(f"Found {len(root_package_names)} root packages out of {len(input_packages)}")

        # Step 5: Return only the root trees
        root_trees = []
        for root_name in root_package_names:
            tree = self.complete_trees.get(root_name)
            if tree:
                tree.mark_as_root()
                root_trees.append(tree)

        return root_trees

    def _fetch_complete_dependency_tree(
        self, package: Package, input_package_names: Set[str]
    ) -> Optional[DependencyNode]:
        """Fetch the complete dependency tree for a package."""
        graph = self.api_client.get_dependency_graph(package)

        if not graph:
            logger.warning(f"WARNING: Unknown component {package.full_name}. Treating as root dependency.")
            return DependencyNode(package=package, depth=0)

        return self._parse_full_dependency_graph(graph, package, input_package_names)

    def _parse_full_dependency_graph(
        self, graph: Dict, root_package: Package, input_package_names: Set[str]
    ) -> Optional[DependencyNode]:
        """Parse the complete dependency graph from deps.dev response."""
        nodes = graph.get("nodes", [])
        edges = graph.get("edges", [])

        if not nodes or not edges:
            return DependencyNode(package=root_package, depth=0)

        # Build map: node index -> Package
        node_map: Dict[int, Package] = {}
        node_tree_map: Dict[int, DependencyNode] = {}
        self_node_index = -1

        # Process all nodes
        for i, node in enumerate(nodes):
            version_key = node.get("versionKey", {})
            system = version_key.get("system", "")
            name = version_key.get("name", "")
            version = version_key.get("version", "")
            relation = node.get("relation", "")

            # Check if we already have this package (deduplication)
            full_name = f"{system.lower()}:{name}:{version}"
            pkg = self.all_packages.get(full_name)

            if not pkg:
                pkg = Package(system=system, name=name, version=version)
                self.all_packages[full_name] = pkg

            node_map[i] = pkg
            node_tree_map[i] = DependencyNode(package=pkg, depth=0)

            # Find the SELF node
            if relation == "SELF":
                self_node_index = i

        # Build adjacency list from edges
        adjacency: Dict[int, List[int]] = defaultdict(list)
        for edge in edges:
            from_node = edge.get("fromNode")
            to_node = edge.get("toNode")
            if from_node is not None and to_node is not None:
                adjacency[from_node].append(to_node)

        # Build tree structure from SELF node
        if self_node_index != -1:
            self._build_tree_from_adjacency(
                node_tree_map, adjacency, self_node_index, 0, set()
            )
            return node_tree_map[self_node_index]

        return DependencyNode(package=root_package, depth=0)

    def _build_tree_from_adjacency(
        self,
        node_tree_map: Dict[int, DependencyNode],
        adjacency: Dict[int, List[int]],
        current_node: int,
        depth: int,
        visited: Set[int]
    ) -> None:
        """Recursively build tree structure from adjacency list."""
        # Prevent cycles
        if current_node in visited:
            return
        visited.add(current_node)

        current_tree_node = node_tree_map.get(current_node)
        if not current_tree_node:
            return

        # Get parent package for exclusion checks
        parent_pkg = current_tree_node.package
        parent_exclusions = self.exclusions.get(parent_pkg.name, set())

        children = adjacency.get(current_node, [])
        for child_index in children:
            child_pkg = node_tree_map[child_index].package

            # Check if excluded
            if self._is_excluded(child_pkg, parent_exclusions):
                logger.debug(f"Excluding dependency {child_pkg.name} from parent {parent_pkg.name}")
                continue

            # Create new node with correct depth
            new_child_node = DependencyNode(package=child_pkg, depth=depth + 1)
            current_tree_node.add_child(new_child_node)

            # Recursively build subtree
            self._build_child_subtree(
                new_child_node, node_tree_map, adjacency, child_index, depth + 1, visited.copy()
            )

    def _build_child_subtree(
        self,
        parent_node: DependencyNode,
        node_tree_map: Dict[int, DependencyNode],
        adjacency: Dict[int, List[int]],
        current_node_index: int,
        depth: int,
        visited: Set[int]
    ) -> None:
        """Build subtree for a child node."""
        if current_node_index in visited:
            return
        visited.add(current_node_index)

        parent_pkg = parent_node.package
        parent_exclusions = self.exclusions.get(parent_pkg.name, set())

        children = adjacency.get(current_node_index, [])
        for child_index in children:
            child_pkg = node_tree_map[child_index].package

            # Check if excluded
            if self._is_excluded(child_pkg, parent_exclusions):
                logger.debug(f"Excluding dependency {child_pkg.name} from parent {parent_pkg.name}")
                continue

            child_node = DependencyNode(package=child_pkg, depth=depth + 1)
            parent_node.add_child(child_node)

            # Recurse
            self._build_child_subtree(
                child_node, node_tree_map, adjacency, child_index, depth + 1, visited.copy()
            )

    def _is_excluded(self, package: Package, parent_exclusions: Set[str]) -> bool:
        """Check if a package should be excluded."""
        if not parent_exclusions:
            return False
        return package.name in parent_exclusions

    def _reconcile_tree_versions(
        self,
        node: DependencyNode,
        observed_versions: Dict[str, str],
        input_package_names: Set[str]
    ) -> None:
        """Reconcile versions in the dependency tree with actual runtime versions."""
        if not node:
            return

        pkg = node.package
        base_key = f"{pkg.system}:{pkg.name}"
        current_version = pkg.version
        reconciled_version = None

        # Priority 1: Check dependency management
        if pkg.name in self.dependency_management:
            managed_version = self.dependency_management[pkg.name]
            if managed_version != current_version:
                reconciled_version = managed_version
                logger.debug(
                    f"Applying managed version for {pkg.name}: {current_version} -> {managed_version}"
                )

        # Priority 2: Check observed versions
        if reconciled_version is None and base_key in observed_versions:
            observed_version = observed_versions[base_key]
            if observed_version != current_version:
                reconciled_version = observed_version
                logger.debug(
                    f"Applying observed version for {base_key}: {current_version} -> {observed_version}"
                )

        # Apply reconciled version
        if reconciled_version:
            logger.info(f"Reconciling {pkg.name} from {current_version} to {reconciled_version}")
            reconciled_pkg = Package(system=pkg.system, name=pkg.name, version=reconciled_version)
            node.package = reconciled_pkg

            # Fetch dependencies for new version
            logger.debug(f"Fetching dependencies for reconciled version {reconciled_pkg.full_name}")
            new_tree = self._fetch_complete_dependency_tree(reconciled_pkg, input_package_names)

            if new_tree and new_tree.children:
                # Replace children
                node.children.clear()
                for new_child in new_tree.children:
                    node.add_child(new_child)
                    self._reconcile_tree_versions(new_child, observed_versions, input_package_names)
                logger.debug(f"Replaced {len(new_tree.children)} children for reconciled {reconciled_pkg.full_name}")
                return  # Don't recurse into old children

        # Recurse into children
        for child in node.children:
            self._reconcile_tree_versions(child, observed_versions, input_package_names)

    def _find_input_packages_in_tree(
        self,
        node: DependencyNode,
        input_package_names: Set[str],
        input_packages_appearing_as_children: Set[str],
        tree_root_name: str
    ) -> None:
        """Recursively find which input packages appear in this tree."""
        if not node:
            return

        node_name = node.package.full_name

        # If this node is an input package (and not the tree root), mark it
        if node_name in input_package_names and node_name != tree_root_name:
            input_packages_appearing_as_children.add(node_name)

        # Recurse into children
        for child in node.children:
            self._find_input_packages_in_tree(
                child, input_package_names, input_packages_appearing_as_children, tree_root_name
            )

    def _collect_all_package_names(self, node: DependencyNode, package_names: Set[str]) -> None:
        """Recursively collect all package names from a dependency tree."""
        if not node:
            return

        package_names.add(node.package.full_name)

        for child in node.children:
            self._collect_all_package_names(child, package_names)

    def get_all_reconciled_packages(self) -> Collection[Package]:
        """
        Get all packages from the reconciled dependency trees.

        When multiple versions exist, keeps the managed version or highest version.
        """
        package_map: Dict[str, Package] = {}

        for tree in self.complete_trees.values():
            self._collect_packages_from_tree(tree, package_map)

        return package_map.values()

    def _collect_packages_from_tree(
        self, node: DependencyNode, package_map: Dict[str, Package]
    ) -> None:
        """Recursively collect packages from tree, keeping highest/managed version."""
        if not node:
            return

        pkg = node.package
        base_key = f"{pkg.system}:{pkg.name}"

        existing = package_map.get(base_key)
        if not existing:
            package_map[base_key] = pkg
        else:
            # Check for managed version
            managed_version = self.dependency_management.get(pkg.name)

            if managed_version:
                if pkg.version == managed_version:
                    package_map[base_key] = pkg
                    logger.debug(
                        f"Replaced {base_key} version {existing.version} with managed version {pkg.version}"
                    )
                elif existing.version == managed_version:
                    pass  # Keep existing
                elif self._compare_versions(pkg.version, existing.version) > 0:
                    package_map[base_key] = pkg
                    logger.debug(
                        f"Replaced {base_key} version {existing.version} with higher version {pkg.version}"
                    )
            else:
                # No managed version - use higher
                if self._compare_versions(pkg.version, existing.version) > 0:
                    package_map[base_key] = pkg
                    logger.debug(
                        f"Replaced {base_key} version {existing.version} with higher version {pkg.version}"
                    )

        for child in node.children:
            self._collect_packages_from_tree(child, package_map)

    def _compare_versions(self, v1: str, v2: str) -> int:
        """Simple version comparison. Returns >0 if v1 > v2, <0 if v1 < v2, 0 if equal."""
        if v1 == v2:
            return 0

        # Split by dots and dashes
        import re
        parts1 = re.split(r'[.\-]', v1)
        parts2 = re.split(r'[.\-]', v2)

        min_length = min(len(parts1), len(parts2))
        for i in range(min_length):
            part1 = parts1[i]
            part2 = parts2[i]

            # Try to parse as integers
            try:
                num1 = int(part1)
                num2 = int(part2)
                if num1 != num2:
                    return num1 - num2
            except ValueError:
                # Lexicographic comparison
                if part1 != part2:
                    return 1 if part1 > part2 else -1

        # Longer version is considered higher
        return len(parts1) - len(parts2)

    def close(self):
        """Close resources."""
        self.api_client.close()

    def __enter__(self):
        """Context manager entry."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.close()
