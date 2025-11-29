"""Builds dependency graphs from package lists."""

import logging
from typing import List, Dict, Set, Optional, Collection, Tuple
from collections import defaultdict, deque

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
        self.all_nodes: Dict[str, DependencyNode] = {}  # For graph node reuse across API calls
        self.dependency_management: Dict[str, str] = {}
        self.exclusions: Dict[str, Set[str]] = {}
        self.resolution_strategy: str = "highest"  # maven or highest

    def set_dependency_management(self, management: Dict[str, str]) -> None:
        """Set dependency management versions."""
        self.dependency_management = management or {}
        logger.info(f"DependencyManagement set with {len(self.dependency_management)} entries")

    def set_exclusions(self, exclusions: Dict[str, Set[str]]) -> None:
        """Set dependency exclusions."""
        self.exclusions = exclusions or {}
        logger.info(f"Exclusions set with {len(self.exclusions)} entries")

    def set_resolution_strategy(self, strategy: str) -> None:
        """Set version resolution strategy (maven or highest)."""
        self.resolution_strategy = strategy or "highest"
        logger.info(f"Resolution strategy set to: {self.resolution_strategy}")

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

            # Skip if we already have a complete tree for this package
            if pkg_name in self.complete_trees:
                logger.debug(f"Skipping {pkg_name} - already have complete tree")
                skipped_count += 1
                continue

            # Check if this package appears in any OTHER package's tree
            # If so, we still need to fetch its tree for cloning purposes
            found_in_other_tree = pkg_name in packages_already_in_trees

            tree = self._fetch_complete_dependency_tree(pkg, input_package_names)
            if tree:
                self.complete_trees[pkg_name] = tree

                if found_in_other_tree:
                    logger.debug(f"Package {pkg_name} found in another tree but fetched for cloning")
                    skipped_count += 1  # Still count as optimization since we found it earlier

                # Add all packages in this tree to the set to track what we've seen
                self._collect_all_package_names(tree, packages_already_in_trees)

        if skipped_count > 0:
            logger.info(
                f"⚡ Optimization: Skipped {skipped_count} packages already found in other trees "
                f"({skipped_count} fewer API calls)"
            )

        # Step 2.5/2.6: Version resolution strategy
        if self.resolution_strategy == "maven":
            # Maven nearest-wins: Use the version found nearest to the root in the dependency tree
            logger.info("Applying Maven nearest-wins version resolution")
            self._apply_nearest_wins_resolution(list(self.complete_trees.values()))
        else:
            # Default: Highest version reconciliation
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
                # DEBUG: Log hibernate-core root
                if "hibernate-core" in root_name:
                    logger.info(f"🔍 GERONIMO ROOT: Returning hibernate-core root (node id={id(tree)}, children={len(tree.children)})")
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

            # CRITICAL: Check if we already have this node from another package's graph
            # If we do, return the existing node (which may have children populated)
            # Don't create a new empty node that would lose the children!
            if package.full_name in self.all_nodes:
                logger.debug(f"Package {package.full_name} returned 404 but already exists in all_nodes with children - reusing")
                return self.all_nodes[package.full_name]

            # Only create new empty node if we've never seen this package before
            return DependencyNode(package=package)

        return self._parse_full_dependency_graph(graph, package, input_package_names)

    def _parse_full_dependency_graph(
        self, graph: Dict, root_package: Package, input_package_names: Set[str]
    ) -> Optional[DependencyNode]:
        """Parse the complete dependency graph from deps.dev response."""
        nodes = graph.get("nodes", [])
        edges = graph.get("edges", [])

        if not nodes or not edges:
            return DependencyNode(package=root_package)

        # Build map: node index -> Package
        # Also build ONE DependencyNode per unique package (graph, not tree!)
        node_map: Dict[int, Package] = {}
        node_graph_map: Dict[int, DependencyNode] = {}
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

            # Reuse existing DependencyNode if we've already created one for this package
            # Use the class-level all_nodes map to share nodes across ALL API calls
            if full_name not in self.all_nodes:
                self.all_nodes[full_name] = DependencyNode(package=pkg)

            node_graph_map[i] = self.all_nodes[full_name]

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

        # DEBUG: Log if we're processing hibernate-core
        for node in node_graph_map.values():
            if "hibernate-core" in node.package.name:
                logger.info(f"🔍 GERONIMO: Processing hibernate-core@{node.package.version} in {root_package.full_name} graph")

        # CRITICAL FIX: Clear children for nodes that appear in this API response
        # BUT: Don't clear children for nodes that were already fetched as complete trees
        # because deps.dev returns different (incomplete) subgraphs depending on context.
        #
        # Example: hibernate-validator fetched as root returns 6 direct dependencies.
        # But when it appears in spring-boot-starter-thymeleaf's graph, it only has 3.
        # If we clear and rebuild from the thymeleaf context, we lose 3 dependencies!
        for node in node_graph_map.values():
            pkg_name = node.package.full_name

            # Skip clearing if this node was already fetched as a complete tree
            # BUT: Need to check the EXACT version, not just the name
            # Because hibernate-core@5.0.4.Final is a complete tree, but
            # hibernate-core@5.0.12.Final appearing in entitymanager's graph is NOT
            if pkg_name in self.complete_trees:
                logger.debug(f"Preserving complete tree for {pkg_name} (not clearing children)")
                logger.debug(f"🔍 GERONIMO DEBUG: Preserving {pkg_name} - {len(node.children)} children")
                continue

            if node.children:
                logger.debug(f"Clearing {len(node.children)} existing children for {pkg_name}")
                logger.debug(f"🔍 GERONIMO DEBUG: Clearing children for {pkg_name}")
            node.children.clear()

        # Build graph structure from SELF node
        if self_node_index != -1:
            self._build_tree_from_adjacency(
                node_graph_map, adjacency, self_node_index, set()
            )
            self_node = node_graph_map[self_node_index]
            logger.debug(f"Built tree for {self_node.package.full_name} with {len(self_node.children)} children")
            return self_node

        return DependencyNode(package=root_package)

    def _build_tree_from_adjacency(
        self,
        node_graph_map: Dict[int, DependencyNode],
        adjacency: Dict[int, List[int]],
        current_node: int,
        visited: Set[int]
    ) -> None:
        """Recursively build graph structure from adjacency list."""
        # Prevent cycles
        if current_node in visited:
            return
        visited.add(current_node)

        current_graph_node = node_graph_map.get(current_node)
        if not current_graph_node:
            return

        # Get parent package for exclusion checks
        parent_pkg = current_graph_node.package
        parent_exclusions = self.exclusions.get(parent_pkg.name, set())

        children = adjacency.get(current_node, [])
        for child_index in children:
            child_node = node_graph_map[child_index]
            child_pkg = child_node.package

            # Check if excluded
            if self._is_excluded(child_pkg, parent_exclusions):
                logger.debug(f"Excluding dependency {child_pkg.name} from parent {parent_pkg.name}")
                continue

            # DEBUG: Log if adding edge to hibernate-core
            if "hibernate-core" in parent_pkg.name:
                logger.info(f"🔍 GERONIMO: Adding edge hibernate-core@{parent_pkg.version} -> {child_pkg.name}@{child_pkg.version}")

            # Just add reference to existing node - NO cloning needed!
            current_graph_node.add_child(child_node)

            # Recursively build this child's edges
            self._build_tree_from_adjacency(
                node_graph_map, adjacency, child_index, visited.copy()
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
        """
        Reconcile versions in the dependency tree with actual runtime versions.
        Matches Java's algorithm: fetch new version's tree and replace children.
        """
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

            # IMPORTANT: Fetch the dependency tree for the NEW version
            # This ensures we get the correct dependencies for the reconciled version
            logger.debug(f"Fetching dependencies for reconciled version {reconciled_pkg.full_name}")
            new_tree = self._fetch_complete_dependency_tree(reconciled_pkg, input_package_names)

            if new_tree and new_tree.children:
                # Replace the children with the new version's dependencies
                node.children.clear()
                for new_child in new_tree.children:
                    node.add_child(new_child)
                    # Recursively reconcile the new subtree
                    self._reconcile_tree_versions(new_child, observed_versions, input_package_names)
                logger.debug(f"Replaced {len(new_tree.children)} children for reconciled {reconciled_pkg.full_name}")
                return  # Don't recurse into old children - we already processed new ones

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

    def _apply_nearest_wins_resolution(self, roots: List[DependencyNode]) -> None:
        """
        Apply Maven's nearest-wins resolution algorithm.
        Uses BFS to find the nearest occurrence of each package and updates all nodes to use that version.
        """
        logger.info("Applying Maven nearest-wins version resolution")

        # Track: package base name -> (version, depth)
        first_occurrence: Dict[str, Tuple[str, int]] = {}

        # BFS traversal to find first occurrence of each package
        queue = deque()
        for root in roots:
            queue.append((root, 0))

        visited: Set[str] = set()

        while queue:
            node, depth = queue.popleft()

            pkg = node.package
            base_key = f"{pkg.system.lower()}:{pkg.name}"
            node_id = f"{base_key}:{pkg.version}:{depth}"

            # Prevent infinite loops in cyclic dependencies
            if node_id in visited:
                continue
            visited.add(node_id)

            # First occurrence wins (or nearer occurrence)
            if base_key not in first_occurrence:
                first_occurrence[base_key] = (pkg.version, depth)
                logger.debug(f"First occurrence: {base_key} at depth {depth} with version {pkg.version}")
            else:
                # Check if this occurrence is nearer
                existing_version, existing_depth = first_occurrence[base_key]
                if depth < existing_depth:
                    # Nearer occurrence - update the winning version
                    logger.info(
                        f"Found nearer occurrence of {base_key}: depth {depth} (v{pkg.version}) "
                        f"replaces depth {existing_depth} (v{existing_version})"
                    )
                    first_occurrence[base_key] = (pkg.version, depth)

            # Add children to queue
            for child in node.children:
                queue.append((child, depth + 1))

        # Second pass: Update all nodes to use the winning version
        for root in roots:
            self._update_versions_to_nearest_wins(root, first_occurrence, set())

        logger.info(f"Applied nearest-wins resolution to {len(first_occurrence)} packages")

    def _update_versions_to_nearest_wins(
        self, node: DependencyNode, winning_versions: Dict[str, Tuple[str, int]], visited: Set[str]
    ) -> None:
        """Recursively update versions based on nearest-wins resolution."""
        pkg = node.package
        base_key = f"{pkg.system.lower()}:{pkg.name}"
        node_id = f"{base_key}:{pkg.version}"

        # Prevent infinite loops in cyclic dependencies
        if node_id in visited:
            return
        visited.add(node_id)

        if base_key in winning_versions:
            winner_version, _ = winning_versions[base_key]
            if winner_version != pkg.version:
                logger.debug(f"Updating {base_key} from {pkg.version} to {winner_version} (nearest-wins)")

                updated_pkg = Package(pkg.system, pkg.name, winner_version)
                node.package = updated_pkg

                # IMPORTANT: Fetch the correct dependency tree for the new version
                logger.debug(f"Fetching dependencies for reconciled version {updated_pkg.full_name}")
                winner_tree = self._fetch_complete_dependency_tree(updated_pkg, set())

                if winner_tree and winner_tree.children:
                    node.children.clear()
                    for child in winner_tree.children:
                        node.add_child(child)
                        self._update_versions_to_nearest_wins(child, winning_versions, set(visited))
                    logger.debug(
                        f"Replaced {len(winner_tree.children)} children for nearest-wins {updated_pkg.full_name}"
                    )
                else:
                    logger.debug(f"No new dependencies found for nearest-wins {updated_pkg.full_name}")
            else:
                # Version is already correct, just recurse
                for child in node.children:
                    self._update_versions_to_nearest_wins(child, winning_versions, set(visited))
        else:
            # No winning version found (shouldn't happen), just recurse
            for child in node.children:
                self._update_versions_to_nearest_wins(child, winning_versions, set(visited))

    def close(self):
        """Close resources."""
        self.api_client.close()

    def __enter__(self):
        """Context manager entry."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.close()
