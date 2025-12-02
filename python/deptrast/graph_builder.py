"""Builds dependency graphs from package lists using a two-phase approach."""

import logging
from typing import List, Dict, Set, Optional, Collection, Tuple
from collections import defaultdict, deque

from .models import Package, DependencyNode
from .api_client import DepsDevClient

logger = logging.getLogger(__name__)


class DependencyGraphBuilder:
    """
    Builds complete dependency trees from a list of packages using a two-phase approach:

    Phase 1: Build raw dependency graph from deps.dev
    - Fetch all package graphs from deps.dev API
    - Build complete graph structure with ALL edges as returned by API
    - No version resolution or filtering at this stage

    Phase 2: Apply resolution and relink
    - Determine winning versions based on resolution strategy (maven/highest)
    - Relink edges to point to winning version nodes
    - This "delinks" parts of the tree not selected by resolution
    """

    def __init__(self):
        """Initialize the graph builder."""
        self.api_client = DepsDevClient()

        # Phase 1: Raw graph data from deps.dev
        self.all_packages: Dict[str, Package] = {}  # pkg_name -> Package
        self.all_nodes: Dict[str, DependencyNode] = {}  # pkg_name -> Node (one per version)
        self.raw_graphs: Dict[str, DependencyNode] = {}  # pkg_name -> root node of fetched graph
        self.parent_map: Dict[str, Set[str]] = defaultdict(set)  # child_pkg_name -> Set[parent_pkg_names]

        # Phase 2: Resolution results
        self.root_nodes: List[DependencyNode] = []  # Root nodes after resolution

        # Configuration
        self.dependency_management: Dict[str, str] = {}  # name -> version
        self.exclusions: Dict[str, Set[str]] = {}  # parent_name -> Set[excluded_names]
        self.resolution_strategy: str = "highest"  # maven or highest

    def set_dependency_management(self, management: Dict[str, str]) -> None:
        """Set dependency management versions."""
        self.dependency_management = management or {}
        logger.info(f"DependencyManagement set with {len(self.dependency_management)} entries")
        # Build lookup map for dependency management (will be populated during graph building)
        self._name_to_system: Dict[str, str] = {}  # name -> system (for managed packages)

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
        Build dependency trees from input packages - Phase 1 only (no reconciliation).

        Returns root nodes with ALL discovered versions included.
        """
        logger.info(f"Building dependency trees for {len(input_packages)} packages")

        input_package_names = {pkg.full_name for pkg in input_packages}

        # PHASE 1: Build raw dependency graph from deps.dev
        logger.info("PHASE 1: Building raw dependency graph from deps.dev")
        self._build_raw_graph(input_packages)

        # PHASE 1.5: Apply dependency management overrides by fetching correct versions
        try:
            self._apply_managed_version_overrides()
        except Exception as e:
            logger.error(f"ERROR in _apply_managed_version_overrides: {e}")
            import traceback
            traceback.print_exc()

        # PHASE 2: SKIPPED FOR NOW - just find root nodes
        logger.info("PHASE 2: SKIPPED - no reconciliation, all versions included")

        # STEP 3: Find which INPUT packages appear as dependencies in OTHER input packages' trees
        input_packages_appearing_as_children = set()
        for tree_root_name, tree in self.raw_graphs.items():
            self._find_input_packages_in_tree(
                tree, input_package_names,
                input_packages_appearing_as_children,
                tree_root_name, set()
            )

        # STEP 4: Roots = input packages that DON'T appear as children
        root_package_names = input_package_names - input_packages_appearing_as_children

        logger.info(f"Found {len(root_package_names)} root packages out of {len(input_packages)}")

        # STEP 5: Return only the root trees
        root_nodes = []
        for root_name in root_package_names:
            node = self.raw_graphs.get(root_name)
            if node:
                node.mark_as_root()
                root_nodes.append(node)

        # Store root nodes for later collection
        self.root_nodes = root_nodes

        logger.info(f"Total unique package versions: {len(self.all_nodes)}")
        return root_nodes

    def _get_base_key(self, pkg: Package) -> str:
        """
        Get base key for a package (system:name without version).
        Used for grouping different versions of the same library.
        """
        return f"{pkg.system.lower()}:{pkg.name}"

    def _apply_managed_version_overrides(self) -> None:
        """
        Apply dependency management overrides by fetching correct versions and replacing wrong nodes.
        For each node in all_nodes where dependency management specifies a different version:
        1. Fetch the correct version from deps.dev
        2. Remove the wrong version node (if it has no other parents)
        3. Add the correct version node and redirect parent edges
        """
        if not self.dependency_management:
            return

        logger.info(f"Applying managed version overrides ({len(self.dependency_management)} managed versions, {len(self.all_nodes)} nodes)")

        nodes_to_replace = {}  # wrong_full_name -> correct_full_name

        # Find all nodes that need to be replaced
        for full_name, node in list(self.all_nodes.items()):
            pkg = node.package
            base_key = self._get_base_key(pkg)
            managed_version = self.dependency_management.get(base_key)

            if managed_version and managed_version != pkg.version:
                correct_full_name = f"{pkg.system.lower()}:{pkg.name}:{managed_version}"
                nodes_to_replace[full_name] = correct_full_name
                logger.info(f"Need to replace {full_name} with managed version {correct_full_name}")

        if not nodes_to_replace:
            logger.info("No version overrides needed")
            return

        # Fetch the correct versions
        for wrong_full_name, correct_full_name in nodes_to_replace.items():
            # Skip if we already have the correct version
            if correct_full_name in self.all_nodes:
                logger.debug(f"Correct version {correct_full_name} already exists")
                continue

            # Parse the correct version info
            parts = correct_full_name.split(':')
            if len(parts) != 3:
                logger.warning(f"Invalid fullName format: {correct_full_name}")
                continue

            system, name, version = parts
            correct_pkg = Package(system=system, name=name, version=version)

            logger.info(f"Fetching managed version: {correct_full_name}")

            try:
                correct_tree = self._fetch_raw_dependency_graph(correct_pkg)
                if correct_tree:
                    logger.info(f"Successfully fetched managed version {correct_full_name}")
                else:
                    logger.warning(f"Failed to fetch managed version {correct_full_name}")
            except Exception as e:
                logger.warning(f"Error fetching managed version {correct_full_name}: {e}")

        # Now redirect edges from wrong versions to correct versions
        for wrong_full_name, correct_full_name in nodes_to_replace.items():
            wrong_node = self.all_nodes.get(wrong_full_name)
            correct_node = self.all_nodes.get(correct_full_name)

            if not wrong_node or not correct_node:
                continue

            # Mark wrong version as excluded due to dependency management override
            wrong_pkg = wrong_node.package
            correct_pkg = correct_node.package
            parts = correct_full_name.split(':')
            managed_version = parts[2] if len(parts) == 3 else "unknown"

            wrong_pkg.scope = "excluded"
            wrong_pkg.scope_reason = "override-loser"
            wrong_pkg.winning_version = managed_version

            # Track defeated version on the winner and mark as override winner
            if wrong_pkg.version not in correct_pkg.defeated_versions:
                correct_pkg.defeated_versions.append(wrong_pkg.version)
            correct_pkg.is_override_winner = True

            logger.info(f"Marked {wrong_full_name} as excluded (dependency management override, winner: {managed_version})")

            # DON'T disconnect override losers - keep them in the graph alongside winners
            # The visualization will show both the overridden version and the managed version
            logger.debug(f"Keeping both {wrong_full_name} (override loser) and {correct_full_name} (override winner) in graph")

        logger.info(f"Applied {len(nodes_to_replace)} managed version overrides")

    def apply_conflict_resolution(self) -> None:
        """
        Phase 2: Apply conflict resolution to mark losing versions as excluded.

        For each library with multiple versions:
        1. Choose winner based on strategy (nearest-wins or highest)
        2. Add links from loser's parents → winner
        3. Mark losers as scope:excluded
        4. Mark loser subtrees as excluded (unless other incoming links)
        """
        if not self.root_nodes:
            logger.warning("No root nodes available for conflict resolution")
            return

        logger.info("=== PHASE 2: Applying conflict resolution ===")

        # Step 1: Determine winning versions
        if self.resolution_strategy == "maven":
            winning_versions = self._determine_maven_winning_versions(self.root_nodes)
        else:
            # For "highest" strategy, we need to pass input packages
            # Extract input packages from raw_graphs
            input_packages = [self.all_packages[pkg_name] for pkg_name in self.raw_graphs.keys()]
            winning_versions = self._determine_highest_winning_versions(input_packages)

        logger.info(f"Determined {len(winning_versions)} winning versions")

        # Step 2: Identify all losers (non-winning versions)
        losers: Set[str] = set()
        conflicts_found = 0

        for node_name, node in self.all_nodes.items():
            pkg = node.package
            base_key = self._get_base_key(pkg)
            winning_version = winning_versions.get(base_key)

            if winning_version and pkg.version != winning_version:
                losers.add(node_name)
                conflicts_found += 1
                logger.debug(f"Loser identified: {node_name} (winner: {base_key}:{winning_version})")

        logger.info(f"Found {conflicts_found} losing versions out of {len(self.all_nodes)} total nodes")

        # Step 3: Track defeated versions for winners
        defeated_versions_by_base_key = {}
        for loser_name in losers:
            loser_node = self.all_nodes[loser_name]
            loser_pkg = loser_node.package
            base_key = self._get_base_key(loser_pkg)

            if base_key not in defeated_versions_by_base_key:
                defeated_versions_by_base_key[base_key] = []
            defeated_versions_by_base_key[base_key].append(loser_pkg.version)

        # Step 4: Redirect edges from loser parents → winner
        redirect_count = self._redirect_edges_to_winners(losers, winning_versions)
        logger.info(f"Redirected {redirect_count} edges to winning versions")

        # Step 5: Mark losers as excluded and set strategy
        for loser_name in losers:
            loser_node = self.all_nodes[loser_name]
            loser_pkg = loser_node.package

            # Find the winning version for this loser
            base_key = self._get_base_key(loser_pkg)
            winning_version = winning_versions.get(base_key)

            # Set the strategy on the loser
            loser_pkg.scope_strategy = self.resolution_strategy

            # Only set scope reason if not already set (preserve dependency-management-override from Phase 1.5)
            if not loser_pkg.scope_reason:
                loser_pkg.scope = 'excluded'
                loser_pkg.scope_reason = 'loser'
                loser_pkg.winning_version = winning_version
                logger.debug(f"Marked as excluded: {loser_name} (winner: {winning_version})")
            else:
                # Already marked (e.g., by dependency management), just ensure scope is excluded
                loser_pkg.scope = 'excluded'
                loser_pkg.winning_version = winning_version
                logger.debug(f"Already marked as excluded: {loser_name} (reason: {loser_pkg.scope_reason}, winner: {winning_version})")

        # Step 6: Mark winners with defeated versions
        for base_key, winning_version in winning_versions.items():
            defeated = defeated_versions_by_base_key.get(base_key, [])

            if defeated:
                # Find the winner package node
                winner_full_name = f"{base_key}:{winning_version}"
                winner_node = self.all_nodes.get(winner_full_name)

                if winner_node:
                    winner_pkg = winner_node.package
                    winner_pkg.scope_strategy = self.resolution_strategy  # Set strategy on winner too
                    for defeated_version in defeated:
                        if defeated_version not in winner_pkg.defeated_versions:
                            winner_pkg.defeated_versions.append(defeated_version)
                    logger.debug(f"Winner {winner_full_name} defeated versions: {defeated}")

        # Step 5: Mark loser subtrees as excluded (unless other incoming links)
        excluded_subtree_count = self._mark_loser_subtrees_excluded(losers)
        logger.info(f"Marked {excluded_subtree_count} subtree nodes as excluded")

        logger.info(f"=== Conflict resolution complete: {conflicts_found} losers, "
                   f"{redirect_count} redirects, {excluded_subtree_count} subtree exclusions ===")

        # Step 6: Propagate test/provided/system scopes to transitive dependencies
        self._propagate_excluded_scopes()

    def _build_raw_graph(self, input_packages: List[Package]) -> None:
        """
        Phase 1: Build raw dependency graph from deps.dev.
        Fetches all package graphs and builds complete graph structure.

        NOTE: The deps.dev :dependencies endpoint returns the FULL transitive dependency
        graph in a single API call. We do NOT need to recursively fetch discovered packages!
        We only fetch ONE graph per input package.
        """
        # Pre-populate all_packages with input packages to preserve their scopes
        # This ensures when deps.dev returns the SELF node, we reuse the input package object
        for pkg in input_packages:
            if pkg.full_name not in self.all_packages:
                self.all_packages[pkg.full_name] = pkg
                logger.debug(f"Pre-registered input package: {pkg.full_name} (scope: {pkg.scope})")

        # STEP 1.5: Add managed dependency versions to fetch list if not already present
        input_package_names = {pkg.full_name for pkg in input_packages}
        packages_to_fetch = list(input_packages)

        logger.debug(f"Processing {len(self.dependency_management)} managed dependencies")
        for group_and_artifact, version in self.dependency_management.items():
            # Dependency management from POM is always Maven
            # Parse groupId:artifactId
            parts = group_and_artifact.split(':')
            if len(parts) != 2:
                logger.warning(f"Invalid dependency management key format: {group_and_artifact}")
                continue

            group_id, artifact_id = parts
            name = f"{group_id}:{artifact_id}"
            full_name = f"maven:{name}:{version}"

            # Only add if not already in input packages
            if full_name not in input_package_names:
                managed_pkg = Package(system='maven', name=name, version=version)
                packages_to_fetch.append(managed_pkg)
                self.all_packages[full_name] = managed_pkg
                logger.info(f"Adding managed dependency version to fetch list: {full_name}")

        for pkg in packages_to_fetch:
            pkg_name = pkg.full_name

            # Fetch graph from deps.dev (this returns the COMPLETE transitive tree!)
            root_node = self._fetch_raw_dependency_graph(pkg)
            if root_node:
                self.raw_graphs[pkg_name] = root_node
                logger.debug(f"Successfully fetched graph for {pkg_name}")
            else:
                logger.debug(f"Failed to fetch graph for {pkg_name}")

        logger.info(f"Fetched {len(self.raw_graphs)} graphs")

        logger.info(f"Phase 1 complete: Fetched {len(self.raw_graphs)} graphs, "
                   f"total {len(self.all_nodes)} unique package versions")

    def _fetch_raw_dependency_graph(self, package: Package) -> Optional[DependencyNode]:
        """
        Fetch raw dependency graph from deps.dev for a package.
        Returns root node with ALL edges as returned by API (no filtering).
        """
        graph = self.api_client.get_dependency_graph(package)

        if not graph:
            logger.warning(f"WARNING: Unknown component {package.full_name}. Treating as leaf node.")

            # Check if we already have this node from another graph
            if package.full_name in self.all_nodes:
                logger.debug(f"Package {package.full_name} returned 404 but exists in graph - reusing")
                return self.all_nodes[package.full_name]

            # Create leaf node and add to all_nodes
            node = DependencyNode(package=package)
            self.all_nodes[package.full_name] = node
            self.all_packages[package.full_name] = package
            logger.debug(f"Created and registered leaf node for {package.full_name}")
            return node

        return self._parse_dependency_graph(graph, package)

    def _parse_dependency_graph(self, graph: Dict, root_package: Package) -> Optional[DependencyNode]:
        """
        Parse dependency graph from deps.dev response.
        Builds complete graph structure with ALL edges (no filtering).
        """
        nodes = graph.get("nodes", [])
        edges = graph.get("edges", [])

        if not nodes:
            # No nodes at all - create leaf node
            return DependencyNode(package=root_package)

        # If we have nodes but no edges, continue processing
        # (leaf packages have 1 SELF node and 0 edges)

        # Track new packages added during this parse
        packages_before = len(self.all_packages)

        # Build node map: index -> DependencyNode
        node_map: Dict[int, DependencyNode] = {}
        self_node_index = -1

        for i, node in enumerate(nodes):
            version_key = node.get("versionKey", {})
            system = version_key.get("system", "")
            name = version_key.get("name", "")
            version = version_key.get("version", "")
            relation = node.get("relation", "")

            # Create or reuse package
            full_name = f"{system.lower()}:{name}:{version}"
            if full_name not in self.all_packages:
                self.all_packages[full_name] = Package(system=system, name=name, version=version)
            pkg = self.all_packages[full_name]

            # Track name -> system mapping for dependency management lookup
            if name in self.dependency_management and name not in self._name_to_system:
                self._name_to_system[name] = system.lower()

            # Create or reuse node
            if full_name not in self.all_nodes:
                self.all_nodes[full_name] = DependencyNode(package=pkg)
            node_map[i] = self.all_nodes[full_name]

            if relation == "SELF":
                self_node_index = i

        # Build adjacency from edges
        adjacency: Dict[int, List[int]] = defaultdict(list)
        for edge in edges:
            from_node = edge.get("fromNode")
            to_node = edge.get("toNode")
            if from_node is not None and to_node is not None:
                adjacency[from_node].append(to_node)

        # Build graph from SELF node
        # Note: _build_graph_from_adjacency will only add children if the node doesn't already have them
        if self_node_index != -1:
            self._build_graph_from_adjacency(node_map, adjacency, self_node_index, set())
            packages_added = len(self.all_packages) - packages_before
            logger.debug(f"Parsed graph for {root_package.full_name}: {len(nodes)} nodes in response, {packages_added} new packages added to all_packages")
            return node_map[self_node_index]

        return DependencyNode(package=root_package)

    def _build_graph_from_adjacency(
        self,
        node_map: Dict[int, DependencyNode],
        adjacency: Dict[int, List[int]],
        current_index: int,
        visited: Set[int]
    ) -> None:
        """
        Build graph structure from adjacency list.
        ALWAYS populate children from this graph - merge all edges.
        """
        if current_index in visited:
            return
        visited.add(current_index)

        current_node = node_map.get(current_index)
        if not current_node:
            return

        # Get parent exclusions
        parent_pkg = current_node.package
        parent_exclusions = self.exclusions.get(parent_pkg.name, set())

        # Add all children from this graph
        children = adjacency.get(current_index, [])
        for child_index in children:
            child_node = node_map[child_index]
            child_pkg = child_node.package

            # Check if this child is excluded by the parent
            if self._is_excluded(child_pkg, parent_exclusions):
                logger.debug(f"Excluding dependency {child_pkg.name} from parent {parent_pkg.name}")
                continue  # Skip this child

            # Add child if not already present
            if child_node not in current_node.children:
                current_node.add_child(child_node)

            # Track parent-child relationship
            self.parent_map[child_node.package.full_name].add(current_node.package.full_name)

            # Recursively build subtree
            self._build_graph_from_adjacency(node_map, adjacency, child_index, visited.copy())

    def _determine_maven_winning_versions(self, roots: List[DependencyNode]) -> Dict[str, str]:
        """
        Phase 2: Determine winning versions using Maven nearest-wins strategy.
        Returns map of package_base_key -> winning_version.
        """
        logger.info("Determining winning versions using Maven nearest-wins")

        # BFS to find nearest occurrence of each package
        first_occurrence: Dict[str, Tuple[str, int]] = {}
        queue = deque()

        for root in roots:
            queue.append((root, 0))

        visited: Set[str] = set()

        while queue:
            node, depth = queue.popleft()

            pkg = node.package
            base_key = self._get_base_key(pkg)
            node_id = f"{base_key}:{pkg.version}"

            if node_id in visited:
                continue
            visited.add(node_id)

            # Track first/nearest occurrence
            if base_key not in first_occurrence:
                first_occurrence[base_key] = (pkg.version, depth)
                logger.debug(f"First occurrence: {base_key} v{pkg.version} at depth {depth}")
            else:
                existing_version, existing_depth = first_occurrence[base_key]
                if depth < existing_depth:
                    logger.info(f"Nearer occurrence: {base_key} v{pkg.version} at depth {depth} "
                              f"replaces v{existing_version} at depth {existing_depth}")
                    first_occurrence[base_key] = (pkg.version, depth)
                elif depth == existing_depth and self._compare_versions(pkg.version, existing_version) > 0:
                    logger.info(f"Tie-breaker: {base_key} at depth {depth}: "
                              f"v{pkg.version} replaces v{existing_version} (higher)")
                    first_occurrence[base_key] = (pkg.version, depth)

            # Queue children
            for child in node.children:
                queue.append((child, depth + 1))

        # Return just version map
        return {base_key: version for base_key, (version, _) in first_occurrence.items()}

    def _determine_highest_winning_versions(self, input_packages: List[Package]) -> Dict[str, str]:
        """
        Phase 2: Determine winning versions using highest version strategy.
        Priority: 1) dependency management, 2) input package version, 3) highest seen.
        Returns map of package_base_key -> winning_version.
        """
        logger.info("Determining winning versions using highest version strategy")

        winning_versions: Dict[str, str] = {}

        # Priority 1: Dependency management (O(m) using pre-built lookup)
        for name, version in self.dependency_management.items():
            system = self._name_to_system.get(name)
            if system:
                base_key = f"{system}:{name}"
                winning_versions[base_key] = version
                logger.debug(f"Managed version: {base_key} -> {version}")

        # Priority 2: Input package versions (only if successfully fetched)
        for pkg in input_packages:
            pkg_name = pkg.full_name
            # Only use input version if we successfully fetched its graph
            if pkg_name not in self.raw_graphs:
                logger.debug(f"Skipping input version for {pkg_name} (not in raw_graphs)")
                continue

            base_key = f"{pkg.system}:{pkg.name}"
            if base_key not in winning_versions:
                winning_versions[base_key] = pkg.version
                logger.debug(f"Input version: {base_key} -> {pkg.version}")

        # Priority 3: Highest version seen IN FETCHED GRAPHS
        # Only consider versions that actually exist in all_nodes (successfully fetched)
        for node_name, node in self.all_nodes.items():
            pkg = node.package
            base_key = self._get_base_key(pkg)

            if base_key in winning_versions:
                # Already have a winner from higher priority - check if this is higher
                if self._compare_versions(pkg.version, winning_versions[base_key]) > 0:
                    logger.debug(f"Higher version: {base_key} {winning_versions[base_key]} -> {pkg.version}")
                    winning_versions[base_key] = pkg.version
            else:
                # First time seeing this package
                winning_versions[base_key] = pkg.version

        return winning_versions

    def _relink_to_winning_versions(self, winning_versions: Dict[str, str]) -> None:
        """
        Phase 2: Relink all edges to point to winning version nodes.
        Simple strategy: iterate through each node's children, if a child needs reconciliation
        to a different version, fetch that version and replace the child.
        """
        logger.info("Relinking edges to winning versions")

        relinked_count = 0

        # Visit all nodes and reconcile their children to point to winning versions
        for node in self.all_nodes.values():
            new_children = []

            for child in node.children:
                child_pkg = child.package
                base_key = f"{child_pkg.system.lower()}:{child_pkg.name}"

                # Check exclusions
                parent_exclusions = self.exclusions.get(node.package.name, set())
                if self._is_excluded(child_pkg, parent_exclusions):
                    logger.debug(f"Excluding {child_pkg.name} from parent {node.package.name}")
                    continue

                # Get winning version
                winning_version = winning_versions.get(base_key)
                if not winning_version:
                    logger.warning(f"No winning version for {base_key}, keeping current {child_pkg.version}")
                    new_children.append(child)
                    continue

                # If child already points to winning version, keep it
                if child_pkg.version == winning_version:
                    new_children.append(child)
                    continue

                # Need to replace this child with the winning version
                logger.info(f"Reconciling child {child_pkg.name} from {child_pkg.version} to {winning_version}")

                # Look up the winning version node (should already exist from Phase 1)
                winning_node_name = f"{child_pkg.system.lower()}:{child_pkg.name}:{winning_version}"
                winning_node = self.all_nodes.get(winning_node_name)

                if winning_node:
                    new_children.append(winning_node)
                    relinked_count += 1
                else:
                    logger.warning(f"Winning version {winning_node_name} not found in all_nodes, keeping {child_pkg.version}")
                    new_children.append(child)

            node.children = new_children

        logger.info(f"Relinked {relinked_count} edges to winning versions")

    def _mark_excluded_nodes(self, replaced_node_names: Set[str]) -> int:
        """
        Mark replaced nodes as scope='excluded'.
        Only mark children as excluded if they are ONLY reachable from excluded nodes.
        Returns count of packages marked as excluded.
        """
        # First, find all packages that are reachable from non-replaced (winning) nodes
        reachable_from_winners = set()
        for node in self.all_nodes.values():
            if node.package.full_name not in replaced_node_names:
                self._collect_reachable_packages(node, reachable_from_winners)

        logger.debug(f"Found {len(reachable_from_winners)} packages reachable from winning versions")

        # Now mark replaced nodes and their children (but skip if reachable from winners)
        excluded_count = 0
        visited = set()

        for node_name in replaced_node_names:
            node = self.all_nodes.get(node_name)
            if node:
                excluded_count += self._mark_excluded_recursive(node, visited, reachable_from_winners)

        return excluded_count

    def _collect_reachable_packages(self, node: DependencyNode, reachable: Set[str], visited: Optional[Set[str]] = None) -> None:
        """Collect all packages reachable from this node."""
        if visited is None:
            visited = set()

        if node.package.full_name in visited:
            return

        visited.add(node.package.full_name)
        reachable.add(node.package.full_name)

        for child in node.children:
            self._collect_reachable_packages(child, reachable, visited)

    def _mark_excluded_recursive(self, node: DependencyNode, visited: Set[str], reachable_from_winners: Set[str]) -> int:
        """
        Recursively mark a node and its children as scope='excluded'.
        Skip marking if the package is reachable from winning versions.
        Returns count of packages marked.
        """
        # Prevent infinite loops in case of cycles
        if node.package.full_name in visited:
            return 0

        visited.add(node.package.full_name)
        count = 0

        # Only mark as excluded if NOT reachable from winning versions
        if node.package.full_name not in reachable_from_winners:
            if node.package.scope != 'excluded':
                logger.debug(f"Marking {node.package.full_name} as excluded (not reachable from winners)")
                node.package.scope = 'excluded'
                count = 1

            # Recursively mark children (they'll also check reachability)
            for child in node.children:
                count += self._mark_excluded_recursive(child, visited, reachable_from_winners)

        return count

    def _find_root_nodes(self, input_packages: List[Package], input_package_names: Set[str]) -> List[DependencyNode]:
        """
        Find root nodes: input packages that don't appear as dependencies in other trees.
        """
        # Find which input packages appear as children
        input_packages_appearing_as_children: Set[str] = set()

        for root_name, root in self.raw_graphs.items():
            self._find_input_packages_in_tree(root, input_package_names,
                                             input_packages_appearing_as_children, root_name, set())

        # Roots are input packages NOT appearing as children
        root_package_names = input_package_names - input_packages_appearing_as_children

        root_nodes = []
        for root_name in root_package_names:
            node = self.all_nodes.get(root_name)
            if node:
                node.mark_as_root()
                root_nodes.append(node)

        return root_nodes

    def _find_input_packages_in_tree(
        self,
        node: DependencyNode,
        input_package_names: Set[str],
        input_packages_appearing_as_children: Set[str],
        tree_root_name: str,
        visited: Set[str]
    ) -> None:
        """Recursively find which input packages appear in this tree."""
        if not node:
            return

        node_name = node.package.full_name

        # Prevent cycles (relinking can create cycles)
        if node_name in visited:
            return
        visited.add(node_name)

        if node_name in input_package_names and node_name != tree_root_name:
            input_packages_appearing_as_children.add(node_name)

        for child in node.children:
            self._find_input_packages_in_tree(child, input_package_names,
                                            input_packages_appearing_as_children, tree_root_name, visited)

    def _collect_all_package_names(self, node: DependencyNode, package_names: Set[str],
                                   visited: Optional[Set[str]] = None) -> None:
        """Recursively collect all package names from a dependency tree."""
        if not node:
            return

        if visited is None:
            visited = set()

        package_name = node.package.full_name

        if package_name in visited:
            return
        visited.add(package_name)

        package_names.add(package_name)

        for child in node.children:
            self._collect_all_package_names(child, package_names, visited)

    def _is_excluded(self, package: Package, parent_exclusions: Set[str]) -> bool:
        """Check if a package should be excluded."""
        if not parent_exclusions:
            return False
        return package.name in parent_exclusions

    def _redirect_edges_to_winners(self, losers: Set[str], winning_versions: Dict[str, str]) -> int:
        """
        Redirect edges from loser parents to winning versions.
        For each loser, find all parents and add edges parent → winner.
        Returns count of redirected edges.
        """
        redirect_count = 0

        for loser_name in losers:
            loser_node = self.all_nodes.get(loser_name)
            if not loser_node:
                continue

            # Get loser's package info
            loser_pkg = loser_node.package
            base_key = self._get_base_key(loser_pkg)
            winning_version = winning_versions.get(base_key)

            if not winning_version:
                logger.warning(f"No winning version found for {base_key}")
                continue

            # Find winner node
            winner_name = f"{base_key}:{winning_version}"
            winner_node = self.all_nodes.get(winner_name)

            if not winner_node:
                logger.warning(f"Winner node not found: {winner_name}")
                continue

            # Get all parents of this loser
            parent_names = self.parent_map.get(loser_name, set())

            for parent_name in parent_names:
                parent_node = self.all_nodes.get(parent_name)
                if not parent_node:
                    continue

                # Add winner as child of parent (if not already present)
                if winner_node not in parent_node.children:
                    parent_node.add_child(winner_node)
                    # Update parent_map for the winner
                    self.parent_map[winner_name].add(parent_name)
                    redirect_count += 1
                    logger.debug(f"Redirected: {parent_name} → {winner_name} (was {loser_name})")

                    # DEBUG: Track commons-io additions to commons-compress
                    if "commons-compress@1.27.1" in parent_name and "commons-io" in winner_name:
                        logger.warning(f"DEBUG: Adding {winner_name} to commons-compress@1.27.1 (from loser {loser_name})")
                        logger.warning(f"DEBUG: commons-compress@1.27.1 children before: {[c.package.full_name for c in parent_node.children]}")

        return redirect_count

    def _mark_loser_subtrees_excluded(self, losers: Set[str]) -> int:
        """
        Mark nodes in loser subtrees as excluded, UNLESS they have other incoming links
        from non-excluded nodes.
        Returns count of nodes marked as excluded.
        """
        excluded_count = 0
        visited = set()

        for loser_name in losers:
            loser_node = self.all_nodes.get(loser_name)
            if not loser_node:
                continue

            # Recursively mark children (if they don't have other incoming links)
            excluded_count += self._mark_subtree_excluded_recursive(
                loser_node, visited, losers
            )

        return excluded_count

    def _mark_subtree_excluded_recursive(
        self, node: DependencyNode, visited: Set[str], excluded_parents: Set[str]
    ) -> int:
        """
        Recursively mark children as excluded if ALL their parents are excluded.
        """
        count = 0

        for child in node.children:
            child_name = child.package.full_name

            if child_name in visited:
                continue
            visited.add(child_name)

            # Skip if already excluded
            if child.package.scope == 'excluded':
                continue

            # Check if child has ANY non-excluded parents
            child_parents = self.parent_map.get(child_name, set())
            has_non_excluded_parent = any(
                parent_name not in excluded_parents
                for parent_name in child_parents
            )

            if not has_non_excluded_parent:
                # All parents are excluded, so mark this child as excluded too
                child.package.scope = 'excluded'
                child.package.scope_reason = 'conflict-resolution-subtree'
                count += 1
                logger.debug(f"Marked subtree node as excluded: {child_name}")

                # Recursively mark its children
                # Add this child to excluded_parents for recursive call
                new_excluded = excluded_parents | {child_name}
                count += self._mark_subtree_excluded_recursive(child, visited, new_excluded)

        return count

    def _compare_versions(self, v1: str, v2: str) -> int:
        """Simple version comparison. Returns >0 if v1 > v2, <0 if v1 < v2, 0 if equal."""
        if v1 == v2:
            return 0

        import re
        parts1 = re.split(r'[.\-]', v1)
        parts2 = re.split(r'[.\-]', v2)

        min_length = min(len(parts1), len(parts2))
        for i in range(min_length):
            part1 = parts1[i]
            part2 = parts2[i]

            try:
                num1 = int(part1)
                num2 = int(part2)
                if num1 != num2:
                    return num1 - num2
            except ValueError:
                if part1 != part2:
                    return 1 if part1 > part2 else -1

        return len(parts1) - len(parts2)

    def _propagate_excluded_scopes(self) -> None:
        """
        Propagate test/provided/system scopes to transitive dependencies.

        Maven scope propagation rules:
        - Test, provided, and system scopes propagate to all transitive dependencies
        - Required scope (compile/runtime) overrides test scope if a package is reachable through both paths

        This ensures test libraries and their dependencies are properly excluded from runtime SBOMs.
        """
        if not self.root_nodes:
            logger.warning("No root nodes available for scope propagation")
            return

        logger.info("=== Propagating Maven scopes to transitive dependencies ===")

        # Track which packages are reachable from each scope type
        test_reachable: Set[str] = set()      # Reachable from test/provided/system roots
        required_reachable: Set[str] = set()  # Reachable from compile/runtime/None roots

        # Walk dependency tree from each root to build reachability sets
        for root in self.root_nodes:
            root_scope = root.package.scope or 'required'

            # Determine if this root is test-scoped or required-scoped
            if root_scope in ('test', 'provided', 'system', 'excluded'):
                # Track all packages reachable from test-scoped roots
                self._collect_reachable_packages_by_scope(root, test_reachable)
                logger.debug(f"Root {root.package.full_name} has scope '{root_scope}' - marking transitives as test-reachable")
            else:
                # Track all packages reachable from required-scoped roots
                self._collect_reachable_packages_by_scope(root, required_reachable)
                logger.debug(f"Root {root.package.full_name} has scope '{root_scope}' - marking transitives as required-reachable")

        # Apply scope propagation with override rule
        propagated_count = 0
        for pkg_name in test_reachable:
            # Skip if also reachable from required path (required overrides test)
            if pkg_name in required_reachable:
                logger.debug(f"Package {pkg_name} reachable from both test and required paths - keeping as required")
                continue

            # Mark as excluded since only reachable from test/provided/system paths
            node = self.all_nodes.get(pkg_name)
            if node and node.package.scope not in ('excluded',):
                old_scope = node.package.scope
                node.package.scope = 'excluded'
                node.package.scope_reason = 'test-dependency'
                propagated_count += 1
                logger.debug(f"Propagated test scope to {pkg_name} (was '{old_scope}')")

        logger.info(f"Scope propagation complete: {propagated_count} packages marked as test dependencies")
        logger.info(f"Reachability stats: {len(test_reachable)} test-reachable, {len(required_reachable)} required-reachable")

    def _collect_reachable_packages_by_scope(
        self, node: DependencyNode, reachable: Set[str], visited: Optional[Set[str]] = None
    ) -> None:
        """
        Collect all packages reachable from this node.
        Used for scope propagation to track test vs required reachability.
        """
        if visited is None:
            visited = set()

        pkg_name = node.package.full_name
        if pkg_name in visited:
            return

        visited.add(pkg_name)
        reachable.add(pkg_name)

        # Recursively collect children
        for child in node.children:
            self._collect_reachable_packages_by_scope(child, reachable, visited)

    def get_all_reconciled_packages(self) -> Collection[Package]:
        """
        Get all packages from the resolved dependency trees.
        Returns ALL packages including non-winning versions that were discovered.
        This matches Java behavior - all versions are included in the SBOM.
        """
        # Return all packages from all_packages (includes ALL versions discovered, even excluded ones' children)
        packages = list(self.all_packages.values())

        logger.info(f"get_all_reconciled_packages: returning {len(packages)} packages (all versions)")

        return packages

    def _collect_packages_from_tree(
        self, node: DependencyNode, package_map: Dict[str, Package],
        visited: Optional[Set[str]] = None
    ) -> None:
        """Recursively collect packages from tree."""
        if not node:
            return

        if visited is None:
            visited = set()

        pkg = node.package
        base_key = f"{pkg.system}:{pkg.name}"
        node_id = f"{base_key}:{pkg.version}"

        # Prevent cycles
        if node_id in visited:
            return
        visited.add(node_id)

        # Just add if not present (after resolution, should all be winning versions)
        if base_key not in package_map:
            package_map[base_key] = pkg

        for child in node.children:
            self._collect_packages_from_tree(child, package_map, visited)

    def close(self):
        """Close resources."""
        self.api_client.close()

    def __enter__(self):
        """Context manager entry."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.close()
