package com.contrastsecurity.deptrast.service;

import com.contrastsecurity.deptrast.api.DepsDevClient;
import com.contrastsecurity.deptrast.model.DependencyNode;
import com.contrastsecurity.deptrast.model.Package;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.*;

/**
 * Builds complete dependency trees from a list of runtime packages
 *
 * Algorithm:
 * 1. Fetch complete dependency graph for each input package from deps.dev API
 * 2. Reconcile declared versions with actual runtime versions (handles Maven's dependency resolution)
 * 3. Identify which input packages appear as dependencies in other packages' trees
 * 4. Roots = input packages NOT appearing as dependencies in other trees
 */
public class DependencyGraphBuilder implements AutoCloseable {
    private static final Logger logger = LoggerFactory.getLogger(DependencyGraphBuilder.class);

    private final DepsDevClient apiClient;
    private final Map<String, DependencyNode> completeTrees; // pkg fullName -> its full tree
    private final Map<String, Package> allPackages; // fullName -> Package (for deduplication)
    private final Map<String, DependencyNode> allNodes; // fullName -> DependencyNode (one per version)
    private final Map<String, Set<String>> parentMap; // child fullName -> Set[parent fullNames]
    private Map<String, String> dependencyManagement; // groupId:artifactId -> version
    private Map<String, Set<String>> exclusions; // package name -> set of excluded "groupId:artifactId"
    private List<DependencyNode> rootNodes; // Root nodes after resolution

    /**
     * Simple tuple helper class for BFS queue
     */
    private static class Tuple<A, B> {
        final A first;
        final B second;

        Tuple(A first, B second) {
            this.first = first;
            this.second = second;
        }
    }

    public DependencyGraphBuilder() {
        this.apiClient = new DepsDevClient();
        this.completeTrees = new HashMap<>();
        this.allPackages = new HashMap<>();
        this.allNodes = new HashMap<>();
        this.parentMap = new HashMap<>();
        this.dependencyManagement = new HashMap<>();
        this.exclusions = new HashMap<>();
        this.rootNodes = new ArrayList<>();
    }

    /**
     * Set dependency management to apply to transitive dependencies
     *
     * @param dependencyManagement map of groupId:artifactId to version
     */
    public void setDependencyManagement(Map<String, String> dependencyManagement) {
        this.dependencyManagement = dependencyManagement != null ? dependencyManagement : new HashMap<>();
        logger.info("DependencyManagement set with {} entries", this.dependencyManagement.size());
    }

    /**
     * Set exclusions for dependencies
     *
     * @param exclusions map of package name to set of excluded "groupId:artifactId"
     */
    public void setExclusions(Map<String, Set<String>> exclusions) {
        this.exclusions = exclusions != null ? exclusions : new HashMap<>();
        logger.info("Exclusions set with {} entries", this.exclusions.size());
        for (Map.Entry<String, Set<String>> entry : this.exclusions.entrySet()) {
            logger.debug("Package {} excludes: {}", entry.getKey(), entry.getValue());
        }
    }

    /**
     * Build dependency trees - PHASE 1 ONLY (no reconciliation).
     *
     * Algorithm:
     * 1. Fetch complete dependency graph for each input package from deps.dev
     * 2. Track which INPUT packages appear as dependencies in OTHER trees
     * 3. Roots = input packages NOT appearing as dependencies
     *
     * Returns all discovered package versions (no reconciliation applied).
     */
    public List<DependencyNode> buildDependencyTrees(List<Package> inputPackages) {
        logger.info("Building dependency trees for {} packages - PHASE 1 ONLY", inputPackages.size());

        // STEP 0: Pre-populate allPackages with input packages to preserve their scopes
        // This ensures when deps.dev returns the SELF node, we reuse the input package object
        for (Package pkg : inputPackages) {
            if (!allPackages.containsKey(pkg.getFullName())) {
                allPackages.put(pkg.getFullName(), pkg);
                logger.debug("Pre-registered input package: {} (scope: {})", pkg.getFullName(), pkg.getScope());
            }
        }

        // STEP 1: Create set of input package names for quick lookup
        Set<String> inputPackageNames = new HashSet<>();
        for (Package pkg : inputPackages) {
            inputPackageNames.add(pkg.getFullName());
            logger.debug("Input package: {}", pkg.getFullName());
        }

        // STEP 2: Fetch complete dependency graph for each package
        // Skip packages that already appear in other trees to reduce API calls
        Set<String> packagesAlreadyInTrees = new HashSet<>();
        int skippedCount = 0;

        for (Package pkg : inputPackages) {
            String pkgName = pkg.getFullName();

            // Check if this package already appears in any fetched tree
            if (packagesAlreadyInTrees.contains(pkgName)) {
                logger.debug("Skipping {} - already found in another dependency tree", pkgName);
                skippedCount++;
                continue;
            }

            DependencyNode tree = fetchCompleteDependencyTree(pkg, inputPackageNames);
            if (tree != null) {
                completeTrees.put(pkgName, tree);

                // Add all packages in this tree to the set to avoid redundant fetches
                collectAllPackageNames(tree, packagesAlreadyInTrees);
            }
        }

        if (skippedCount > 0) {
            logger.info("⚡ Optimization: Skipped {} packages already found in other trees ({} fewer API calls)",
                skippedCount, skippedCount);
        }

        // STEP 3: Find which INPUT packages appear as dependencies in OTHER input packages' trees
        Set<String> inputPackagesAppearingAsChildren = new HashSet<>();
        for (Map.Entry<String, DependencyNode> entry : completeTrees.entrySet()) {
            String treeRootName = entry.getKey();
            DependencyNode tree = entry.getValue();

            // Find input packages in this tree (excluding the root itself)
            findInputPackagesInTree(tree, inputPackageNames, inputPackagesAppearingAsChildren, treeRootName);
        }

        // STEP 4: Roots = input packages that DON'T appear as children
        Set<String> rootPackageNames = new HashSet<>(inputPackageNames);
        rootPackageNames.removeAll(inputPackagesAppearingAsChildren);

        logger.info("Found {} root packages out of {}", rootPackageNames.size(), inputPackages.size());

        // STEP 5: Return only the root trees
        List<DependencyNode> rootTrees = new ArrayList<>();
        for (String rootName : rootPackageNames) {
            DependencyNode tree = completeTrees.get(rootName);
            if (tree != null) {
                tree.markAsRoot();
                rootTrees.add(tree);
            }
        }

        // Store root nodes for conflict resolution
        this.rootNodes = rootTrees;

        return rootTrees;
    }

    /**
     * Recursively find which input packages appear in this tree
     */
    private void findInputPackagesInTree(
            DependencyNode node,
            Set<String> inputPackageNames,
            Set<String> inputPackagesAppearingAsChildren,
            String treeRootName) {

        if (node == null) {
            return;
        }

        String nodeName = node.getPackage().getFullName();

        // If this node is an input package (and not the tree root), mark it
        if (inputPackageNames.contains(nodeName) && !nodeName.equals(treeRootName)) {
            inputPackagesAppearingAsChildren.add(nodeName);
        }

        // Recurse into children
        for (DependencyNode child : node.getChildren()) {
            findInputPackagesInTree(child, inputPackageNames, inputPackagesAppearingAsChildren, treeRootName);
        }
    }

    /**
     * Recursively collect all package names from a dependency tree
     * Used to avoid fetching trees for packages already discovered
     *
     * @param node The tree node to collect from
     * @param packageNames Set to add package names to
     */
    private void collectAllPackageNames(DependencyNode node, Set<String> packageNames) {
        if (node == null) {
            return;
        }

        packageNames.add(node.getPackage().getFullName());

        // Recurse into children
        for (DependencyNode child : node.getChildren()) {
            collectAllPackageNames(child, packageNames);
        }
    }

    /**
     * Fetch the COMPLETE dependency tree for a package using the full graph
     * returned by deps.dev API
     */
    private DependencyNode fetchCompleteDependencyTree(Package pkg, Set<String> inputPackageNames) {
        try {
            JsonObject jsonObject = apiClient.getDependencyGraph(pkg);

            if (jsonObject == null) {
                logger.warn("WARNING: Unknown component {}. Treating as root dependency.", pkg.getFullName());
                return new DependencyNode(pkg, false);
            }

            // Parse the FULL graph, not just direct children
            return parseFullDependencyGraph(jsonObject, pkg, inputPackageNames);
        } catch (IOException e) {
            logger.error("Error fetching dependencies for {}: {}", pkg.getFullName(), e.getMessage());
            return new DependencyNode(pkg, false);
        }
    }

    /**
     * Parse the complete dependency graph from deps.dev response
     * This uses ALL nodes and edges, not just direct children
     */
    private DependencyNode parseFullDependencyGraph(JsonObject graph, Package rootPackage, Set<String> inputPackageNames) {
        JsonArray nodes = graph.getAsJsonArray("nodes");
        JsonArray edges = graph.getAsJsonArray("edges");

        if (nodes == null || edges == null) {
            return new DependencyNode(rootPackage, false);
        }

        // Build map: node index -> Package
        Map<Integer, Package> nodeMap = new HashMap<>();
        Map<Integer, DependencyNode> nodeTreeMap = new HashMap<>();
        int selfNodeIndex = -1;

        // Process all nodes
        for (int i = 0; i < nodes.size(); i++) {
            JsonObject node = nodes.get(i).getAsJsonObject();
            JsonObject versionKey = node.getAsJsonObject("versionKey");

            String system = versionKey.get("system").getAsString();
            String name = versionKey.get("name").getAsString();
            String version = versionKey.get("version").getAsString();
            String relation = node.get("relation").getAsString();

            // Check if we already have this package (deduplication)
            String fullName = system.toLowerCase() + ":" + name + ":" + version;
            Package pkg = allPackages.get(fullName);

            if (pkg == null) {
                pkg = new Package(system, name, version);
                allPackages.put(fullName, pkg);
            }

            // Create or reuse DependencyNode (for graph sharing)
            DependencyNode depNode = allNodes.get(fullName);
            if (depNode == null) {
                depNode = new DependencyNode(pkg, false);
                allNodes.put(fullName, depNode);
            }

            nodeMap.put(i, pkg);
            nodeTreeMap.put(i, depNode);

            // Find the SELF node
            if ("SELF".equals(relation)) {
                selfNodeIndex = i;
            }
        }

        // Build adjacency list from edges
        Map<Integer, List<Integer>> adjacency = new HashMap<>();
        for (JsonElement edge : edges) {
            JsonObject edgeObj = edge.getAsJsonObject();
            int fromNode = edgeObj.get("fromNode").getAsInt();
            int toNode = edgeObj.get("toNode").getAsInt();

            adjacency.computeIfAbsent(fromNode, k -> new ArrayList<>()).add(toNode);
        }

        // Note: We don't need to separately cache dependencies since they're
        // already captured in the tree structure via the adjacency list

        // Build tree structure using recursion from SELF node
        if (selfNodeIndex != -1) {
            buildTreeFromAdjacency(nodeTreeMap, adjacency, selfNodeIndex, 0, new HashSet<>());
            return nodeTreeMap.get(selfNodeIndex);
        }

        return new DependencyNode(rootPackage, false);
    }

    /**
     * Recursively build tree structure from adjacency list
     * Tracks parent-child relationships and reuses nodes from allNodes
     */
    private void buildTreeFromAdjacency(
            Map<Integer, DependencyNode> nodeTreeMap,
            Map<Integer, List<Integer>> adjacency,
            int currentNode,
            int depth,
            Set<Integer> visited) {

        // Prevent cycles
        if (visited.contains(currentNode)) {
            return;
        }
        visited.add(currentNode);

        DependencyNode currentTreeNode = nodeTreeMap.get(currentNode);
        if (currentTreeNode == null) {
            return;
        }

        // Get the parent package to check exclusions
        Package parentPkg = currentTreeNode.getPackage();
        Set<String> parentExclusions = exclusions.getOrDefault(parentPkg.getName(), Collections.emptySet());

        List<Integer> children = adjacency.getOrDefault(currentNode, Collections.emptyList());
        for (int childIndex : children) {
            DependencyNode childNode = nodeTreeMap.get(childIndex);
            if (childNode == null) {
                continue;
            }

            Package childPkg = childNode.getPackage();

            // Check if this child is excluded by the parent
            if (isExcluded(childPkg, parentExclusions)) {
                logger.debug("Excluding dependency {} from parent {}", childPkg.getName(), parentPkg.getName());
                continue; // Skip this child
            }

            // Add child if not already present (node reuse)
            if (!currentTreeNode.getChildren().contains(childNode)) {
                currentTreeNode.addChild(childNode);
            }

            // Track parent-child relationship
            parentMap.computeIfAbsent(childPkg.getFullName(), k -> new HashSet<>())
                     .add(parentPkg.getFullName());

            // Recursively build this child's subtree
            buildTreeFromAdjacency(nodeTreeMap, adjacency, childIndex, depth + 1, new HashSet<>(visited));
        }
    }

    /**
     * Check if a package should be excluded based on the parent's exclusions list
     *
     * @param pkg the package to check
     * @param parentExclusions set of excluded "groupId:artifactId"
     * @return true if the package should be excluded
     */
    private boolean isExcluded(Package pkg, Set<String> parentExclusions) {
        if (parentExclusions.isEmpty()) {
            return false;
        }

        // Check if the package name (groupId:artifactId) is in the exclusions set
        return parentExclusions.contains(pkg.getName());
    }

    /**
     * Get base key for a package (system:name without version).
     * Used for grouping different versions of the same library.
     *
     * @param pkg the package
     * @return base key in format "system:name"
     */
    private String getBaseKey(Package pkg) {
        return pkg.getSystem().toLowerCase() + ":" + pkg.getName();
    }

    /**
     * Get all packages discovered
     */
    public Collection<Package> getAllPackages() {
        return allPackages.values();
    }

    /**
     * Get all packages from the dependency trees - PHASE 1 ONLY
     * Returns ALL package versions discovered from deps.dev (no deduplication)
     *
     * @return collection of all packages including all versions
     */
    public Collection<Package> getAllReconciledPackages() {
        // PHASE 1: Return ALL packages from allPackages (includes all versions)
        logger.info("getAllReconciledPackages: returning {} packages (all versions)", allPackages.size());
        return allPackages.values();
    }

    /**
     * Phase 2: Apply conflict resolution to mark losing versions as excluded.
     *
     * For each library with multiple versions:
     * 1. Choose winner based on strategy (maven nearest-wins or highest)
     * 2. Add links from loser's parents → winner
     * 3. Mark losers as scope=excluded
     * 4. Mark loser subtrees as excluded (unless other incoming links)
     */
    public void applyConflictResolution(String strategy) {
        if (rootNodes == null || rootNodes.isEmpty()) {
            logger.warn("No root nodes available for conflict resolution");
            return;
        }

        logger.info("=== PHASE 2: Applying conflict resolution with strategy: {} ===", strategy);

        // Step 1: Determine winning versions
        Map<String, String> winningVersions;
        if ("maven".equals(strategy)) {
            winningVersions = determineMavenWinningVersions(rootNodes);
        } else {
            // Extract input packages from completeTrees
            List<Package> inputPackages = new ArrayList<>();
            for (String pkgName : completeTrees.keySet()) {
                Package pkg = allPackages.get(pkgName);
                if (pkg != null) {
                    inputPackages.add(pkg);
                }
            }
            winningVersions = determineHighestWinningVersions(inputPackages);
        }

        logger.info("Determined {} winning versions", winningVersions.size());

        // Step 2: Identify all losers (non-winning versions)
        Set<String> losers = new HashSet<>();
        int conflictsFound = 0;

        for (Map.Entry<String, DependencyNode> entry : allNodes.entrySet()) {
            String nodeName = entry.getKey();
            DependencyNode node = entry.getValue();
            Package pkg = node.getPackage();
            String baseKey = getBaseKey(pkg);
            String winningVersion = winningVersions.get(baseKey);

            if (winningVersion != null && !pkg.getVersion().equals(winningVersion)) {
                losers.add(nodeName);
                conflictsFound++;
                logger.debug("Loser identified: {} (winner: {}:{})", nodeName, baseKey, winningVersion);
            }
        }

        logger.info("Found {} losing versions out of {} total nodes", conflictsFound, allNodes.size());

        // Step 3: Redirect edges from loser parents → winner
        int redirectCount = redirectEdgesToWinners(losers, winningVersions);
        logger.info("Redirected {} edges to winning versions", redirectCount);

        // Step 4: Mark losers as excluded
        for (String loserName : losers) {
            DependencyNode loserNode = allNodes.get(loserName);
            if (loserNode == null) continue;

            Package loserPkg = loserNode.getPackage();
            String baseKey = getBaseKey(loserPkg);
            String winningVersion = winningVersions.get(baseKey);

            loserPkg.setScope("excluded");
            loserPkg.setScopeReason("conflict-resolution-loser");
            loserPkg.setWinningVersion(winningVersion);
            logger.debug("Marked as excluded: {} (winner: {})", loserName, winningVersion);
        }

        // Step 5: Mark loser subtrees as excluded (unless other incoming links)
        int excludedSubtreeCount = markLoserSubtreesExcluded(losers);
        logger.info("Marked {} subtree nodes as excluded", excludedSubtreeCount);

        logger.info("=== Conflict resolution complete: {} losers, {} redirects, {} subtree exclusions ===",
                conflictsFound, redirectCount, excludedSubtreeCount);

        // Step 6: Propagate test/provided/system scopes to transitive dependencies
        propagateExcludedScopes();
    }

    /**
     * Recursively collect all packages from a dependency tree
     * When encountering the same package with different versions, keeps the managed or highest version
     */
    private void collectPackagesFromTree(DependencyNode node, Map<String, Package> packageMap) {
        if (node == null) {
            return;
        }

        Package pkg = node.getPackage();
        // Use system:name as key (without version) to deduplicate different versions
        String baseKey = pkg.getSystem().toLowerCase() + ":" + pkg.getName();

        Package existing = packageMap.get(baseKey);
        if (existing == null) {
            // First time seeing this package
            packageMap.put(baseKey, pkg);
        } else {
            // Already have this package with a different version
            // Check if this one is managed or has a higher version
            String managedVersion = dependencyManagement.get(pkg.getName());

            if (managedVersion != null) {
                // If current package matches managed version, use it
                if (pkg.getVersion().equals(managedVersion)) {
                    packageMap.put(baseKey, pkg);
                    logger.debug("Replaced {} version {} with managed version {}",
                        baseKey, existing.getVersion(), pkg.getVersion());
                }
                // If existing matches managed version, keep it (do nothing)
                else if (existing.getVersion().equals(managedVersion)) {
                    // Keep existing
                }
                // Neither matches managed - keep higher version
                else if (compareVersions(pkg.getVersion(), existing.getVersion()) > 0) {
                    packageMap.put(baseKey, pkg);
                    logger.debug("Replaced {} version {} with higher version {}",
                        baseKey, existing.getVersion(), pkg.getVersion());
                }
            } else {
                // No managed version - use higher version
                if (compareVersions(pkg.getVersion(), existing.getVersion()) > 0) {
                    packageMap.put(baseKey, pkg);
                    logger.debug("Replaced {} version {} with higher version {}",
                        baseKey, existing.getVersion(), pkg.getVersion());
                }
            }
        }

        for (DependencyNode child : node.getChildren()) {
            collectPackagesFromTree(child, packageMap);
        }
    }

    /**
     * Phase 2: Determine winning versions using Maven nearest-wins strategy.
     * Returns map of package_base_key -> winning_version.
     */
    private Map<String, String> determineMavenWinningVersions(List<DependencyNode> roots) {
        logger.info("Determining winning versions using Maven nearest-wins");

        // BFS to find nearest occurrence of each package
        Map<String, Tuple<String, Integer>> firstOccurrence = new HashMap<>();
        Queue<Tuple<DependencyNode, Integer>> queue = new LinkedList<>();

        for (DependencyNode root : roots) {
            queue.add(new Tuple<>(root, 0));
        }

        Set<String> visited = new HashSet<>();

        while (!queue.isEmpty()) {
            Tuple<DependencyNode, Integer> current = queue.poll();
            DependencyNode node = current.first;
            int depth = current.second;

            Package pkg = node.getPackage();
            String baseKey = getBaseKey(pkg);
            String nodeId = baseKey + ":" + pkg.getVersion();

            if (visited.contains(nodeId)) {
                continue;
            }
            visited.add(nodeId);

            // Track first/nearest occurrence
            if (!firstOccurrence.containsKey(baseKey)) {
                firstOccurrence.put(baseKey, new Tuple<>(pkg.getVersion(), depth));
                logger.debug("First occurrence: {} v{} at depth {}", baseKey, pkg.getVersion(), depth);
            } else {
                Tuple<String, Integer> existing = firstOccurrence.get(baseKey);
                String existingVersion = existing.first;
                int existingDepth = existing.second;

                if (depth < existingDepth) {
                    logger.info("Nearer occurrence: {} v{} at depth {} replaces v{} at depth {}",
                            baseKey, pkg.getVersion(), depth, existingVersion, existingDepth);
                    firstOccurrence.put(baseKey, new Tuple<>(pkg.getVersion(), depth));
                } else if (depth == existingDepth && compareVersions(pkg.getVersion(), existingVersion) > 0) {
                    logger.info("Tie-breaker: {} at depth {}: v{} replaces v{} (higher)",
                            baseKey, depth, pkg.getVersion(), existingVersion);
                    firstOccurrence.put(baseKey, new Tuple<>(pkg.getVersion(), depth));
                }
            }

            // Queue children
            for (DependencyNode child : node.getChildren()) {
                queue.add(new Tuple<>(child, depth + 1));
            }
        }

        // Return just version map
        Map<String, String> result = new HashMap<>();
        for (Map.Entry<String, Tuple<String, Integer>> entry : firstOccurrence.entrySet()) {
            result.put(entry.getKey(), entry.getValue().first);
        }
        return result;
    }

    /**
     * Phase 2: Determine winning versions using highest version strategy.
     * Priority: 1) dependency management, 2) input package version, 3) highest seen.
     * Returns map of package_base_key -> winning_version.
     */
    private Map<String, String> determineHighestWinningVersions(List<Package> inputPackages) {
        logger.info("Determining winning versions using highest version strategy");

        Map<String, String> winningVersions = new HashMap<>();

        // Priority 1: Dependency management
        for (Map.Entry<String, String> entry : dependencyManagement.entrySet()) {
            String name = entry.getKey();
            String version = entry.getValue();

            // Find system for this name from allPackages
            for (Package pkg : allPackages.values()) {
                if (pkg.getName().equals(name)) {
                    String baseKey = getBaseKey(pkg);
                    winningVersions.put(baseKey, version);
                    logger.debug("Managed version: {} -> {}", baseKey, version);
                    break;
                }
            }
        }

        // Priority 2: Input package versions (only if successfully fetched)
        for (Package pkg : inputPackages) {
            String pkgName = pkg.getFullName();
            // Only use input version if we successfully fetched its graph
            if (!completeTrees.containsKey(pkgName)) {
                logger.debug("Skipping input version for {} (not in completeTrees)", pkgName);
                continue;
            }

            String baseKey = getBaseKey(pkg);
            if (!winningVersions.containsKey(baseKey)) {
                winningVersions.put(baseKey, pkg.getVersion());
                logger.debug("Input version: {} -> {}", baseKey, pkg.getVersion());
            }
        }

        // Priority 3: Highest version seen IN FETCHED GRAPHS
        for (Map.Entry<String, DependencyNode> entry : allNodes.entrySet()) {
            DependencyNode node = entry.getValue();
            Package pkg = node.getPackage();
            String baseKey = getBaseKey(pkg);

            if (winningVersions.containsKey(baseKey)) {
                // Already have a winner from higher priority - check if this is higher
                if (compareVersions(pkg.getVersion(), winningVersions.get(baseKey)) > 0) {
                    logger.debug("Higher version: {} {} -> {}", baseKey, winningVersions.get(baseKey), pkg.getVersion());
                    winningVersions.put(baseKey, pkg.getVersion());
                }
            } else {
                // First time seeing this package
                winningVersions.put(baseKey, pkg.getVersion());
            }
        }

        return winningVersions;
    }

    /**
     * Redirect edges from loser parents to winning versions.
     * For each loser, find all parents and add edges parent → winner.
     * Returns count of redirected edges.
     */
    private int redirectEdgesToWinners(Set<String> losers, Map<String, String> winningVersions) {
        int redirectCount = 0;

        for (String loserName : losers) {
            DependencyNode loserNode = allNodes.get(loserName);
            if (loserNode == null) {
                continue;
            }

            // Get loser's package info
            Package loserPkg = loserNode.getPackage();
            String baseKey = getBaseKey(loserPkg);
            String winningVersion = winningVersions.get(baseKey);

            if (winningVersion == null) {
                logger.warn("No winning version found for {}", baseKey);
                continue;
            }

            // Find winner node
            String winnerName = baseKey + ":" + winningVersion;
            DependencyNode winnerNode = allNodes.get(winnerName);

            if (winnerNode == null) {
                logger.warn("Winner node not found: {}", winnerName);
                continue;
            }

            // Get all parents of this loser
            Set<String> parentNames = parentMap.getOrDefault(loserName, Collections.emptySet());

            for (String parentName : parentNames) {
                DependencyNode parentNode = allNodes.get(parentName);
                if (parentNode == null) {
                    continue;
                }

                // Add winner as child of parent (if not already present)
                if (!parentNode.getChildren().contains(winnerNode)) {
                    parentNode.addChild(winnerNode);
                    // Update parent_map for the winner
                    parentMap.computeIfAbsent(winnerName, k -> new HashSet<>()).add(parentName);
                    redirectCount++;
                    logger.debug("Redirected: {} → {} (was {})", parentName, winnerName, loserName);
                }
            }
        }

        return redirectCount;
    }

    /**
     * Mark nodes in loser subtrees as excluded, UNLESS they have other incoming links
     * from non-excluded nodes.
     * Returns count of nodes marked as excluded.
     */
    private int markLoserSubtreesExcluded(Set<String> losers) {
        int excludedCount = 0;
        Set<String> visited = new HashSet<>();

        for (String loserName : losers) {
            DependencyNode loserNode = allNodes.get(loserName);
            if (loserNode == null) {
                continue;
            }

            // Recursively mark children (if they don't have other incoming links)
            excludedCount += markSubtreeExcludedRecursive(loserNode, visited, losers);
        }

        return excludedCount;
    }

    /**
     * Recursively mark children as excluded if ALL their parents are excluded.
     */
    private int markSubtreeExcludedRecursive(
            DependencyNode node,
            Set<String> visited,
            Set<String> excludedParents) {
        int count = 0;

        for (DependencyNode child : node.getChildren()) {
            String childName = child.getPackage().getFullName();

            if (visited.contains(childName)) {
                continue;
            }
            visited.add(childName);

            // Skip if already excluded
            if ("excluded".equals(child.getPackage().getScope())) {
                continue;
            }

            // Check if child has ANY non-excluded parents
            Set<String> childParents = parentMap.getOrDefault(childName, Collections.emptySet());
            boolean hasNonExcludedParent = false;
            for (String parentName : childParents) {
                if (!excludedParents.contains(parentName)) {
                    hasNonExcludedParent = true;
                    break;
                }
            }

            if (!hasNonExcludedParent) {
                // All parents are excluded, so mark this child as excluded too
                child.getPackage().setScope("excluded");
                child.getPackage().setScopeReason("conflict-resolution-subtree");
                count++;
                logger.debug("Marked subtree node as excluded: {}", childName);

                // Recursively mark its children
                // Add this child to excludedParents for recursive call
                Set<String> newExcluded = new HashSet<>(excludedParents);
                newExcluded.add(childName);
                count += markSubtreeExcludedRecursive(child, visited, newExcluded);
            }
        }

        return count;
    }

    /**
     * Simple version comparison - returns positive if v1 > v2, negative if v1 < v2, 0 if equal
     * This is a simplified comparison that works for most semantic versions
     */
    private int compareVersions(String v1, String v2) {
        if (v1.equals(v2)) {
            return 0;
        }

        // Split by dots and dashes
        String[] parts1 = v1.split("[.\\-]");
        String[] parts2 = v2.split("[.\\-]");

        int minLength = Math.min(parts1.length, parts2.length);
        for (int i = 0; i < minLength; i++) {
            String part1 = parts1[i];
            String part2 = parts2[i];

            // Try to parse as integers
            Integer num1 = tryParseInt(part1);
            Integer num2 = tryParseInt(part2);

            if (num1 != null && num2 != null) {
                // Both are numbers - compare numerically
                if (!num1.equals(num2)) {
                    return num1 - num2;
                }
            } else {
                // At least one is not a number - compare lexicographically
                int cmp = part1.compareTo(part2);
                if (cmp != 0) {
                    return cmp;
                }
            }
        }

        // If all compared parts are equal, longer version is considered higher
        return parts1.length - parts2.length;
    }

    /**
     * Try to parse a string as an integer, returning null if it fails
     */
    private Integer tryParseInt(String s) {
        try {
            return Integer.parseInt(s);
        } catch (NumberFormatException e) {
            return null;
        }
    }

    /**
     * Propagate test/provided/system scopes to transitive dependencies.
     *
     * Maven scope propagation rules:
     * - Test, provided, and system scopes propagate to all transitive dependencies
     * - Required scope (compile/runtime) overrides test scope if a package is reachable through both paths
     *
     * This ensures test libraries and their dependencies are properly excluded from runtime SBOMs.
     */
    private void propagateExcludedScopes() {
        if (rootNodes == null || rootNodes.isEmpty()) {
            logger.warn("No root nodes available for scope propagation");
            return;
        }

        logger.info("=== Propagating Maven scopes to transitive dependencies ===");

        // Track which packages are reachable from each scope type
        Set<String> testReachable = new HashSet<>();       // Reachable from test/provided/system roots
        Set<String> requiredReachable = new HashSet<>();   // Reachable from compile/runtime/None roots

        // Walk dependency tree from each root to build reachability sets
        for (DependencyNode root : rootNodes) {
            String rootScope = root.getPackage().getScope();
            if (rootScope == null) {
                rootScope = "required";
            }

            // Determine if this root is test-scoped or required-scoped
            if (rootScope.equals("test") || rootScope.equals("provided") ||
                rootScope.equals("system") || rootScope.equals("excluded")) {
                // Track all packages reachable from test-scoped roots
                collectReachablePackagesByScope(root, testReachable, new HashSet<>());
                logger.debug("Root {} has scope '{}' - marking transitives as test-reachable",
                    root.getPackage().getFullName(), rootScope);
            } else {
                // Track all packages reachable from required-scoped roots
                collectReachablePackagesByScope(root, requiredReachable, new HashSet<>());
                logger.debug("Root {} has scope '{}' - marking transitives as required-reachable",
                    root.getPackage().getFullName(), rootScope);
            }
        }

        // Apply scope propagation with override rule
        int propagatedCount = 0;
        for (String pkgName : testReachable) {
            // Skip if also reachable from required path (required overrides test)
            if (requiredReachable.contains(pkgName)) {
                logger.debug("Package {} reachable from both test and required paths - keeping as required", pkgName);
                continue;
            }

            // Mark as excluded since only reachable from test/provided/system paths
            DependencyNode node = allNodes.get(pkgName);
            if (node != null && !node.getPackage().getScope().equals("excluded")) {
                String oldScope = node.getPackage().getScope();
                node.getPackage().setScope("excluded");
                node.getPackage().setScopeReason("test-dependency");
                propagatedCount++;
                logger.debug("Propagated test scope to {} (was '{}')", pkgName, oldScope);
            }
        }

        logger.info("Scope propagation complete: {} packages marked as test dependencies", propagatedCount);
        logger.info("Reachability stats: {} test-reachable, {} required-reachable",
            testReachable.size(), requiredReachable.size());
    }

    /**
     * Collect all packages reachable from this node.
     * Used for scope propagation to track test vs required reachability.
     */
    private void collectReachablePackagesByScope(DependencyNode node, Set<String> reachable, Set<String> visited) {
        if (node == null) {
            return;
        }

        String pkgName = node.getPackage().getFullName();
        if (visited.contains(pkgName)) {
            return;
        }

        visited.add(pkgName);
        reachable.add(pkgName);

        // Recursively collect children
        for (DependencyNode child : node.getChildren()) {
            collectReachablePackagesByScope(child, reachable, visited);
        }
    }

    /**
     * Close resources
     */
    @Override
    public void close() {
        if (apiClient != null) {
            try {
                apiClient.close();
            } catch (Exception e) {
                logger.warn("Error closing API client: {}", e.getMessage());
            }
        }
    }
}
