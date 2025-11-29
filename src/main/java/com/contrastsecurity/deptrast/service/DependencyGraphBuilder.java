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
    private final Map<String, DependencyNode> allNodes; // fullName -> DependencyNode (for graph node reuse across API calls)
    private Map<String, String> dependencyManagement; // groupId:artifactId -> version
    private Map<String, Set<String>> exclusions; // package name -> set of excluded "groupId:artifactId"
    private String resolutionStrategy = "highest"; // maven or highest

    public DependencyGraphBuilder() {
        this.apiClient = new DepsDevClient();
        this.completeTrees = new HashMap<>();
        this.allPackages = new HashMap<>();
        this.allNodes = new HashMap<>();
        this.dependencyManagement = new HashMap<>();
        this.exclusions = new HashMap<>();
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
     * Set resolution strategy (maven or highest)
     *
     * @param resolutionStrategy "maven" for Maven nearest-wins, "highest" for highest version
     */
    public void setResolutionStrategy(String resolutionStrategy) {
        this.resolutionStrategy = resolutionStrategy != null ? resolutionStrategy : "highest";
        logger.info("Resolution strategy set to: {}", this.resolutionStrategy);
    }

    /**
     * Main algorithm:
     * 1. Fetch complete dependency graph for each input package
     * 2. Track which INPUT packages appear as dependencies in OTHER trees
     * 3. Roots = input packages NOT appearing as dependencies
     */
    public List<DependencyNode> buildDependencyTrees(List<Package> inputPackages) {
        logger.info("Building dependency trees for {} packages using optimized algorithm", inputPackages.size());

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

            // Skip if we already have a complete tree for this package
            if (completeTrees.containsKey(pkgName)) {
                logger.debug("Skipping {} - already have complete tree", pkgName);
                skippedCount++;
                continue;
            }

            // Check if this package appears in any OTHER package's tree
            // If so, we still need to fetch its tree for cloning purposes
            boolean foundInOtherTree = packagesAlreadyInTrees.contains(pkgName);

            DependencyNode tree = fetchCompleteDependencyTree(pkg, inputPackageNames);
            if (tree != null) {
                completeTrees.put(pkgName, tree);

                if (foundInOtherTree) {
                    logger.debug("Package {} found in another tree but fetched for cloning", pkgName);
                    skippedCount++; // Still count as optimization since we found it earlier
                }

                // Add all packages in this tree to the set to track what we've seen
                collectAllPackageNames(tree, packagesAlreadyInTrees);
            }
        }

        if (skippedCount > 0) {
            logger.info("⚡ Optimization: Skipped {} packages already found in other trees ({} fewer API calls)",
                skippedCount, skippedCount);
        }

        // STEP 2.5/2.6: Version resolution strategy
        if ("maven".equals(resolutionStrategy)) {
            // Maven nearest-wins: Use the version found nearest to the root in the dependency tree
            logger.info("Applying Maven nearest-wins version resolution");
            applyNearestWinsResolution(new ArrayList<>(completeTrees.values()));
        } else {
            // Default: Highest version reconciliation - replace declared versions with actual runtime versions
            // This handles Maven's dependency resolution where the runtime has a different version
            // than what was declared in pom.xml files
            Map<String, String> observedVersions = new HashMap<>();
            for (Package pkg : inputPackages) {
                String baseKey = pkg.getSystem().toLowerCase() + ":" + pkg.getName();
                observedVersions.put(baseKey, pkg.getVersion());
            }

            for (DependencyNode tree : completeTrees.values()) {
                reconcileTreeVersions(tree, observedVersions, inputPackageNames);
            }
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

        return rootTrees;
    }

    /**
     * Reconcile versions in the dependency tree with actual runtime versions
     * This handles cases where Maven resolved a different version than what was declared
     * or when dependency management overrides versions
     */
    private void reconcileTreeVersions(
            DependencyNode node,
            Map<String, String> observedVersions,
            Set<String> inputPackageNames) {

        if (node == null) {
            return;
        }

        Package pkg = node.getPackage();
        String baseKey = pkg.getSystem().toLowerCase() + ":" + pkg.getName();
        String currentVersion = pkg.getVersion();
        String reconciledVersion = null;

        // Priority 1: Check if this package is in our dependencyManagement (from POM)
        // This handles property overrides like thymeleaf.version in petclinic
        if (dependencyManagement.containsKey(pkg.getName())) {
            String managedVersion = dependencyManagement.get(pkg.getName());
            if (!managedVersion.equals(currentVersion)) {
                reconciledVersion = managedVersion;
                logger.debug("Applying managed version for {}: {} -> {}", pkg.getName(), currentVersion, managedVersion);
            }
        }

        // Priority 2: If this package base name is in our observed versions, update it
        // This handles actual runtime versions
        if (reconciledVersion == null && observedVersions.containsKey(baseKey)) {
            String observedVersion = observedVersions.get(baseKey);
            if (!observedVersion.equals(currentVersion)) {
                reconciledVersion = observedVersion;
                logger.debug("Applying observed version for {}: {} -> {}", baseKey, currentVersion, observedVersion);
            }
        }

        // Apply the reconciled version if we found one
        if (reconciledVersion != null) {
            logger.info("Reconciling {} from {} to {}", pkg.getName(), currentVersion, reconciledVersion);
            Package reconciledPkg = new Package(pkg.getSystem(), pkg.getName(), reconciledVersion);
            node.setPackage(reconciledPkg);

            // IMPORTANT: Fetch the dependency tree for the NEW version
            // This ensures we get the correct dependencies for the reconciled version
            logger.debug("Fetching dependencies for reconciled version {}", reconciledPkg.getFullName());
            DependencyNode newTree = fetchCompleteDependencyTree(reconciledPkg, inputPackageNames);

            if (newTree != null && !newTree.getChildren().isEmpty()) {
                // Replace the children with the new version's dependencies
                node.getChildren().clear();
                for (DependencyNode newChild : newTree.getChildren()) {
                    node.addChild(newChild);
                    // Recursively reconcile the new subtree
                    reconcileTreeVersions(newChild, observedVersions, inputPackageNames);
                }
                logger.debug("Replaced {} children for reconciled {}", newTree.getChildren().size(), reconciledPkg.getFullName());
                return; // Don't recurse into old children - we already processed new ones
            } else {
                logger.debug("No new dependencies found for reconciled {}", reconciledPkg.getFullName());
            }
        }

        // Recurse into children (only if we didn't replace them above)
        for (DependencyNode child : node.getChildren()) {
            reconcileTreeVersions(child, observedVersions, inputPackageNames);
        }
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

                // CRITICAL: Check if we already have this node from another package's graph
                // If we do, return the existing node (which may have children populated)
                // Don't create a new empty node that would lose the children!
                String fullName = pkg.getFullName();
                if (allNodes.containsKey(fullName)) {
                    logger.debug("Package {} returned 404 but already exists in allNodes with children - reusing", fullName);
                    return allNodes.get(fullName);
                }

                // Only create new empty node if we've never seen this package before
                return new DependencyNode(pkg);
            }

            // Parse the FULL graph, not just direct children
            return parseFullDependencyGraph(jsonObject, pkg, inputPackageNames);
        } catch (IOException e) {
            logger.error("Error fetching dependencies for {}: {}", pkg.getFullName(), e.getMessage());

            // Same check for error case
            String fullName = pkg.getFullName();
            if (allNodes.containsKey(fullName)) {
                logger.debug("Package {} threw error but already exists in allNodes with children - reusing", fullName);
                return allNodes.get(fullName);
            }

            return new DependencyNode(pkg);
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
            return new DependencyNode(rootPackage);
        }

        // Build map: node index -> Package
        // Also build ONE DependencyNode per unique package (graph, not tree!)
        Map<Integer, Package> nodeMap = new HashMap<>();
        Map<Integer, DependencyNode> nodeGraphMap = new HashMap<>();
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

            nodeMap.put(i, pkg);

            // Reuse existing DependencyNode if we've already created one for this package
            // Use the class-level allNodes map to share nodes across ALL API calls
            if (!allNodes.containsKey(fullName)) {
                allNodes.put(fullName, new DependencyNode(pkg));
            }

            nodeGraphMap.put(i, allNodes.get(fullName));

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
        // already captured in the graph structure via the adjacency list

        // Build graph structure using recursion from SELF node
        if (selfNodeIndex != -1) {
            buildTreeFromAdjacency(nodeGraphMap, adjacency, selfNodeIndex, new HashSet<>());
            return nodeGraphMap.get(selfNodeIndex);
        }

        return new DependencyNode(rootPackage);
    }

    /**
     * Recursively build graph structure from adjacency list
     */
    private void buildTreeFromAdjacency(
            Map<Integer, DependencyNode> nodeGraphMap,
            Map<Integer, List<Integer>> adjacency,
            int currentNode,
            Set<Integer> visited) {

        // Prevent cycles
        if (visited.contains(currentNode)) {
            return;
        }
        visited.add(currentNode);

        DependencyNode currentGraphNode = nodeGraphMap.get(currentNode);
        if (currentGraphNode == null) {
            return;
        }

        // Get the parent package to check exclusions
        Package parentPkg = currentGraphNode.getPackage();
        Set<String> parentExclusions = exclusions.getOrDefault(parentPkg.getName(), Collections.emptySet());

        List<Integer> children = adjacency.getOrDefault(currentNode, Collections.emptyList());
        for (int childIndex : children) {
            DependencyNode childNode = nodeGraphMap.get(childIndex);
            Package childPkg = childNode.getPackage();

            if (childPkg != null) {
                // Check if this child is excluded by the parent
                if (isExcluded(childPkg, parentExclusions)) {
                    logger.debug("Excluding dependency {} from parent {}", childPkg.getName(), parentPkg.getName());
                    continue; // Skip this child
                }

                // Just add reference to existing node - NO cloning needed!
                currentGraphNode.addChild(childNode);

                // Recursively build this child's edges
                buildTreeFromAdjacency(nodeGraphMap, adjacency, childIndex, new HashSet<>(visited));
            }
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
     * Helper class for BFS traversal with depth tracking
     */
    private static class NodeWithDepth {
        DependencyNode node;
        int depth;

        NodeWithDepth(DependencyNode node, int depth) {
            this.node = node;
            this.depth = depth;
        }
    }

    /**
     * Helper class to track version and depth for Maven nearest-wins
     */
    private static class VersionDepth {
        String version;
        int depth;

        VersionDepth(String version, int depth) {
            this.version = version;
            this.depth = depth;
        }
    }

    /**
     * Apply Maven's nearest-wins resolution algorithm
     * Uses BFS to find the nearest occurrence of each package and updates all nodes to use that version
     */
    private void applyNearestWinsResolution(List<DependencyNode> roots) {
        logger.info("Applying Maven nearest-wins version resolution");

        // Track: package base name -> (version, depth)
        Map<String, VersionDepth> firstOccurrence = new HashMap<>();

        // BFS traversal to find first occurrence of each package
        Queue<NodeWithDepth> queue = new LinkedList<>();
        for (DependencyNode root : roots) {
            queue.offer(new NodeWithDepth(root, 0));
        }

        Set<String> visited = new HashSet<>();

        while (!queue.isEmpty()) {
            NodeWithDepth current = queue.poll();
            DependencyNode node = current.node;
            int depth = current.depth;

            Package pkg = node.getPackage();
            String baseKey = pkg.getSystem().toLowerCase() + ":" + pkg.getName();
            String nodeId = baseKey + ":" + pkg.getVersion() + ":" + depth;

            // Prevent infinite loops in cyclic dependencies
            if (visited.contains(nodeId)) {
                continue;
            }
            visited.add(nodeId);

            // First occurrence wins (or nearer occurrence)
            if (!firstOccurrence.containsKey(baseKey)) {
                firstOccurrence.put(baseKey, new VersionDepth(pkg.getVersion(), depth));
                logger.debug("First occurrence: {} at depth {} with version {}",
                    baseKey, depth, pkg.getVersion());
            } else {
                // Check if this occurrence is nearer
                VersionDepth existing = firstOccurrence.get(baseKey);
                if (depth < existing.depth) {
                    // Nearer occurrence - update the winning version
                    logger.info("Found nearer occurrence of {}: depth {} (v{}) replaces depth {} (v{})",
                        baseKey, depth, pkg.getVersion(), existing.depth, existing.version);
                    firstOccurrence.put(baseKey, new VersionDepth(pkg.getVersion(), depth));
                }
            }

            // Add children to queue
            for (DependencyNode child : node.getChildren()) {
                queue.offer(new NodeWithDepth(child, depth + 1));
            }
        }

        // Second pass: Update all nodes to use the winning version
        for (DependencyNode root : roots) {
            updateVersionsToNearestWins(root, firstOccurrence, new HashSet<>());
        }

        logger.info("Applied nearest-wins resolution to {} packages", firstOccurrence.size());
    }

    /**
     * Recursively update versions based on nearest-wins resolution
     */
    private void updateVersionsToNearestWins(
            DependencyNode node,
            Map<String, VersionDepth> winningVersions,
            Set<String> visited) {

        Package pkg = node.getPackage();
        String baseKey = pkg.getSystem().toLowerCase() + ":" + pkg.getName();
        String nodeId = baseKey + ":" + pkg.getVersion();

        // Prevent infinite loops in cyclic dependencies
        if (visited.contains(nodeId)) {
            return;
        }
        visited.add(nodeId);

        VersionDepth winner = winningVersions.get(baseKey);
        if (winner != null && !winner.version.equals(pkg.getVersion())) {
            logger.debug("Updating {} from {} to {} (nearest-wins)",
                baseKey, pkg.getVersion(), winner.version);

            Package updatedPkg = new Package(pkg.getSystem(), pkg.getName(), winner.version);
            node.setPackage(updatedPkg);

            // IMPORTANT: Fetch the correct dependency tree for the new version
            logger.debug("Fetching dependencies for reconciled version {}", updatedPkg.getFullName());
            DependencyNode winnerTree = fetchCompleteDependencyTree(updatedPkg, new HashSet<>());

            if (winnerTree != null && !winnerTree.getChildren().isEmpty()) {
                node.getChildren().clear();
                for (DependencyNode child : winnerTree.getChildren()) {
                    node.addChild(child);
                    updateVersionsToNearestWins(child, winningVersions, new HashSet<>(visited));
                }
                logger.debug("Replaced {} children for nearest-wins {}", winnerTree.getChildren().size(), updatedPkg.getFullName());
            } else {
                logger.debug("No new dependencies found for nearest-wins {}", updatedPkg.getFullName());
            }
        } else {
            // Version is already correct, just recurse
            for (DependencyNode child : node.getChildren()) {
                updateVersionsToNearestWins(child, winningVersions, new HashSet<>(visited));
            }
        }
    }

    /**
     * Get all packages discovered
     */
    public Collection<Package> getAllPackages() {
        return allPackages.values();
    }

    /**
     * Get all packages from the reconciled dependency trees
     * This returns the actual Package objects with reconciled versions
     * When multiple versions of the same package exist, keeps the managed version or highest version
     *
     * @return collection of all reconciled packages
     */
    public Collection<Package> getAllReconciledPackages() {
        Map<String, Package> packageMap = new HashMap<>();

        for (DependencyNode tree : completeTrees.values()) {
            collectPackagesFromTree(tree, packageMap);
        }

        return packageMap.values();
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
