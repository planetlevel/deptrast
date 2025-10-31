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
    private final PackageCache cache;
    private Map<String, String> dependencyManagement; // groupId:artifactId -> version
    private Map<String, Set<String>> exclusions; // package name -> set of excluded "groupId:artifactId"

    public DependencyGraphBuilder() {
        this.apiClient = new DepsDevClient();
        this.completeTrees = new HashMap<>();
        this.cache = PackageCache.getInstance();
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
            logger.warn("⚡ Optimization: Skipped {} packages already found in other trees ({} fewer API calls)",
                skippedCount, skippedCount);
        }

        // STEP 2.5: Version reconciliation - replace declared versions with actual runtime versions
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
            Package reconciledPkg = new Package(pkg.getSystem(), pkg.getName(), reconciledVersion);
            node.setPackage(reconciledPkg);
        }

        // Recurse into children
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
                return new DependencyNode(pkg, 0);
            }

            // Parse the FULL graph, not just direct children
            return parseFullDependencyGraph(jsonObject, pkg, inputPackageNames);
        } catch (IOException e) {
            logger.error("Error fetching dependencies for {}: {}", pkg.getFullName(), e.getMessage());
            return new DependencyNode(pkg, 0);
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
            return new DependencyNode(rootPackage, 0);
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

            // Check if we already have this package in the cache
            String fullName = system.toLowerCase() + ":" + name + ":" + version;
            Package pkg = cache.getCachedPackage(fullName);

            if (pkg == null) {
                pkg = new Package(system, name, version);
                cache.cachePackage(pkg);
            }

            nodeMap.put(i, pkg);
            nodeTreeMap.put(i, new DependencyNode(pkg, 0)); // Depth updated later

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

        // Cache direct dependencies for each package
        for (Map.Entry<Integer, Package> entry : nodeMap.entrySet()) {
            int nodeIndex = entry.getKey();
            Package pkg = entry.getValue();

            // Get direct dependencies (children in adjacency list)
            List<Integer> childIndices = adjacency.getOrDefault(nodeIndex, Collections.emptyList());
            List<Package> directDeps = new ArrayList<>();
            for (int childIndex : childIndices) {
                Package childPkg = nodeMap.get(childIndex);
                if (childPkg != null) {
                    directDeps.add(childPkg);
                }
            }

            // Cache the direct dependencies
            cache.cacheDependencies(pkg, directDeps);
        }

        // Build tree structure using recursion from SELF node
        if (selfNodeIndex != -1) {
            buildTreeFromAdjacency(nodeTreeMap, adjacency, selfNodeIndex, 0, new HashSet<>());
            return nodeTreeMap.get(selfNodeIndex);
        }

        return new DependencyNode(rootPackage, 0);
    }

    /**
     * Recursively build tree structure from adjacency list
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
            Package childPkg = nodeTreeMap.get(childIndex).getPackage();
            if (childPkg != null) {
                // Check if this child is excluded by the parent
                if (isExcluded(childPkg, parentExclusions)) {
                    logger.debug("Excluding dependency {} from parent {}", childPkg.getName(), parentPkg.getName());
                    continue; // Skip this child
                }

                // Create new node with correct depth
                DependencyNode newChildNode = new DependencyNode(childPkg, depth + 1);
                currentTreeNode.addChild(newChildNode);

                // Recursively build this child's subtree
                buildChildSubtree(newChildNode, nodeTreeMap, adjacency, childIndex, depth + 1, new HashSet<>(visited));
            }
        }
    }

    /**
     * Build subtree for a child node
     */
    private void buildChildSubtree(
            DependencyNode parentNode,
            Map<Integer, DependencyNode> nodeTreeMap,
            Map<Integer, List<Integer>> adjacency,
            int currentNodeIndex,
            int depth,
            Set<Integer> visited) {

        if (visited.contains(currentNodeIndex)) {
            return;
        }
        visited.add(currentNodeIndex);

        // Get the parent package to check exclusions
        Package parentPkg = parentNode.getPackage();
        Set<String> parentExclusions = exclusions.getOrDefault(parentPkg.getName(), Collections.emptySet());

        List<Integer> children = adjacency.getOrDefault(currentNodeIndex, Collections.emptyList());
        for (int childIndex : children) {
            Package childPkg = nodeTreeMap.get(childIndex).getPackage();
            if (childPkg != null) {
                // Check if this child is excluded by the parent
                if (isExcluded(childPkg, parentExclusions)) {
                    logger.debug("Excluding dependency {} from parent {}", childPkg.getName(), parentPkg.getName());
                    continue; // Skip this child
                }

                DependencyNode childNode = new DependencyNode(childPkg, depth + 1);
                parentNode.addChild(childNode);

                // Recurse
                buildChildSubtree(childNode, nodeTreeMap, adjacency, childIndex, depth + 1, new HashSet<>(visited));
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
     * Get all packages discovered
     */
    public Collection<Package> getAllPackages() {
        return cache.getAllPackages();
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
