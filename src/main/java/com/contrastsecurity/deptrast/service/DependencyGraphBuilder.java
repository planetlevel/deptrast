package com.contrastsecurity.deptrast.service;

import com.contrastsecurity.deptrast.api.DepsDevClient;
import com.contrastsecurity.deptrast.model.DependencyNode;
import com.contrastsecurity.deptrast.model.Package;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.*;
import java.io.IOException;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.*;
import java.util.concurrent.TimeUnit;

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
    private static final String BASE_URL = "https://api.deps.dev/v3alpha/systems";

    private final OkHttpClient client;
    private final Map<String, DependencyNode> completeTrees; // pkg fullName -> its full tree
    private final PackageCache cache;

    public DependencyGraphBuilder() {
        OkHttpClient.Builder clientBuilder = new OkHttpClient.Builder()
                .connectTimeout(30, TimeUnit.SECONDS)
                .readTimeout(30, TimeUnit.SECONDS)
                .retryOnConnectionFailure(false);

        // Create a trust manager that does not validate certificate chains
        try {
            TrustManager[] trustAllCerts = new TrustManager[]{
                new X509TrustManager() {
                    @Override
                    public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
                    }

                    @Override
                    public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
                    }

                    @Override
                    public X509Certificate[] getAcceptedIssuers() {
                        return new X509Certificate[0];
                    }
                }
            };

            // Install the all-trusting trust manager
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, trustAllCerts, new java.security.SecureRandom());

            // Create an SSL socket factory with our all-trusting manager
            SSLSocketFactory sslSocketFactory = sslContext.getSocketFactory();

            // Set SSL settings on the client builder
            clientBuilder.sslSocketFactory(sslSocketFactory, (X509TrustManager) trustAllCerts[0])
                         .hostnameVerifier((hostname, session) -> true);

        } catch (NoSuchAlgorithmException | KeyManagementException e) {
            logger.error("Error setting up SSL context: {}", e.getMessage());
        }

        this.client = clientBuilder.build();
        this.completeTrees = new HashMap<>();
        this.cache = PackageCache.getInstance();
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
        }

        // STEP 2: Fetch complete dependency graph for each package
        for (Package pkg : inputPackages) {
            DependencyNode tree = fetchCompleteDependencyTree(pkg, inputPackageNames);
            if (tree != null) {
                completeTrees.put(pkg.getFullName(), tree);
            }
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

        // If this package base name is in our observed versions, update it
        if (observedVersions.containsKey(baseKey)) {
            String observedVersion = observedVersions.get(baseKey);
            String currentVersion = pkg.getVersion();

            if (!observedVersion.equals(currentVersion)) {
                // Create new package with observed version
                Package reconciledPkg = new Package(pkg.getSystem(), pkg.getName(), observedVersion);
                node.setPackage(reconciledPkg);
            }
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
     * Fetch the COMPLETE dependency tree for a package using the full graph
     * returned by deps.dev API
     */
    private DependencyNode fetchCompleteDependencyTree(Package pkg, Set<String> inputPackageNames) {
        try {
            String url = String.format("%s/%s/packages/%s/versions/%s:dependencies",
                    BASE_URL, pkg.getSystem().toLowerCase(), pkg.getName(), pkg.getVersion());

            Request request = new Request.Builder().url(url).get().build();

            try (Response response = client.newCall(request).execute()) {
                if (!response.isSuccessful()) {
                    logger.error("Failed to get dependencies for {}: {}", pkg.getFullName(), response.code());
                    return new DependencyNode(pkg, 0);
                }

                String responseBody = response.body().string();
                JsonObject jsonObject = JsonParser.parseString(responseBody).getAsJsonObject();

                // Parse the FULL graph, not just direct children
                return parseFullDependencyGraph(jsonObject, pkg, inputPackageNames);
            }
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

        List<Integer> children = adjacency.getOrDefault(currentNode, Collections.emptyList());
        for (int childIndex : children) {
            Package childPkg = nodeTreeMap.get(childIndex).getPackage();
            if (childPkg != null) {
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

        List<Integer> children = adjacency.getOrDefault(currentNodeIndex, Collections.emptyList());
        for (int childIndex : children) {
            Package childPkg = nodeTreeMap.get(childIndex).getPackage();
            if (childPkg != null) {
                DependencyNode childNode = new DependencyNode(childPkg, depth + 1);
                parentNode.addChild(childNode);

                // Recurse
                buildChildSubtree(childNode, nodeTreeMap, adjacency, childIndex, depth + 1, new HashSet<>(visited));
            }
        }
    }

    /**
     * Get all packages discovered
     */
    public Collection<Package> getAllPackages() {
        return cache.getAllPackages();
    }

    /**
     * Close resources
     */
    @Override
    public void close() {
        if (client != null) {
            client.dispatcher().cancelAll();
            client.connectionPool().evictAll();
            client.dispatcher().executorService().shutdown();
        }
    }
}
