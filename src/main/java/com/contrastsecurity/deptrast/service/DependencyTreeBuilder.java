package com.contrastsecurity.deptrast.service;

import com.contrastsecurity.deptrast.api.DepsDevClient;
import com.contrastsecurity.deptrast.model.DependencyNode;
import com.contrastsecurity.deptrast.model.Package;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Service to build a dependency tree from root dependencies
 */
public class DependencyTreeBuilder {
    private static final Logger logger = LoggerFactory.getLogger(DependencyTreeBuilder.class);
    private final DepsDevClient depsDevClient;
    private final Set<String> processedPackages;
    private Map<String, List<Package>> dependencyMap; // Pre-fetched dependencies
    private int maxDepth = 25; // Default max depth to prevent infinite recursion

    public DependencyTreeBuilder() {
        this.depsDevClient = new DepsDevClient();
        this.processedPackages = new HashSet<>();
        this.dependencyMap = new HashMap<>();
    }
    
    /**
     * Build a dependency tree using a pre-built dependency graph
     * 
     * @param rootPackages the root packages to build the tree from
     * @param dependencyMap map of package fullName to its dependencies
     * @return list of dependency nodes representing the root of each tree
     */
    public List<DependencyNode> buildDependencyTree(List<Package> rootPackages, Map<String, List<Package>> dependencyMap) {
        List<DependencyNode> rootNodes = new ArrayList<>();
        processedPackages.clear();
        this.dependencyMap = dependencyMap;

        for (Package rootPkg : rootPackages) {
            DependencyNode rootNode = new DependencyNode(rootPkg, 0);
            try {
                buildTreeRecursiveFromMap(rootNode, 0);
                rootNodes.add(rootNode);
            } catch (Exception e) {
                logger.error("Error building dependency tree for {}: {}", rootPkg.getFullName(), e.getMessage());
            }
        }

        return rootNodes;
    }
    
    public List<DependencyNode> buildDependencyTree(List<Package> rootPackages, boolean useCache) {
        List<DependencyNode> rootNodes = new ArrayList<>();
        processedPackages.clear();

        for (Package rootPkg : rootPackages) {
            DependencyNode rootNode = new DependencyNode(rootPkg, 0);
            try {
                buildTreeRecursive(rootNode, 0, useCache);
                rootNodes.add(rootNode);
            } catch (IOException e) {
                logger.error("Error building dependency tree for {}: {}", rootPkg.getFullName(), e.getMessage());
            }
        }

        return rootNodes;
    }

    public void setMaxDepth(int maxDepth) {
        this.maxDepth = maxDepth;
    }

    /**
     * Build a dependency tree for a set of root packages
     *
     * @param rootPackages the root packages to build a tree for
     * @return a list of dependency nodes representing the root of each tree
     */
    public List<DependencyNode> buildDependencyTree(List<Package> rootPackages) {
        // Default to using cache
        return buildDependencyTree(rootPackages, true);
    }

    /**
     * Build the tree using the pre-fetched dependency map
     */
    private void buildTreeRecursiveFromMap(DependencyNode node, int depth) {
        if (depth >= maxDepth) {
            logger.warn("Max depth reached for {}", node.getPackage().getFullName());
            return;
        }

        String packageKey = node.getPackage().getFullName();
        if (processedPackages.contains(packageKey)) {
            logger.debug("Package {} already processed, skipping", packageKey);
            return;
        }

        processedPackages.add(packageKey);
        logger.info("Processing dependencies for {} at depth {}", packageKey, depth);

        List<Package> dependencies = dependencyMap.getOrDefault(packageKey, Collections.emptyList());
        
        for (Package dependency : dependencies) {
            DependencyNode childNode = new DependencyNode(dependency, depth + 1);
            node.addChild(childNode);
            buildTreeRecursiveFromMap(childNode, depth + 1);
        }
    }
    
    /**
     * Build a dependency tree for a single package
     * 
     * @param node the starting node
     * @param dependencyMap pre-fetched dependency map
     */
    public void buildTreeForPackage(DependencyNode node, Map<String, List<Package>> dependencyMap) {
        this.dependencyMap = dependencyMap;
        processedPackages.clear();
        buildTreeRecursiveFromMap(node, 0);
    }
    
    private void buildTreeRecursive(DependencyNode node, int depth, boolean useCache) throws IOException {
        if (depth >= maxDepth) {
            logger.warn("Max depth reached for {}", node.getPackage().getFullName());
            return;
        }

        String packageKey = node.getPackage().getFullName();
        if (processedPackages.contains(packageKey)) {
            logger.debug("Package {} already processed, skipping", packageKey);
            return;
        }

        processedPackages.add(packageKey);
        logger.info("Processing dependencies for {} at depth {}", packageKey, depth);

        List<Package> dependencies;
        if (useCache) {
            PackageCache cache = PackageCache.getInstance();
            if (cache.hasCachedDependencies(node.getPackage())) {
                logger.debug("Using cached dependencies for {}", packageKey);
                dependencies = cache.getCachedDependencies(node.getPackage());
            } else {
                dependencies = depsDevClient.getDependencies(node.getPackage());
            }
        } else {
            dependencies = depsDevClient.getDependencies(node.getPackage());
        }
        
        for (Package dependency : dependencies) {
            DependencyNode childNode = new DependencyNode(dependency, depth + 1);
            node.addChild(childNode);
            buildTreeRecursive(childNode, depth + 1, useCache);
        }
    }
    
    private void buildTreeRecursive(DependencyNode node, int depth) throws IOException {
        buildTreeRecursive(node, depth, true);
    }

    /**
     * Print the dependency tree to console
     * 
     * @param rootNodes the root nodes of the dependency tree
     */
    public void printDependencyTree(List<DependencyNode> rootNodes) {
        for (DependencyNode rootNode : rootNodes) {
            System.out.println(rootNode.getTreeRepresentation());
        }
    }
}