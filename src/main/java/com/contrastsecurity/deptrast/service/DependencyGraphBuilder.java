package com.contrastsecurity.deptrast.service;

import com.contrastsecurity.deptrast.api.DepsDevClient;
import com.contrastsecurity.deptrast.model.Package;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Service to build a complete dependency graph and find root dependencies
 */
public class DependencyGraphBuilder implements AutoCloseable {
    private static final Logger logger = LoggerFactory.getLogger(DependencyGraphBuilder.class);
    private final DepsDevClient depsDevClient;
    private final Map<String, Package> allPackages;
    private final Map<String, List<Package>> dependencyMap;
    private Set<String> processedPackages;

    public DependencyGraphBuilder() {
        this.depsDevClient = new DepsDevClient();
        this.allPackages = new HashMap<>();
        this.processedPackages = new HashSet<>();
        this.dependencyMap = new HashMap<>();
        
        // Initialize the package cache
        PackageCache.getInstance();
    }

    /**
     * Builds a complete dependency graph from a flat list of packages
     * Determines parent-child relationships and identifies root dependencies
     * Uses batch API for better performance
     *
     * @param flatPackageList a flat list of all packages
     * @return a list of root packages (packages with no parents)
     */
    public List<Package> buildDependencyGraph(List<Package> flatPackageList) {
        logger.info("Building dependency graph from {} packages using batch API", flatPackageList.size());
        processedPackages.clear();
        
        // First, add all packages to our map for easy lookup
        for (Package pkg : flatPackageList) {
            String key = pkg.getFullName();
            allPackages.put(key, pkg);
        }
        
        // Use batch API to fetch dependencies for all packages at once
        try {
            // Get dependencies for all packages in batches
            Map<String, List<Package>> batchResults = depsDevClient.getBatchDependencies(flatPackageList);
            
            // Process results and build relationships
            processBatchResults(batchResults, flatPackageList);
            
            // Process any transitive dependencies
            processTransitiveDependencies();
        } catch (IOException e) {
            logger.error("Error fetching batch dependencies: {}", e.getMessage());
        }

        // Identify root packages (those with no parents)
        List<Package> rootPackages = findRootPackages();
        logger.info("Found {} root packages", rootPackages.size());
        return rootPackages;
    }

    /**
     * Process the batch API results and build relationships
     *
     * @param batchResults The results from the batch API call
     * @param initialPackages The initial list of packages we're analyzing
     */
    private void processBatchResults(Map<String, List<Package>> batchResults, List<Package> initialPackages) {
        AtomicInteger processedCount = new AtomicInteger(0);
        AtomicInteger dependencyCount = new AtomicInteger(0);
        
        // Process each package and its dependencies
        for (Package pkg : initialPackages) {
            String packageKey = pkg.getFullName();
            processedPackages.add(packageKey); // Mark as processed
            
            List<Package> dependencies = batchResults.get(packageKey);
            if (dependencies == null) {
                logger.warn("No dependencies found for {} in batch results", packageKey);
                dependencies = new ArrayList<>();
            }
            
            // Store in our dependency map for later reuse by tree builder
            dependencyMap.put(packageKey, new ArrayList<>(dependencies));
            
            // Process each dependency
            for (Package dependency : dependencies) {
                dependencyCount.incrementAndGet();
                
                // Try to use the already tracked package if we have it
                String dependencyKey = dependency.getFullName();
                Package trackedDependency = allPackages.get(dependencyKey);
                
                if (trackedDependency == null) {
                    // New dependency we haven't seen before
                    trackedDependency = dependency;
                    allPackages.put(dependencyKey, trackedDependency);
                }
                
                // Add the relationship in both directions
                pkg.addDependency(trackedDependency);
            }
            
            processedCount.incrementAndGet();
        }
        
        logger.info("Processed {} packages with {} dependencies from batch results", 
                processedCount.get(), dependencyCount.get());
    }
    
    /**
     * Process transitive dependencies that we discovered but weren't in the initial list
     */
    private void processTransitiveDependencies() throws IOException {
        // Find packages that need processing (discovered in dependencies but not initially provided)
        List<Package> toProcess = new ArrayList<>();
        for (String key : allPackages.keySet()) {
            if (!processedPackages.contains(key)) {
                toProcess.add(allPackages.get(key));
            }
        }
        
        if (toProcess.isEmpty()) {
            logger.info("No transitive dependencies to process");
            return;
        }
        
        logger.info("Processing {} transitive dependencies", toProcess.size());
        
        // Process them in batches using the batch API
        Map<String, List<Package>> batchResults = depsDevClient.getBatchDependencies(toProcess);
        
        // Process each result
        for (Package pkg : toProcess) {
            String packageKey = pkg.getFullName();
            processedPackages.add(packageKey);
            
            List<Package> dependencies = batchResults.get(packageKey);
            if (dependencies == null) {
                continue;
            }
            
            // Store in our dependency map for later reuse by tree builder
            dependencyMap.put(packageKey, new ArrayList<>(dependencies));
            
            for (Package dependency : dependencies) {
                // Try to use the already tracked package if we have it
                String dependencyKey = dependency.getFullName();
                Package trackedDependency = allPackages.get(dependencyKey);
                
                if (trackedDependency == null) {
                    trackedDependency = dependency;
                    allPackages.put(dependencyKey, trackedDependency);
                }
                
                // Add the relationship in both directions
                pkg.addDependency(trackedDependency);
            }
        }
        
        // Call the method again to handle any new transitive dependencies we found
        // We'll continue until we've processed all packages in the dependency tree
        if (toProcess.size() > 0) {
            processTransitiveDependencies();
        }
    }
    
    /**
     * Legacy method for processing a single package at a time
     * 
     * @deprecated Use batch mode instead
     */
    @Deprecated
    private void processPackage(Package pkg) throws IOException {
        String packageKey = pkg.getFullName();
        
        // Skip if we've already processed this package
        if (processedPackages.contains(packageKey)) {
            return;
        }
        
        processedPackages.add(packageKey);
        logger.info("Processing dependencies for {}", packageKey);

        try {
            // Get dependencies from the API
            List<Package> dependencies = depsDevClient.getDependencies(pkg);
            
            // Store in our dependency map for later reuse by tree builder
            dependencyMap.put(packageKey, new ArrayList<>(dependencies));
            
            for (Package dependency : dependencies) {
                // Try to use the already tracked package if we have it
                String dependencyKey = dependency.getFullName();
                Package trackedDependency = allPackages.get(dependencyKey);
                
                if (trackedDependency == null) {
                    // New dependency we haven't seen before
                    trackedDependency = dependency;
                    allPackages.put(dependencyKey, trackedDependency);
                }
                
                // Add the relationship in both directions
                pkg.addDependency(trackedDependency);
                
                // Recursively process this dependency to build the complete tree
                processPackage(trackedDependency);
            }
        } catch (Exception e) {
            logger.error("Error fetching dependencies for {}: {}", packageKey, e.getMessage());
        }
    }

    /**
     * Find packages that have no parents (root dependencies)
     * Using the new algorithm: packages that are not dependencies of any other package
     */
    private List<Package> findRootPackages() {
        List<Package> rootPackages = new ArrayList<>();
        PackageCache cache = PackageCache.getInstance();
        
        // Get all packages that are not dependencies of any other package
        Set<Package> packagesWithNoReverseDependencies = cache.getPackagesWithNoReverseDependencies();
        
        for (Package pkg : packagesWithNoReverseDependencies) {
            rootPackages.add(pkg);
            logger.info("Identified root package: {}", pkg.getFullName());
        }
        
        logger.info("Identified {} root packages using new algorithm", rootPackages.size());
        return rootPackages;
    }
    
    /**
     * Get all packages in the dependency graph
     */
    public Collection<Package> getAllPackages() {
        return allPackages.values();
    }
    
    /**
     * Get the stored dependency mapping from the graph builder
     * 
     * @return Map from package full name to its dependencies
     */
    public Map<String, List<Package>> getDependencyMap() {
        return dependencyMap;
    }
    
    /**
     * Close resources used by the dependency graph builder
     */
    @Override
    public void close() {
        // Close the API client to release its resources
        if (depsDevClient != null) {
            try {
                depsDevClient.close();
                logger.info("Closed DepsDevClient resources");
            } catch (Exception e) {
                logger.warn("Error closing DepsDevClient: {}", e.getMessage());
            }
        }
    }
}