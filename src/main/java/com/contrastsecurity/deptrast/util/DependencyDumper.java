package com.contrastsecurity.deptrast.util;

import com.contrastsecurity.deptrast.api.DepsDevClient;
import com.contrastsecurity.deptrast.model.Package;

import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.HashSet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Utility to dump all dependencies for a set of packages in a flat file
 * 
 * Note: This utility fetches only direct dependencies from deps.dev API.
 * The deps.dev API does not return transitive dependencies automatically.
 */
public class DependencyDumper {
    
    private static final Logger logger = LoggerFactory.getLogger(DependencyDumper.class);
    private final DepsDevClient depsDevClient;
    private final Map<String, Set<String>> dependencyMap;
    
    public DependencyDumper() {
        this.depsDevClient = new DepsDevClient();
        this.dependencyMap = new HashMap<>();
    }
    
    /**
     * Process a file containing package definitions and dump all direct dependencies
     * 
     * @param inputFilePath Path to the input file with package definitions
     * @param outputFilePath Path to the output file for dependencies
     * @throws IOException if there's an error reading or writing files
     */
    public void dumpDependencies(String inputFilePath, String outputFilePath) throws IOException {
        // Parse input file to get packages
        List<Package> packages = FileParser.parsePackagesFromFile(inputFilePath);
        logger.info("Processing {} packages...", packages.size());
        System.out.println("Processing " + packages.size() + " packages...");
        
        // Process each package to get its dependencies
        for (Package pkg : packages) {
            try {
                String packageKey = pkg.getFullName();
                logger.info("Fetching dependencies for {}", packageKey);
                System.out.println("Fetching dependencies for " + packageKey);
                
                // Get direct dependencies from deps.dev API
                List<Package> dependencies = depsDevClient.getDependencies(pkg);
                
                // Record these dependencies
                Set<String> deps = new HashSet<>();
                for (Package dep : dependencies) {
                    deps.add(dep.getFullName());
                }
                dependencyMap.put(packageKey, deps);
                logger.info("Found {} direct dependencies for {}", deps.size(), packageKey);
                
            } catch (Exception e) {
                logger.error("Error processing {}: {}", pkg.getFullName(), e.getMessage());
                System.err.println("Error processing " + pkg.getFullName() + ": " + e.getMessage());
            }
        }
        
        // Write the dependency map to the output file
        writeToFile(outputFilePath);
    }
    
    /**
     * Recursively fetch all transitive dependencies for a set of packages
     * 
     * @param inputFilePath Path to the input file with package definitions
     * @param outputFilePath Path to the output file for dependencies
     * @param maxDepth Maximum recursion depth (to prevent infinite recursion)
     * @throws IOException if there's an error reading or writing files
     */
    public void dumpAllTransitiveDependencies(String inputFilePath, String outputFilePath, int maxDepth) throws IOException {
        // Parse input file to get packages
        List<Package> packages = FileParser.parsePackagesFromFile(inputFilePath);
        logger.info("Processing {} packages with recursive dependency fetching...", packages.size());
        System.out.println("Processing " + packages.size() + " packages with recursive dependency fetching...");
        
        // Set to track all packages we've processed to avoid duplicates
        Set<String> processedPackages = new HashSet<>();
        
        // Process each package 
        for (Package pkg : packages) {
            String packageKey = pkg.getFullName();
            logger.info("Starting recursive dependency fetch for {}", packageKey);
            System.out.println("Starting recursive dependency fetch for " + packageKey);
            
            // Create a set for this package's dependencies
            Set<String> allDependencies = new HashSet<>();
            dependencyMap.put(packageKey, allDependencies);
            
            // Recursively fetch dependencies
            fetchDependenciesRecursively(pkg, allDependencies, processedPackages, 0, maxDepth);
            
            logger.info("Found {} total dependencies for {}", allDependencies.size(), packageKey);
            System.out.println("Found " + allDependencies.size() + " total dependencies for " + packageKey);
        }
        
        // Write the dependency map to the output file
        writeToFile(outputFilePath);
    }
    
    /**
     * Recursively fetch dependencies up to a certain depth
     * 
     * @param pkg The package to fetch dependencies for
     * @param allDependencies Set to store all dependencies found
     * @param processedPackages Set of packages already processed to avoid cycles
     * @param currentDepth Current recursion depth
     * @param maxDepth Maximum recursion depth
     */
    private void fetchDependenciesRecursively(Package pkg, Set<String> allDependencies, 
            Set<String> processedPackages, int currentDepth, int maxDepth) {
        
        // Check if we've reached max depth or already processed this package
        String pkgKey = pkg.getFullName();
        if (currentDepth > maxDepth || processedPackages.contains(pkgKey)) {
            return;
        }
        
        // Mark as processed to avoid cycles
        processedPackages.add(pkgKey);
        
        try {
            // Get direct dependencies
            List<Package> dependencies = depsDevClient.getDependencies(pkg);
            
            // Add dependencies and recurse
            for (Package dep : dependencies) {
                String depKey = dep.getFullName();
                allDependencies.add(depKey);
                
                // Recursively get dependencies of this dependency
                fetchDependenciesRecursively(dep, allDependencies, processedPackages, currentDepth + 1, maxDepth);
            }
        } catch (Exception e) {
            logger.error("Error fetching dependencies for {}: {}", pkgKey, e.getMessage());
        }
    }
    
    /**
     * Write the dependency map to a file
     */
    private void writeToFile(String outputFilePath) throws IOException {
        try (BufferedWriter writer = new BufferedWriter(new FileWriter(outputFilePath))) {
            for (Map.Entry<String, Set<String>> entry : dependencyMap.entrySet()) {
                String packageName = entry.getKey();
                Set<String> dependencies = entry.getValue();
                
                // Write package information
                writer.write("PACKAGE: " + packageName);
                writer.newLine();
                writer.write("DEPENDENCIES_COUNT: " + dependencies.size());
                writer.newLine();
                
                // Write dependencies
                for (String dependency : dependencies) {
                    writer.write("  " + dependency);
                    writer.newLine();
                }
                
                // Add a separator between packages
                writer.write("-------------------------------------------");
                writer.newLine();
            }
        }
        
        logger.info("Dependency information written to {}", outputFilePath);
        System.out.println("Dependency information written to " + outputFilePath);
    }
    
    public static void main(String[] args) {
        if (args.length < 2) {
            System.out.println("Usage: java DependencyDumper <input-file> <output-file> [--recursive] [max-depth]");
            System.out.println("  --recursive: Fetch all transitive dependencies recursively");
            System.out.println("  max-depth: Maximum recursion depth (default: 5)");
            return;
        }
        
        String inputFilePath = args[0];
        String outputFilePath = args[1];
        boolean recursive = false;
        int maxDepth = 5; // Default max depth
        
        // Parse optional arguments
        for (int i = 2; i < args.length; i++) {
            if ("--recursive".equals(args[i])) {
                recursive = true;
            } else {
                try {
                    maxDepth = Integer.parseInt(args[i]);
                } catch (NumberFormatException e) {
                    System.err.println("Invalid max depth value: " + args[i] + ". Using default: 5");
                }
            }
        }
        
        try {
            DependencyDumper dumper = new DependencyDumper();
            
            if (recursive) {
                System.out.println("Fetching all transitive dependencies with max depth: " + maxDepth);
                dumper.dumpAllTransitiveDependencies(inputFilePath, outputFilePath, maxDepth);
            } else {
                System.out.println("Fetching direct dependencies only");
                dumper.dumpDependencies(inputFilePath, outputFilePath);
            }
        } catch (IOException e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace();
        }
    }
}