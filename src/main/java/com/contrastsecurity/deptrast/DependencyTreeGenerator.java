package com.contrastsecurity.deptrast;

import com.contrastsecurity.deptrast.model.DependencyNode;
import com.contrastsecurity.deptrast.model.Package;
import com.contrastsecurity.deptrast.service.DependencyGraphBuilder;
import com.contrastsecurity.deptrast.service.DependencyTreeBuilder;
import com.contrastsecurity.deptrast.util.FileParser;
import com.contrastsecurity.deptrast.util.MavenDependencyTreeFormatter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.contrastsecurity.deptrast.model.PackageDependencyInfo;
import com.contrastsecurity.deptrast.service.PackageCache;

import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.LoggerContext;

/**
 * Main application class for generating dependency trees
 */
public class DependencyTreeGenerator {
    
    private static DependencyGraphBuilder graphBuilder;
    private static final String NEW_LINE = System.lineSeparator();
    private static final Logger logger = LoggerFactory.getLogger(DependencyTreeGenerator.class);

    public static void main(String[] args) {
        // Register shutdown hook for clean termination
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            logger.info("Shutdown hook triggered, cleaning up resources");
            cleanupResources();
        }));
        if (args.length < 1) {
            System.out.println("Usage: java -jar deptrast.jar <input-file> [max-depth] [options]");
            System.out.println("  <input-file>: Path to a file containing all package dependencies");
            System.out.println("  [max-depth]: Optional maximum depth for dependency resolution (default: 25)");
            System.out.println("  [--maven-format=<root-project>]: Optional flag to output in Maven dependency:tree format");
            System.out.println("                                    with the specified root project name");
            System.out.println("  [--detailed-report=<output-file>]: Generate a detailed report of dependency paths and version conflicts");
            System.out.println("  [--verbose|-v]: Enable verbose logging output");
            System.out.println("\nInput file format:");
            System.out.println("  Each line should contain a package in the format: system:name:version");
            System.out.println("  For Maven packages: maven:groupId:artifactId:version");
            System.out.println("  For npm packages: npm:packageName:version");
            System.out.println("\nExample:");
            System.out.println("  maven:org.springframework.boot:spring-boot-starter-web:2.7.0");
            System.out.println("  npm:react:17.0.2");
            return;
        }

        String inputFilePath = args[0];
        int maxDepth = 25; // Default max depth
        String rootProject = null; // For Maven dependency:tree format
        boolean useMavenFormat = false;
        String detailedReportPath = null; // Path for detailed report output
        boolean verbose = false; // Verbose output flag
        
        // Parse additional arguments
        for (int i = 1; i < args.length; i++) {
            String arg = args[i];
            
            if (arg.startsWith("--maven-format=")) {
                useMavenFormat = true;
                rootProject = arg.substring(15); // Extract project name after '='
                if (rootProject.isEmpty()) {
                    rootProject = "project"; // Default name if not provided
                }
            } else if (arg.startsWith("--detailed-report=")) {
                detailedReportPath = arg.substring(18); // Extract file path after '='
                logger.info("Will generate detailed dependency report at: {}", detailedReportPath);
            } else if (arg.equals("--verbose") || arg.equals("-v")) {
                verbose = true;
            } else {
                try {
                    maxDepth = Integer.parseInt(arg);
                    if (maxDepth <= 0) {
                        System.err.println("Max depth must be greater than 0. Using default value of 10.");
                        maxDepth = 25;
                    }
                } catch (NumberFormatException e) {
                    System.err.println("Invalid argument: " + arg + ". Ignoring.");
                }
            }
        }

        try {
            // Set logging level based on verbose flag
            if (verbose) {
                setLoggingLevel(Level.INFO);
                logger.info("Verbose mode enabled");
            }
            
            // Initialize the package cache
            PackageCache.getInstance().clear();
            
            logger.info("Starting dependency analysis with max depth: {}", maxDepth);
            
            // Parse packages from input file
            List<Package> allPackages = FileParser.parsePackagesFromFile(inputFilePath);
            
            if (allPackages.isEmpty()) {
                logger.error("No valid packages found in the input file");
                System.out.println("No valid packages found in the input file. Check format and try again.");
                return;
            }
            
            logger.info("Loaded {} packages from the input file", allPackages.size());
            System.out.println("Analyzing dependencies for " + allPackages.size() + " packages...");
            
            // Build dependency graph
            graphBuilder = new DependencyGraphBuilder();
            // Build the dependency graph
            graphBuilder.buildDependencyGraph(allPackages);
            
            PackageCache cache = PackageCache.getInstance();
            Set<Package> packagesWithNoReverseDeps = cache.getPackagesWithNoReverseDependencies();
            List<Package> rootPackages = new ArrayList<>(packagesWithNoReverseDeps);
            
            List<Package> inputPackages = new ArrayList<>(allPackages);
            inputPackages.removeAll(rootPackages); // Remove those that are already root packages
            
            logger.info("Identified {} root packages (those with no reverse dependencies)", rootPackages.size());
            
            // Generate detailed dependency report if requested
            if (detailedReportPath != null) {
                generateDetailedReport(detailedReportPath, cache);
            }
            
            if (!useMavenFormat) {
                System.out.println("\nIdentified " + rootPackages.size() + " root dependencies:");
                for (Package rootPkg : rootPackages) {
                    System.out.println("  " + rootPkg.getFullName());
                }
            }
            
            DependencyTreeBuilder treeBuilder = new DependencyTreeBuilder();
            treeBuilder.setMaxDepth(maxDepth);
            Map<String, List<Package>> dependencyMap = graphBuilder.getDependencyMap();
            List<DependencyNode> dependencyTree = treeBuilder.buildDependencyTree(rootPackages, dependencyMap);
            
            Map<String, String> observedVersions = new HashMap<>();
            for (Package pkg : allPackages) {
                String baseKey = pkg.getSystem().toLowerCase() + ":" + pkg.getName();
                observedVersions.put(baseKey, pkg.getVersion());
            }
            
            updateTreeVersions(dependencyTree, observedVersions);
            
            for (DependencyNode rootNode : dependencyTree) {
                rootNode.markAsRoot();
            }
            
            // Only add project root node for standard format (not for Maven format)
            if (!useMavenFormat) {
                DependencyNode projectRootNode = new DependencyNode(new Package("project", rootProject != null ? rootProject : "root", "1.0.0"), 0, false);
                
                for (DependencyNode node : new ArrayList<>(dependencyTree)) {
                    projectRootNode.addChild(node);
                }
                
                dependencyTree = Collections.singletonList(projectRootNode);
            }
            
            if (useMavenFormat && rootProject != null) {
                String mavenTree = MavenDependencyTreeFormatter.formatMavenDependencyTree(rootProject, dependencyTree);
                System.out.println(mavenTree);
            } else {
                System.out.println("\nDependency Tree:\n");
                treeBuilder.printDependencyTree(dependencyTree);
            }
            
            Collection<Package> allTrackedPackages = graphBuilder.getAllPackages();
            System.out.println("\nDependency Statistics:");
            System.out.println("  Total Packages: " + allTrackedPackages.size());
            System.out.println("  Root Packages: " + rootPackages.size());
            
            logger.info("Dependency tree generation completed successfully");
            
            cleanupResources();
        } catch (Exception e) {
            logger.error("Error generating dependency tree: {}", e.getMessage(), e);
            System.err.println("Error generating dependency tree: " + e.getMessage());
            e.printStackTrace();
        } finally {
            cleanupResources();
        }
    }
    
    /**
     * Generate a detailed report of dependency paths and version conflicts
     * 
     * @param outputFilePath Path to output the detailed report
     * @param cache The package cache containing dependency information
     */
    
    /**
     * Set the logging level for the application
     * 
     * @param level The logging level to set
     */
    private static void setLoggingLevel(Level level) {
        LoggerContext loggerContext = (LoggerContext) LoggerFactory.getILoggerFactory();
        loggerContext.getLogger("com.contrastsecurity.deptrast").setLevel(level);
    }
    
    /**
     * Clean up resources and close any open connections
     */
    private static void cleanupResources() {
        if (graphBuilder != null) {
            try {
                graphBuilder.close();
                logger.info("Successfully closed all resources");
            } catch (Exception e) {
                logger.warn("Error cleaning up resources: {}", e.getMessage());
            }
        }
    }
    
    
    /**
     * Updates the versions in the dependency tree to match observed versions from input file
     * 
     * @param nodes The dependency tree nodes to update
     * @param observedVersions Map of system:name to observed version
     */
    private static void updateTreeVersions(List<DependencyNode> nodes, Map<String, String> observedVersions) {
        if (nodes == null) {
            return;
        }
        
        for (DependencyNode node : nodes) {
            Package pkg = node.getPackage();
            String baseKey = pkg.getSystem().toLowerCase() + ":" + pkg.getName();
            
            if (observedVersions.containsKey(baseKey)) {
                String observedVersion = observedVersions.get(baseKey);
                if (!observedVersion.equals(pkg.getVersion())) {
                    Package newPkg = new Package(pkg.getSystem(), pkg.getName(), observedVersion);
                    node.setPackage(newPkg);
                }
            }
            
            updateTreeVersions(node.getChildren(), observedVersions);
        }
    }
    
    private static void generateDetailedReport(String outputFilePath, PackageCache cache) {
        try (BufferedWriter writer = new BufferedWriter(new FileWriter(outputFilePath))) {
            Map<String, PackageDependencyInfo> detailedInfo = cache.getDetailedDependencyInfo();
            
            writer.write("# DEPENDENCY ANALYSIS REPORT" + NEW_LINE + NEW_LINE);
            writer.write(String.format("Total packages analyzed: %d%s", cache.size(), NEW_LINE));
            writer.write(String.format("Unique libraries (ignoring versions): %d%s%s", detailedInfo.size(), NEW_LINE, NEW_LINE));
            
            List<PackageDependencyInfo> packagesWithConflicts = detailedInfo.values().stream()
                    .filter(PackageDependencyInfo::hasVersionConflicts)
                    .collect(Collectors.toList());
            
            writer.write("## VERSION CONFLICTS" + NEW_LINE + NEW_LINE);
            writer.write(String.format("Found %d libraries with version conflicts:%s%s", packagesWithConflicts.size(), NEW_LINE, NEW_LINE));
            
            for (PackageDependencyInfo info : packagesWithConflicts) {
                writer.write(String.format("### %s%s%s", info.getBaseName(), NEW_LINE, NEW_LINE));
                writer.write("| Version | Used by |" + NEW_LINE);
                writer.write("|---------|---------|" + NEW_LINE);
                
                for (Package version : info.getVersions()) {
                    StringBuilder usedBy = new StringBuilder();
                    Set<Package> reverseDeps = cache.getReverseDependencies(version);
                    for (Package dep : reverseDeps) {
                        usedBy.append(dep.getFullName()).append(", ");
                    }
                    String usedByStr = usedBy.length() > 2 ? 
                            usedBy.substring(0, usedBy.length() - 2) : "(no direct usage)";
                    
                    writer.write(String.format("| %s | %s |%s", version.getVersion(), usedByStr, NEW_LINE));
                }
                writer.write(NEW_LINE);
            }
            
            List<PackageDependencyInfo> rootPackages = detailedInfo.values().stream()
                    .filter(info -> !info.hasReverseDependencies())
                    .collect(Collectors.toList());
            
            writer.write("## ROOT DEPENDENCIES" + NEW_LINE + NEW_LINE);
            writer.write(String.format("Found %d root dependencies (not depended upon by any other package):%s%s", rootPackages.size(), NEW_LINE, NEW_LINE));
            
            for (PackageDependencyInfo info : rootPackages) {
                for (Package version : info.getVersions()) {
                    writer.write(String.format("- %s%s", version.getFullName(), NEW_LINE));
                }
            }
            writer.write(NEW_LINE);
            
            writer.write("## DETAILED DEPENDENCY PATHS" + NEW_LINE + NEW_LINE);
            
            List<String> sortedBaseNames = new ArrayList<>(detailedInfo.keySet());
            Collections.sort(sortedBaseNames);
            
            for (String baseName : sortedBaseNames) {
                PackageDependencyInfo info = detailedInfo.get(baseName);
                writer.write(String.format("### %s%s%s", baseName, NEW_LINE, NEW_LINE));
                
                writer.write(String.format("**Root Dependency**: %s%s%s", !info.hasReverseDependencies() ? "Yes" : "No", NEW_LINE, NEW_LINE));
                
                if (info.hasReverseDependencies()) {
                    writer.write("**Dependency Paths**:" + NEW_LINE + NEW_LINE);
                    
                    for (Package version : info.getVersions()) {
                        writer.write(String.format("#### Version: %s%s%s", version.getVersion(), NEW_LINE, NEW_LINE));
                        Set<Package> reverseDeps = cache.getReverseDependencies(version);
                        
                        if (reverseDeps.isEmpty()) {
                            writer.write("No packages directly depend on this version." + NEW_LINE + NEW_LINE);
                        } else {
                            for (Package parent : reverseDeps) {
                                writer.write(String.format("- %s%s", parent.getFullName(), NEW_LINE));
                            }
                            writer.write(NEW_LINE);
                        }
                    }
                }
                
                writer.write("---" + NEW_LINE + NEW_LINE);
            }
            
            logger.info("Detailed dependency report written to: {}", outputFilePath);
            System.out.println("Detailed dependency report written to: " + outputFilePath);
            
        } catch (IOException e) {
            logger.error("Error generating detailed report: {}", e.getMessage());
            System.err.println("Error generating detailed report: " + e.getMessage());
        }
    }
}