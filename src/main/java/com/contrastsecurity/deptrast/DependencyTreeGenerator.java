package com.contrastsecurity.deptrast;

import com.contrastsecurity.deptrast.model.DependencyNode;
import com.contrastsecurity.deptrast.model.Package;
import com.contrastsecurity.deptrast.service.DependencyGraphBuilder;
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
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.LoggerContext;

import org.cyclonedx.generators.json.BomJsonGenerator;
import org.cyclonedx.model.Bom;
import org.cyclonedx.model.Component;
import org.cyclonedx.model.Dependency;
import org.cyclonedx.model.Metadata;
import org.cyclonedx.model.Tool;
import org.cyclonedx.Version;

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
            System.out.println("Usage: java -jar deptrast.jar <input-file> [options]");
            System.out.println("  <input-file>: Path to a file containing all package dependencies");
            System.out.println("  [--maven-format=<root-project>]: Optional flag to output in Maven dependency:tree format");
            System.out.println("                                    with the specified root project name");
            System.out.println("  [--detailed-report=<output-file>]: Generate a detailed report of dependency paths and version conflicts");
            System.out.println("  [--sbom=<output-file>]: Generate CycloneDX 1.6 SBOM JSON file");
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
        String rootProject = null; // For Maven dependency:tree format
        boolean useMavenFormat = false;
        String detailedReportPath = null; // Path for detailed report output
        String sbomOutputPath = null; // Path for SBOM output
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
            } else if (arg.startsWith("--sbom=")) {
                sbomOutputPath = arg.substring(7); // Extract file path after '='
                logger.info("Will generate CycloneDX SBOM at: {}", sbomOutputPath);
            } else if (arg.equals("--verbose") || arg.equals("-v")) {
                verbose = true;
            } else {
                System.err.println("Unknown argument: " + arg + ". Ignoring.");
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

            // Parse packages from input file
            List<Package> allPackages = FileParser.parsePackagesFromFile(inputFilePath);
            
            if (allPackages.isEmpty()) {
                logger.error("No valid packages found in the input file");
                System.out.println("No valid packages found in the input file. Check format and try again.");
                return;
            }
            
            logger.info("Loaded {} packages from the input file", allPackages.size());
            System.out.println("Analyzing dependencies for " + allPackages.size() + " packages...");

            // Build dependency trees using optimized algorithm
            graphBuilder = new DependencyGraphBuilder();
            List<DependencyNode> dependencyTree = graphBuilder.buildDependencyTrees(allPackages);
            Collection<Package> allTrackedPackages = graphBuilder.getAllPackages();
            int rootCount = dependencyTree.size();

            logger.info("Identified {} root packages", rootCount);

            PackageCache cache = PackageCache.getInstance();

            // Generate detailed dependency report if requested
            if (detailedReportPath != null) {
                generateDetailedReport(detailedReportPath, cache);
            }

            // Generate SBOM if requested
            if (sbomOutputPath != null) {
                generateSbom(sbomOutputPath, cache.getAllPackages());
            }

            if (!useMavenFormat) {
                System.out.println("\nIdentified " + rootCount + " root dependencies:");
                for (DependencyNode rootNode : dependencyTree) {
                    System.out.println("  " + rootNode.getPackage().getFullName());
                }
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
                for (DependencyNode tree : dependencyTree) {
                    System.out.println(tree.getTreeRepresentation());
                }
            }

            System.out.println("\nDependency Statistics:");
            System.out.println("  Total Packages: " + allTrackedPackages.size());
            System.out.println("  Root Packages: " + rootCount);
            
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
                logger.info("Successfully closed resources");
            } catch (Exception e) {
                logger.warn("Error cleaning up resources: {}", e.getMessage());
            }
        }
    }
    
    
    /**
     * Generate a CycloneDX SBOM from the analyzed dependencies
     *
     * @param outputFilePath Path to output the SBOM file
     * @param packages List of packages to include in the SBOM
     */
    private static void generateSbom(String outputFilePath, Collection<Package> packages) {
        try {
            PackageCache cache = PackageCache.getInstance();

            // Create a new BOM
            Bom bom = new Bom();
            bom.setSerialNumber("urn:uuid:" + UUID.randomUUID());

            Metadata metadata = new Metadata();
            metadata.setTimestamp(new Date());
            Tool tool = new Tool();
            tool.setName("deptrast");
            tool.setVendor("Contrast Security");
            List<Tool> tools = new ArrayList<>();
            tools.add(tool);
            metadata.setTools(tools);
            bom.setMetadata(metadata);

            // Add all packages as components and track purlByPackage for dependency graph
            List<Component> components = new ArrayList<>();
            Map<Package, String> purlByPackage = new HashMap<>();

            for (Package pkg : packages) {
                Component component = new Component();
                component.setType(Component.Type.LIBRARY);
                String purl;

                if ("maven".equalsIgnoreCase(pkg.getSystem())) {
                    // For Maven packages, separate group and artifact if available
                    String name = pkg.getName();
                    if (name.contains(":")) {
                        String[] parts = name.split(":");
                        component.setGroup(parts[0]);
                        component.setName(parts[1]);
                    } else {
                        component.setName(name);
                    }
                    purl = "pkg:maven/" + (component.getGroup() != null ? component.getGroup() : "") +
                           "/" + component.getName() + "@" + pkg.getVersion();
                } else {
                    // For other package systems
                    component.setName(pkg.getName());
                    purl = "pkg:" + pkg.getSystem().toLowerCase() + "/" + pkg.getName() + "@" + pkg.getVersion();
                }

                component.setVersion(pkg.getVersion());
                component.setPurl(purl);
                components.add(component);
                purlByPackage.put(pkg, purl);
            }

            bom.setComponents(components);

            // Build dependency graph from the cache
            List<Dependency> dependencies = new ArrayList<>();

            // For each package, create a dependency entry with its direct dependencies from cache
            for (Package pkg : packages) {
                String pkgPurl = purlByPackage.get(pkg);
                Dependency dependency = new Dependency(pkgPurl);

                // Get direct dependencies from the cache
                List<Package> directDeps = cache.getCachedDependencies(pkg);
                if (directDeps != null && !directDeps.isEmpty()) {
                    for (Package depPkg : directDeps) {
                        if (purlByPackage.containsKey(depPkg)) {
                            String depPurl = purlByPackage.get(depPkg);
                            dependency.addDependency(new Dependency(depPurl));
                        }
                    }
                }

                dependencies.add(dependency);
            }

            // Set dependencies on BOM
            for (Dependency dependency : dependencies) {
                bom.addDependency(dependency);
            }
            
            // Generate JSON output
            BomJsonGenerator generator = new BomJsonGenerator(bom, Version.VERSION_16);
            String jsonOutput = generator.toJsonString(true);
            
            // Write to file
            try (BufferedWriter writer = new BufferedWriter(new FileWriter(outputFilePath))) {
                writer.write(jsonOutput);
                logger.info("SBOM successfully written to: {}", outputFilePath);
                System.out.println("SBOM successfully written to: " + outputFilePath);
            }
            
        } catch (Exception e) {
            logger.error("Error generating SBOM: {}", e.getMessage(), e);
            System.err.println("Error generating SBOM: " + e.getMessage());
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