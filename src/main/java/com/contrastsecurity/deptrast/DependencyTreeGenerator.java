package com.contrastsecurity.deptrast;

import com.contrastsecurity.deptrast.model.DependencyNode;
import com.contrastsecurity.deptrast.model.Package;
import com.contrastsecurity.deptrast.service.DependencyGraphBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
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

        if (args.length < 2) {
            printUsage();
            return;
        }

        String inputFilePath = args[0];
        String outputFilePath = args[1];

        // Parse options
        String inputFormat = "auto";
        String inputType = "smart";
        String outputFormat = "tree";
        String projectName = "project";
        boolean verbose = false;

        // Parse additional arguments
        for (int i = 2; i < args.length; i++) {
            String arg = args[i];

            if (arg.startsWith("--iformat=")) {
                inputFormat = arg.substring(10).toLowerCase();
            } else if (arg.startsWith("--itype=")) {
                inputType = arg.substring(8).toLowerCase();
            } else if (arg.startsWith("--oformat=")) {
                outputFormat = arg.substring(10).toLowerCase();
            } else if (arg.startsWith("--project-name=")) {
                projectName = arg.substring(15);
            } else if (arg.equals("--verbose") || arg.equals("-v")) {
                verbose = true;
            } else {
                System.err.println("Unknown argument: " + arg + ". Ignoring.");
            }
        }

        // Auto-detect input format if set to "auto"
        if ("auto".equals(inputFormat)) {
            inputFormat = detectInputFormat(inputFilePath);
        }

        // Smart input type detection
        if ("smart".equals(inputType)) {
            inputType = getSmartInputType(inputFormat);
        }

        // Validate formats
        if (!isValidInputFormat(inputFormat)) {
            System.err.println("Invalid input format: " + inputFormat);
            System.err.println("Valid formats: auto, flat, pom, gradle, pypi, sbom");
            return;
        }

        if (!isValidInputType(inputType)) {
            System.err.println("Invalid input type: " + inputType);
            System.err.println("Valid types: all, roots, smart");
            return;
        }

        if (!isValidOutputFormat(outputFormat)) {
            System.err.println("Invalid output format: " + outputFormat);
            System.err.println("Valid formats: tree, maven, sbom");
            return;
        }

        try {
            // Set logging level based on verbose flag
            if (verbose) {
                setLoggingLevel(Level.INFO);
                logger.info("Verbose mode enabled");
                logger.info("Input: {} (format={}, type={})", inputFilePath, inputFormat, inputType);
                logger.info("Output: {} (format={})", outputFilePath, outputFormat);
            }

            // Initialize the package cache
            PackageCache.getInstance().clear();

            // Parse packages from input file based on input format
            List<Package> allPackages;
            String originalSbomContent = null; // Store original SBOM if input is SBOM

            switch (inputFormat) {
                case "flat":
                    allPackages = FileParser.parsePackagesFromFile(inputFilePath);
                    break;
                case "sbom":
                    allPackages = FileParser.parseSbomFile(inputFilePath);
                    // If output is also SBOM, preserve original content
                    if ("sbom".equals(outputFormat)) {
                        try {
                            originalSbomContent = new String(java.nio.file.Files.readAllBytes(
                                java.nio.file.Paths.get(inputFilePath)));
                        } catch (IOException e) {
                            logger.warn("Could not read original SBOM content: {}", e.getMessage());
                        }
                    }
                    break;
                case "pom":
                    allPackages = FileParser.parsePomFile(inputFilePath);
                    break;
                case "pypi":
                    allPackages = FileParser.parseRequirementsFile(inputFilePath);
                    break;
                case "gradle":
                    System.err.println("Input format 'gradle' is not yet implemented.");
                    return;
                default:
                    System.err.println("Unknown input format: " + inputFormat);
                    return;
            }

            if (allPackages.isEmpty()) {
                logger.error("No valid packages found in the input file");
                System.out.println("No valid packages found in the input file. Check format and try again.");
                return;
            }

            logger.info("Loaded {} packages from the input file", allPackages.size());
            System.out.println("Analyzing dependencies for " + allPackages.size() + " packages...");

            // Build dependency trees - currently assumes inputType="all"
            // TODO: Add support for inputType="roots" to fetch transitive dependencies
            graphBuilder = new DependencyGraphBuilder();
            List<DependencyNode> dependencyTree = graphBuilder.buildDependencyTrees(allPackages);
            Collection<Package> allTrackedPackages = graphBuilder.getAllPackages();
            int rootCount = dependencyTree.size();

            logger.info("Identified {} root packages", rootCount);

            PackageCache cache = PackageCache.getInstance();

            // Generate output based on output format
            String output = generateOutput(dependencyTree, allTrackedPackages, outputFormat, projectName, originalSbomContent);

            // Write output to file or stdout
            if ("-".equals(outputFilePath)) {
                System.out.println(output);
            } else {
                try (BufferedWriter writer = new BufferedWriter(new FileWriter(outputFilePath))) {
                    writer.write(output);
                    logger.info("Output written to: {}", outputFilePath);
                    System.out.println("Output written to: " + outputFilePath);
                }
            }

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
     * Print usage information
     */
    private static void printUsage() {
        System.out.println("Usage: deptrast <input-file> <output-file> [options]");
        System.out.println();
        System.out.println("Required:");
        System.out.println("  <input-file>              Input file path");
        System.out.println("  <output-file>             Output file path (use \"-\" for stdout)");
        System.out.println();
        System.out.println("Input Options:");
        System.out.println("  --iformat=<format>        Input format (default: auto)");
        System.out.println("                            auto, flat, pom, gradle, pypi, sbom");
        System.out.println("  --itype=<type>            Input type (default: smart)");
        System.out.println("                            all     - All dependencies (find roots)");
        System.out.println("                            roots   - Root dependencies (fetch transitive)");
        System.out.println();
        System.out.println("Output Options:");
        System.out.println("  --oformat=<format>        Output format (default: tree)");
        System.out.println("                            tree, maven, sbom");
        System.out.println("  --project-name=<name>     Project name for root node (tree/maven)");
        System.out.println();
        System.out.println("Other:");
        System.out.println("  --verbose, -v             Verbose logging");
        System.out.println();
        System.out.println("Examples:");
        System.out.println("  deptrast libraries.txt -");
        System.out.println("  deptrast libraries.txt output.sbom --oformat=sbom");
        System.out.println("  deptrast pom.xml - --iformat=pom --itype=roots");
    }

    /**
     * Detect input format based on file extension
     */
    private static String detectInputFormat(String filePath) {
        String lower = filePath.toLowerCase();
        if (lower.endsWith(".xml") || lower.endsWith("pom.xml")) {
            return "pom";
        } else if (lower.endsWith(".gradle") || lower.endsWith(".gradle.kts")) {
            return "gradle";
        } else if (lower.endsWith("requirements.txt")) {
            return "pypi";
        } else if (lower.endsWith(".json") && (lower.contains("sbom") || lower.contains("bom"))) {
            return "sbom";
        } else {
            return "flat";
        }
    }

    /**
     * Get smart default for input type based on format
     */
    private static String getSmartInputType(String inputFormat) {
        switch (inputFormat) {
            case "pom":
            case "gradle":
            case "pypi":
                return "roots";
            case "flat":
            case "sbom":
            default:
                return "all";
        }
    }

    /**
     * Validate input format
     */
    private static boolean isValidInputFormat(String format) {
        return "auto".equals(format) || "flat".equals(format) || "pom".equals(format) ||
               "gradle".equals(format) || "pypi".equals(format) || "sbom".equals(format);
    }

    /**
     * Validate input type
     */
    private static boolean isValidInputType(String type) {
        return "all".equals(type) || "roots".equals(type) || "smart".equals(type);
    }

    /**
     * Validate output format
     */
    private static boolean isValidOutputFormat(String format) {
        return "tree".equals(format) || "maven".equals(format) || "sbom".equals(format);
    }

    /**
     * Generate output based on format
     */
    private static String generateOutput(List<DependencyNode> dependencyTree,
                                         Collection<Package> allTrackedPackages,
                                         String outputFormat,
                                         String projectName,
                                         String originalSbomContent) {
        StringBuilder output = new StringBuilder();
        int rootCount = dependencyTree.size();

        if ("sbom".equals(outputFormat)) {
            // Generate SBOM JSON
            PackageCache cache = PackageCache.getInstance();
            // If we have original SBOM content, enhance it instead of creating new
            if (originalSbomContent != null) {
                return enhanceSbomWithDependencies(originalSbomContent, cache.getAllPackages());
            } else {
                return generateSbomString(cache.getAllPackages());
            }
        } else if ("maven".equals(outputFormat)) {
            // Generate Maven dependency:tree format
            return MavenDependencyTreeFormatter.formatMavenDependencyTree(projectName, dependencyTree);
        } else {
            // Generate tree format (default)
            output.append("Identified ").append(rootCount).append(" root dependencies:").append(NEW_LINE);
            for (DependencyNode rootNode : dependencyTree) {
                output.append("  ").append(rootNode.getPackage().getFullName()).append(NEW_LINE);
            }
            output.append(NEW_LINE).append("Dependency Tree:").append(NEW_LINE).append(NEW_LINE);

            // Add project root node for tree format
            DependencyNode projectRootNode = new DependencyNode(
                new Package("project", projectName, "1.0.0"), 0, false);
            for (DependencyNode node : new ArrayList<>(dependencyTree)) {
                projectRootNode.addChild(node);
            }

            output.append(projectRootNode.getTreeRepresentation());
            output.append(NEW_LINE).append("Dependency Statistics:").append(NEW_LINE);
            output.append("  Total Packages: ").append(allTrackedPackages.size()).append(NEW_LINE);
            output.append("  Root Packages: ").append(rootCount).append(NEW_LINE);

            return output.toString();
        }
    }

    /**
     * Enhance existing SBOM with dependencies section
     */
    private static String enhanceSbomWithDependencies(String originalSbom, Collection<Package> packages) {
        try {
            PackageCache cache = PackageCache.getInstance();

            // Parse original SBOM
            JsonObject sbom = JsonParser.parseString(originalSbom).getAsJsonObject();

            // Build purl lookup map from original components
            Map<Package, String> purlByPackage = new HashMap<>();
            JsonArray components = sbom.getAsJsonArray("components");

            if (components != null) {
                for (JsonElement element : components) {
                    JsonObject component = element.getAsJsonObject();
                    JsonElement purlElement = component.get("purl");

                    if (purlElement != null && !purlElement.isJsonNull()) {
                        String purl = purlElement.getAsString();
                        // Find matching package
                        for (Package pkg : packages) {
                            String expectedPurl = buildPurl(pkg);
                            if (purl.equals(expectedPurl)) {
                                purlByPackage.put(pkg, purl);
                                break;
                            }
                        }
                    }
                }
            }

            // Build dependencies array
            JsonArray dependenciesArray = new JsonArray();

            for (Package pkg : packages) {
                String pkgPurl = purlByPackage.get(pkg);
                if (pkgPurl == null) continue;

                JsonObject dependency = new JsonObject();
                dependency.addProperty("ref", pkgPurl);

                // Get direct dependencies from cache
                List<Package> directDeps = cache.getCachedDependencies(pkg);
                if (directDeps != null && !directDeps.isEmpty()) {
                    JsonArray dependsOn = new JsonArray();
                    for (Package depPkg : directDeps) {
                        if (purlByPackage.containsKey(depPkg)) {
                            dependsOn.add(purlByPackage.get(depPkg));
                        }
                    }
                    if (dependsOn.size() > 0) {
                        dependency.add("dependsOn", dependsOn);
                    }
                }

                dependenciesArray.add(dependency);
            }

            // Add or replace dependencies in SBOM
            sbom.add("dependencies", dependenciesArray);

            // Convert back to pretty-printed JSON
            com.google.gson.Gson gson = new com.google.gson.GsonBuilder().setPrettyPrinting().create();
            return gson.toJson(sbom);

        } catch (Exception e) {
            logger.error("Error enhancing SBOM: {}", e.getMessage(), e);
            return "Error enhancing SBOM: " + e.getMessage();
        }
    }

    /**
     * Build a purl string for a package
     */
    private static String buildPurl(Package pkg) {
        if ("maven".equalsIgnoreCase(pkg.getSystem())) {
            String name = pkg.getName().replace(':', '/');
            return "pkg:maven/" + name + "@" + pkg.getVersion();
        } else {
            return "pkg:" + pkg.getSystem().toLowerCase() + "/" + pkg.getName() + "@" + pkg.getVersion();
        }
    }

    /**
     * Generate SBOM as a string
     */
    private static String generateSbomString(Collection<Package> packages) {
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
            return generator.toJsonString(true);

        } catch (Exception e) {
            logger.error("Error generating SBOM: {}", e.getMessage(), e);
            return "Error generating SBOM: " + e.getMessage();
        }
    }

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
    
}