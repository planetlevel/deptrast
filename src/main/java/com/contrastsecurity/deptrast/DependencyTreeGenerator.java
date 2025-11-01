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
import org.cyclonedx.model.metadata.ToolInformation;
import org.cyclonedx.model.ExternalReference;
import org.cyclonedx.model.OrganizationalContact;
import org.cyclonedx.Version;

import java.io.InputStream;
import java.util.Properties;

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
        String outputFormat = "sbom";
        String outputType = "all";  // Default: output all dependencies
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
            } else if (arg.startsWith("--otype=")) {
                outputType = arg.substring(8).toLowerCase();
            } else if (arg.startsWith("--project-name=")) {
                projectName = arg.substring(15);
            } else if (arg.equals("--verbose") || arg.equals("-v")) {
                verbose = true;
            } else if (arg.startsWith("--loglevel=")) {
                String logLevel = arg.substring(11).toUpperCase();
                setLogLevel(logLevel);
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

        if (!isValidOutputType(outputType)) {
            System.err.println("Invalid output type: " + outputType);
            System.err.println("Valid types: all, roots");
            return;
        }

        try {
            // Set logging level based on verbose flag
            if (verbose) {
                setLoggingLevel(Level.INFO);
                logger.info("Verbose mode enabled");
                logger.info("Input: {} (format={}, type={})", inputFilePath, inputFormat, inputType);
                logger.info("Output: {} (format={}, type={})", outputFilePath, outputFormat, outputType);
            }

            // Parse packages from input file based on input format
            List<Package> allPackages;
            Map<String, String> dependencyManagement = null;
            Map<String, Set<String>> exclusions = null;
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
                    FileParser.PomParseResult pomResult = FileParser.parsePomFileWithManagement(inputFilePath);
                    allPackages = pomResult.getPackages();
                    dependencyManagement = pomResult.getDependencyManagement();
                    exclusions = pomResult.getExclusions();
                    logger.info("Parsed {} packages with {} managed versions and {} exclusions from pom.xml",
                        allPackages.size(), dependencyManagement.size(), exclusions.size());
                    break;
                case "pypi":
                    allPackages = FileParser.parseRequirementsFile(inputFilePath);
                    break;
                case "gradle":
                    allPackages = FileParser.parseGradleFile(inputFilePath);
                    break;
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

            // Apply dependency management if available (from POM files)
            if (dependencyManagement != null && !dependencyManagement.isEmpty()) {
                graphBuilder.setDependencyManagement(dependencyManagement);
                logger.info("Applied {} managed dependency versions to graph builder", dependencyManagement.size());
            }

            // Apply exclusions if available (from POM files)
            if (exclusions != null && !exclusions.isEmpty()) {
                graphBuilder.setExclusions(exclusions);
                logger.info("Applied {} exclusion rules to graph builder", exclusions.size());
            }

            List<DependencyNode> dependencyTree = graphBuilder.buildDependencyTrees(allPackages);

            // Get reconciled packages from the dependency tree (with managed versions applied)
            Collection<Package> allTrackedPackages = graphBuilder.getAllReconciledPackages();
            int rootCount = dependencyTree.size();

            logger.info("Identified {} root packages", rootCount);
            logger.info("Using {} reconciled packages for output", allTrackedPackages.size());

            // Generate output based on output format
            String output = generateOutput(dependencyTree, allTrackedPackages, outputFormat, outputType, projectName, originalSbomContent);

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
        System.out.println("  --oformat=<format>        Output format (default: sbom)");
        System.out.println("                            tree, maven, sbom");
        System.out.println("  --otype=<type>            Output type (default: all)");
        System.out.println("                            all     - All packages (roots + transitive)");
        System.out.println("                            roots   - Root packages only");
        System.out.println("  --project-name=<name>     Project name for root node (tree/maven)");
        System.out.println();
        System.out.println("Other:");
        System.out.println("  --verbose, -v             Verbose logging");
        System.out.println("  --loglevel=<level>        Set log level (TRACE, DEBUG, INFO, WARN, ERROR)");
        System.out.println();
        System.out.println("Examples:");
        System.out.println("  deptrast libraries.txt -");
        System.out.println("  deptrast libraries.txt output.sbom --oformat=sbom");
        System.out.println("  deptrast pom.xml - --iformat=pom --itype=roots");
        System.out.println("  deptrast pom.xml output.json --loglevel=INFO");
    }

    private static void setLogLevel(String level) {
        ch.qos.logback.classic.Logger root = (ch.qos.logback.classic.Logger)
            org.slf4j.LoggerFactory.getLogger(org.slf4j.Logger.ROOT_LOGGER_NAME);
        ch.qos.logback.classic.Level logbackLevel;

        switch (level) {
            case "TRACE":
                logbackLevel = ch.qos.logback.classic.Level.TRACE;
                break;
            case "DEBUG":
                logbackLevel = ch.qos.logback.classic.Level.DEBUG;
                break;
            case "INFO":
                logbackLevel = ch.qos.logback.classic.Level.INFO;
                break;
            case "WARN":
                logbackLevel = ch.qos.logback.classic.Level.WARN;
                break;
            case "ERROR":
                logbackLevel = ch.qos.logback.classic.Level.ERROR;
                break;
            default:
                System.err.println("Unknown log level: " + level + ". Using WARN.");
                logbackLevel = ch.qos.logback.classic.Level.WARN;
        }

        root.setLevel(logbackLevel);
        logger.info("Log level set to: {}", level);
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
        } else if (lower.endsWith(".sbom") || lower.endsWith(".cdx.json") ||
                   (lower.endsWith(".json") && (lower.contains("sbom") || lower.contains("bom") || lower.contains("cdx")))) {
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
     * Validate output type
     */
    private static boolean isValidOutputType(String type) {
        return "all".equals(type) || "roots".equals(type);
    }

    /**
     * Generate output based on format
     */
    private static String generateOutput(List<DependencyNode> dependencyTree,
                                         Collection<Package> allTrackedPackages,
                                         String outputFormat,
                                         String outputType,
                                         String projectName,
                                         String originalSbomContent) {
        StringBuilder output = new StringBuilder();
        int rootCount = dependencyTree.size();

        // Filter packages based on output type
        Collection<Package> packagesToOutput;
        if ("roots".equals(outputType)) {
            // Only output root packages (no transitive dependencies)
            packagesToOutput = new ArrayList<>();
            for (DependencyNode rootNode : dependencyTree) {
                packagesToOutput.add(rootNode.getPackage());
            }
            logger.info("Output type is 'roots': outputting {} root packages only", packagesToOutput.size());
        } else {
            // Output all packages
            packagesToOutput = allTrackedPackages;
        }

        if ("sbom".equals(outputFormat)) {
            // Generate SBOM JSON
            // If we have original SBOM content, enhance it instead of creating new
            if (originalSbomContent != null) {
                return enhanceSbomWithDependencies(originalSbomContent, packagesToOutput, dependencyTree);
            } else {
                return generateSbomString(packagesToOutput, dependencyTree);
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
     * Build a map of Package -> direct dependencies from the dependency tree
     */
    private static Map<Package, List<Package>> buildDependencyMap(List<DependencyNode> trees) {
        Map<Package, List<Package>> dependencyMap = new HashMap<>();

        for (DependencyNode tree : trees) {
            collectDependenciesFromTree(tree, dependencyMap);
        }

        return dependencyMap;
    }

    /**
     * Recursively collect dependency relationships from tree
     */
    private static void collectDependenciesFromTree(DependencyNode node, Map<Package, List<Package>> dependencyMap) {
        if (node == null) {
            return;
        }

        Package pkg = node.getPackage();
        List<Package> children = new ArrayList<>();

        for (DependencyNode child : node.getChildren()) {
            children.add(child.getPackage());
            // Recurse into children
            collectDependenciesFromTree(child, dependencyMap);
        }

        // Store this package's direct dependencies
        dependencyMap.put(pkg, children);
    }

    /**
     * Enhance existing SBOM with dependencies section
     */
    private static String enhanceSbomWithDependencies(String originalSbom, Collection<Package> packages, List<DependencyNode> trees) {
        try {
            // Build dependency map from tree structure
            Map<Package, List<Package>> dependencyMap = buildDependencyMap(trees);

            // Parse original SBOM
            JsonObject sbom = JsonParser.parseString(originalSbom).getAsJsonObject();

            // Build purl lookup map from original components
            // Use bom-ref if present, otherwise use purl
            Map<Package, String> purlByPackage = new HashMap<>();
            Map<Package, String> bomRefByPackage = new HashMap<>();
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

                                // Check if component has bom-ref, use it if present
                                JsonElement bomRefElement = component.get("bom-ref");
                                if (bomRefElement != null && !bomRefElement.isJsonNull()) {
                                    bomRefByPackage.put(pkg, bomRefElement.getAsString());
                                } else {
                                    // If no bom-ref, add it to the component
                                    component.addProperty("bom-ref", purl);
                                    bomRefByPackage.put(pkg, purl);
                                }
                                break;
                            }
                        }
                    }
                }
            }

            // Build dependencies array using bom-refs
            JsonArray dependenciesArray = new JsonArray();

            for (Package pkg : packages) {
                String pkgBomRef = bomRefByPackage.get(pkg);
                if (pkgBomRef == null) continue;

                JsonObject dependency = new JsonObject();
                dependency.addProperty("ref", pkgBomRef);

                // Get direct dependencies from dependency map
                List<Package> directDeps = dependencyMap.get(pkg);
                if (directDeps != null && !directDeps.isEmpty()) {
                    JsonArray dependsOn = new JsonArray();
                    for (Package depPkg : directDeps) {
                        String depBomRef = bomRefByPackage.get(depPkg);
                        if (depBomRef != null) {
                            dependsOn.add(depBomRef);
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
    private static String generateSbomString(Collection<Package> packages, List<DependencyNode> trees) {
        try {
            // Build dependency map from tree structure
            Map<Package, List<Package>> dependencyMap = buildDependencyMap(trees);

            // Create a new BOM
            Bom bom = new Bom();
            bom.setSerialNumber("urn:uuid:" + UUID.randomUUID());

            Metadata metadata = new Metadata();
            metadata.setTimestamp(new Date());

            // Create tool component using modern CycloneDX 1.6 format
            Component toolComponent = new Component();
            toolComponent.setGroup("com.contrastsecurity");
            toolComponent.setName("deptrast");
            toolComponent.setVersion(getVersion());
            toolComponent.setType(Component.Type.APPLICATION);

            String toolPurl = "pkg:maven/com.contrastsecurity/deptrast@" + getVersion();
            toolComponent.setPurl(toolPurl);
            toolComponent.setBomRef(toolPurl);
            toolComponent.setPublisher("Contrast Security");

            // Add author
            OrganizationalContact author = new OrganizationalContact();
            author.setName("Jeff Williams");
            List<OrganizationalContact> authors = new ArrayList<>();
            authors.add(author);
            toolComponent.setAuthors(authors);

            // Add GitHub repository reference
            ExternalReference vcsRef = new ExternalReference();
            vcsRef.setType(ExternalReference.Type.VCS);
            vcsRef.setUrl("https://github.com/planetlevel/deptrast");
            List<ExternalReference> externalRefs = new ArrayList<>();
            externalRefs.add(vcsRef);
            toolComponent.setExternalReferences(externalRefs);

            // Set tool component in ToolInformation
            ToolInformation toolInfo = new ToolInformation();
            List<Component> toolComponents = new ArrayList<>();
            toolComponents.add(toolComponent);
            toolInfo.setComponents(toolComponents);

            metadata.setToolChoice(toolInfo);
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
                component.setBomRef(purl);  // Use PURL as bom-ref for consistent referencing
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

                // Get direct dependencies from dependency map
                List<Package> directDeps = dependencyMap.get(pkg);
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
     * Get the version from pom.xml properties file
     */
    private static String getVersion() {
        try {
            Properties props = new Properties();
            try (InputStream is = DependencyTreeGenerator.class.getResourceAsStream("/META-INF/maven/com.contrastsecurity/deptrast/pom.properties")) {
                if (is != null) {
                    props.load(is);
                    return props.getProperty("version", "2.0.3");
                }
            }
        } catch (Exception e) {
            logger.debug("Could not read version from pom.properties: {}", e.getMessage());
        }
        // Fallback to hardcoded version
        return "2.0.3";
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