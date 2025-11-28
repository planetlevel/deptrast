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
import java.util.HashSet;
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

        if (args.length < 1) {
            printUsage();
            return;
        }

        String subcommand = args[0].toLowerCase();

        // Dispatch to appropriate subcommand handler
        try {
            switch (subcommand) {
                case "create":
                    handleCreate(args);
                    break;
                case "enrich":
                    handleEnrich(args);
                    break;
                case "print":
                    handlePrint(args);
                    break;
                case "stats":
                    handleStats(args);
                    break;
                case "compare":
                    handleCompare(args);
                    break;
                case "validate":
                    handleValidate(args);
                    break;
                case "--help":
                case "-h":
                case "help":
                    printUsage();
                    break;
                default:
                    System.err.println("Unknown subcommand: " + subcommand);
                    System.err.println("Run 'deptrast help' for usage information");
                    return;
            }
        } catch (Exception e) {
            logger.error("Error executing {}: {}", subcommand, e.getMessage(), e);
            System.err.println("Error: " + e.getMessage());
            return;
        } finally {
            cleanupResources();
        }
    }

    /**
     * Handle 'create' subcommand
     */
    private static void handleCreate(String[] args) throws Exception {
        if (args.length < 3) {
            System.err.println("Usage: deptrast create <input-file> <output-file> [options]");
            return;
        }

        String inputFilePath = args[1];
        String outputFilePath = args[2];

        // Parse options
        String inputType = "smart";  // roots or list
        String outputFormat = "sbom"; // sbom, roots, tree, list
        String treeFormat = "tree";   // tree or maven (for tree output)
        String projectName = "project";
        boolean verbose = false;
        boolean useExistingDeps = false;  // Use existing dependency graph from SBOM

        // Parse additional arguments
        for (int i = 3; i < args.length; i++) {
            String arg = args[i];

            if (arg.startsWith("--input=")) {
                inputType = arg.substring(8).toLowerCase();
            } else if (arg.startsWith("--output=")) {
                outputFormat = arg.substring(9).toLowerCase();
            } else if (arg.startsWith("--format=")) {
                treeFormat = arg.substring(9).toLowerCase();
            } else if (arg.startsWith("--project-name=")) {
                projectName = arg.substring(15);
            } else if (arg.equals("--verbose") || arg.equals("-v")) {
                verbose = true;
            } else if (arg.startsWith("--loglevel=")) {
                String logLevel = arg.substring(11).toUpperCase();
                setLogLevel(logLevel);
            } else if (arg.equals("--use-existing-deps")) {
                useExistingDeps = true;
            } else if (arg.equals("--rebuild-deps")) {
                useExistingDeps = false;
            } else {
                System.err.println("Unknown argument: " + arg + ". Ignoring.");
            }
        }

        // Validate input type
        if (!inputType.equals("roots") && !inputType.equals("list") && !inputType.equals("smart")) {
            System.err.println("Invalid --input value: " + inputType);
            System.err.println("Valid values: roots, list");
            return;
        }

        // Validate output format
        if (!outputFormat.equals("sbom") && !outputFormat.equals("roots") &&
            !outputFormat.equals("tree") && !outputFormat.equals("list")) {
            System.err.println("Invalid --output value: " + outputFormat);
            System.err.println("Valid values: sbom, roots, tree, list");
            return;
        }

        // Auto-detect input file format
        String detectedFormat = detectInputFormat(inputFilePath);

        // Smart input type detection: infer based on detected format
        if ("smart".equals(inputType)) {
            inputType = getSmartInputType(detectedFormat);
        }

        // Set logging level based on verbose flag
        if (verbose) {
            setLoggingLevel(Level.INFO);
            logger.info("Verbose mode enabled");
            logger.info("Input: {} (format={}, type={})", inputFilePath, detectedFormat, inputType);
            logger.info("Output: {} (format={})", outputFilePath, outputFormat);
        }

        // Parse packages from input file based on detected format
        List<Package> allPackages;
        Map<String, String> dependencyManagement = null;
        Map<String, Set<String>> exclusions = null;
        String originalSbomContent = null; // Store original SBOM if input is SBOM

        switch (detectedFormat) {
            case "flat":
                allPackages = FileParser.parsePackagesFromFile(inputFilePath);
                break;
            case "sbom":
                allPackages = FileParser.parseSbomFile(inputFilePath);
                // Read original SBOM content for potential fast mode usage
                try {
                    originalSbomContent = new String(java.nio.file.Files.readAllBytes(
                        java.nio.file.Paths.get(inputFilePath)));
                } catch (IOException e) {
                    logger.warn("Could not read original SBOM content: {}", e.getMessage());
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
                System.err.println("Unknown input format: " + detectedFormat);
                return;
        }

        if (allPackages.isEmpty()) {
            logger.error("No valid packages found in the input file");
            System.out.println("No valid packages found in the input file. Check format and try again.");
            return;
        }

        logger.info("Loaded {} packages from the input file", allPackages.size());

        List<DependencyNode> dependencyTree;
        Collection<Package> allTrackedPackages;
        int rootCount;

        // Check if we should use existing dependency graph or rebuild it
        if (useExistingDeps && "sbom".equals(detectedFormat) && originalSbomContent != null) {
            logger.info("Using existing dependency graph from SBOM (fast mode)");

            // Parse the existing dependency graph from the SBOM
            dependencyTree = parseDependencyGraphFromSbom(originalSbomContent, allPackages);
            allTrackedPackages = allPackages;
            rootCount = dependencyTree.size();

            logger.info("Using existing dependency graph with {} root packages", rootCount);
        } else {
            // Build dependency trees from scratch using API
            logger.info("Analyzing dependencies for {} packages...", allPackages.size());

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

            dependencyTree = graphBuilder.buildDependencyTrees(allPackages);

            // Get reconciled packages from the dependency tree (with managed versions applied)
            allTrackedPackages = graphBuilder.getAllReconciledPackages();
            rootCount = dependencyTree.size();
        }

        logger.info("Identified {} root packages", rootCount);
        logger.info("Using {} reconciled packages for output", allTrackedPackages.size());

        // Generate output based on output format
        String output;

        if ("list".equals(outputFormat)) {
            // Simple flat list format: one package per line
            output = generateListOutput(allTrackedPackages);
        } else if ("roots".equals(outputFormat)) {
            // SBOM with only root packages
            Collection<Package> rootPackages = new ArrayList<>();
            for (DependencyNode node : dependencyTree) {
                rootPackages.add(node.getPackage());
            }
            output = generateSbomString(rootPackages, dependencyTree);
        } else if ("tree".equals(outputFormat)) {
            // Tree visualization
            if ("maven".equals(treeFormat)) {
                output = MavenDependencyTreeFormatter.formatMavenDependencyTree(projectName, dependencyTree);
            } else {
                output = generateTreeOutput(dependencyTree, allTrackedPackages, projectName);
            }
        } else {
            // Default: full SBOM
            if (originalSbomContent != null) {
                output = enhanceSbomWithDependencies(originalSbomContent, allTrackedPackages, dependencyTree);
            } else {
                output = generateSbomString(allTrackedPackages, dependencyTree);
            }
        }

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
    }

    /**
     * Handle 'enrich' subcommand
     */
    private static void handleEnrich(String[] args) throws Exception {
        if (args.length < 3) {
            System.err.println("Usage: deptrast enrich <input-sbom> <output-sbom> [options]");
            System.err.println();
            System.err.println("Enriches an existing SBOM by adding dependency relationships.");
            return;
        }

        // Delegate to create with SBOM input/output
        String[] createArgs = new String[args.length];
        createArgs[0] = "create";
        System.arraycopy(args, 1, createArgs, 1, args.length - 1);
        handleCreate(createArgs);
    }

    /**
     * Handle 'print' subcommand
     */
    private static void handlePrint(String[] args) throws Exception {
        if (args.length < 2) {
            System.err.println("Usage: deptrast print <input-sbom> [options]");
            System.err.println();
            System.err.println("Options:");
            System.err.println("  --output=tree|list|roots   Output format (default: tree)");
            System.err.println("  --format=tree|maven        Tree visualization format (default: tree)");
            System.err.println("  --project-name=NAME        Project name for tree output");
            System.err.println("  --use-existing-deps        Use existing dependency graph (default, fast)");
            System.err.println("  --rebuild-deps             Rebuild dependency graph from scratch");
            System.err.println("  --verbose, -v              Verbose logging");
            System.err.println("  --loglevel=LEVEL           Set log level (TRACE, DEBUG, INFO, WARN, ERROR)");
            return;
        }

        String inputFilePath = args[1];
        String outputFormat = "tree"; // tree, list, roots
        String treeFormat = "tree";   // tree or maven
        String projectName = "project";
        boolean useExistingDeps = true; // Default to fast mode for print
        boolean verbose = false;
        String logLevel = null;

        // Parse additional arguments
        for (int i = 2; i < args.length; i++) {
            String arg = args[i];

            if (arg.startsWith("--output=")) {
                outputFormat = arg.substring(9).toLowerCase();
            } else if (arg.startsWith("--format=")) {
                treeFormat = arg.substring(9).toLowerCase();
            } else if (arg.startsWith("--project-name=")) {
                projectName = arg.substring(15);
            } else if (arg.equals("--use-existing-deps")) {
                useExistingDeps = true;
            } else if (arg.equals("--rebuild-deps")) {
                useExistingDeps = false;
            } else if (arg.equals("--verbose") || arg.equals("-v")) {
                verbose = true;
            } else if (arg.startsWith("--loglevel=")) {
                logLevel = arg.substring(11);
            } else {
                System.err.println("Unknown argument: " + arg + ". Ignoring.");
            }
        }

        // Delegate to create with stdout output
        List<String> createArgs = new ArrayList<>();
        createArgs.add("create");
        createArgs.add(inputFilePath);
        createArgs.add("-"); // stdout
        createArgs.add("--output=" + outputFormat);
        if ("tree".equals(outputFormat)) {
            createArgs.add("--format=" + treeFormat);
        }
        createArgs.add("--project-name=" + projectName);

        // Add dependency mode flag
        if (useExistingDeps) {
            createArgs.add("--use-existing-deps");
        } else {
            createArgs.add("--rebuild-deps");
        }

        // Add logging flags
        if (verbose) {
            createArgs.add("--verbose");
        }
        if (logLevel != null) {
            createArgs.add("--loglevel=" + logLevel);
        }

        handleCreate(createArgs.toArray(new String[0]));
    }

    /**
     * Handle 'stats' subcommand
     */
    private static void handleStats(String[] args) throws Exception {
        if (args.length < 2) {
            System.err.println("Usage: deptrast stats <input-sbom>");
            return;
        }

        String inputFilePath = args[1];

        // Parse SBOM
        List<Package> allPackages = FileParser.parseSbomFile(inputFilePath);

        // Build dependency trees to get root count
        graphBuilder = new DependencyGraphBuilder();
        List<DependencyNode> dependencyTree = graphBuilder.buildDependencyTrees(allPackages);
        Collection<Package> allTrackedPackages = graphBuilder.getAllReconciledPackages();

        System.out.println("SBOM Statistics:");
        System.out.println("  Total Packages: " + allTrackedPackages.size());
        System.out.println("  Root Packages: " + dependencyTree.size());
        System.out.println("  Transitive Packages: " + (allTrackedPackages.size() - dependencyTree.size()));
    }

    /**
     * Normalize a purl by removing qualifiers (everything after ?)
     */
    private static String normalizePurl(String purl) {
        int qualifierIndex = purl.indexOf('?');
        if (qualifierIndex > 0) {
            return purl.substring(0, qualifierIndex);
        }
        return purl;
    }

    /**
     * Parse existing dependency graph from SBOM
     */
    private static List<DependencyNode> parseDependencyGraphFromSbom(String sbomContent, List<Package> allPackages) {
        try {
            JsonObject sbom = JsonParser.parseString(sbomContent).getAsJsonObject();

            // Build a map of purl -> Package for quick lookup
            Map<String, Package> purlToPackage = new HashMap<>();
            for (Package pkg : allPackages) {
                String purl = normalizePurl(buildPurl(pkg));
                purlToPackage.put(purl, pkg);
            }

            // Build a map of bom-ref -> Package
            Map<String, Package> bomRefToPackage = new HashMap<>();
            if (sbom.has("components")) {
                JsonArray components = sbom.getAsJsonArray("components");
                for (JsonElement elem : components) {
                    JsonObject component = elem.getAsJsonObject();
                    if (component.has("bom-ref") && component.has("purl")) {
                        String bomRef = component.get("bom-ref").getAsString();
                        String purl = normalizePurl(component.get("purl").getAsString());
                        Package pkg = purlToPackage.get(purl);
                        if (pkg != null) {
                            bomRefToPackage.put(bomRef, pkg);
                        }
                    }
                }
            }

            // Parse dependencies array
            Map<String, List<String>> depGraph = new HashMap<>();
            if (sbom.has("dependencies")) {
                JsonArray dependencies = sbom.getAsJsonArray("dependencies");
                for (JsonElement elem : dependencies) {
                    JsonObject dep = elem.getAsJsonObject();
                    if (dep.has("ref")) {
                        String ref = dep.get("ref").getAsString();
                        List<String> deps = new ArrayList<>();
                        if (dep.has("dependsOn")) {
                            JsonArray dependsOn = dep.getAsJsonArray("dependsOn");
                            for (JsonElement depElem : dependsOn) {
                                deps.add(depElem.getAsString());
                            }
                        }
                        depGraph.put(ref, deps);
                    }
                }
            }

            // Build DependencyNode tree structure
            // Find root nodes (nodes that are not dependencies of any other node)
            Set<String> allRefs = new HashSet<>(depGraph.keySet());
            Set<String> nonRootRefs = new HashSet<>();
            for (List<String> deps : depGraph.values()) {
                nonRootRefs.addAll(deps);
            }
            Set<String> rootRefs = new HashSet<>(allRefs);
            rootRefs.removeAll(nonRootRefs);

            // Build tree from roots
            List<DependencyNode> trees = new ArrayList<>();
            Map<String, DependencyNode> refToNode = new HashMap<>();

            for (String rootRef : rootRefs) {
                Package pkg = bomRefToPackage.get(rootRef);
                if (pkg != null) {
                    DependencyNode rootNode = buildDependencyNode(rootRef, depGraph, bomRefToPackage, refToNode, 0);
                    if (rootNode != null) {
                        trees.add(rootNode);
                    }
                } else {
                    // Root ref not in components (likely project/metadata reference)
                    // Treat its direct dependencies as the actual roots
                    logger.debug("Root ref not in components: {}. Using its dependencies as roots.", rootRef);
                    List<String> childRefs = depGraph.get(rootRef);
                    if (childRefs != null) {
                        for (String childRef : childRefs) {
                            Package childPkg = bomRefToPackage.get(childRef);
                            if (childPkg != null) {
                                DependencyNode childNode = buildDependencyNode(childRef, depGraph, bomRefToPackage, refToNode, 0);
                                if (childNode != null) {
                                    trees.add(childNode);
                                }
                            }
                        }
                    }
                }
            }

            return trees;

        } catch (Exception e) {
            logger.error("Error parsing dependency graph from SBOM: {}", e.getMessage(), e);
            return new ArrayList<>();
        }
    }

    /**
     * Recursively build DependencyNode from SBOM dependency graph
     */
    private static DependencyNode buildDependencyNode(String ref,
                                                       Map<String, List<String>> depGraph,
                                                       Map<String, Package> bomRefToPackage,
                                                       Map<String, DependencyNode> refToNode,
                                                       int depth) {
        // Check if already built (handle cycles)
        if (refToNode.containsKey(ref)) {
            return refToNode.get(ref);
        }

        Package pkg = bomRefToPackage.get(ref);
        if (pkg == null) {
            return null;
        }

        DependencyNode node = new DependencyNode(pkg, depth, false);
        refToNode.put(ref, node);

        // Add children
        List<String> childRefs = depGraph.get(ref);
        if (childRefs != null) {
            for (String childRef : childRefs) {
                DependencyNode childNode = buildDependencyNode(childRef, depGraph, bomRefToPackage, refToNode, depth + 1);
                if (childNode != null) {
                    node.addChild(childNode);
                }
            }
        }

        return node;
    }

    /**
     * Extract package name without version from a purl
     */
    private static String getPackageNameFromPurl(String purl) {
        // Remove qualifiers first
        String normalized = normalizePurl(purl);
        // Remove version (everything after last @)
        int versionIndex = normalized.lastIndexOf('@');
        if (versionIndex > 0) {
            return normalized.substring(0, versionIndex);
        }
        return normalized;
    }

    /**
     * Handle 'compare' subcommand
     */
    private static void handleCompare(String[] args) throws Exception {
        if (args.length < 3) {
            System.err.println("Usage: deptrast compare <sbom1> <sbom2>");
            System.err.println();
            System.err.println("Compares two SBOMs and shows differences.");
            return;
        }

        String sbom1Path = args[1];
        String sbom2Path = args[2];

        List<Package> packages1 = FileParser.parseSbomFile(sbom1Path);
        List<Package> packages2 = FileParser.parseSbomFile(sbom2Path);

        // Build maps for comparison
        Map<String, String> purls1Map = packages1.stream()
            .collect(Collectors.toMap(
                pkg -> normalizePurl(buildPurl(pkg)),
                pkg -> normalizePurl(buildPurl(pkg))
            ));
        Map<String, String> purls2Map = packages2.stream()
            .collect(Collectors.toMap(
                pkg -> normalizePurl(buildPurl(pkg)),
                pkg -> normalizePurl(buildPurl(pkg))
            ));

        // Build package name -> full purl maps for version comparison
        Map<String, String> packageNames1 = new HashMap<>();
        Map<String, String> packageNames2 = new HashMap<>();

        for (String purl : purls1Map.values()) {
            packageNames1.put(getPackageNameFromPurl(purl), purl);
        }
        for (String purl : purls2Map.values()) {
            packageNames2.put(getPackageNameFromPurl(purl), purl);
        }

        Set<String> purls1 = new HashSet<>(purls1Map.values());
        Set<String> purls2 = new HashSet<>(purls2Map.values());

        // Find exact matches
        Set<String> inBoth = new HashSet<>(purls1);
        inBoth.retainAll(purls2);

        // Find packages only in one or the other
        Set<String> onlyIn1 = new HashSet<>(purls1);
        onlyIn1.removeAll(purls2);

        Set<String> onlyIn2 = new HashSet<>(purls2);
        onlyIn2.removeAll(purls1);

        // Find version differences (same package name, different version)
        Map<String, String[]> versionDiffs = new HashMap<>();
        Set<String> processedNames = new HashSet<>();

        for (String purl1 : onlyIn1) {
            String packageName = getPackageNameFromPurl(purl1);
            if (packageNames2.containsKey(packageName)) {
                String purl2 = packageNames2.get(packageName);
                versionDiffs.put(packageName, new String[]{purl1, purl2});
                processedNames.add(packageName);
            }
        }

        // Remove version diffs from the "only in" sets
        onlyIn1.removeIf(purl -> processedNames.contains(getPackageNameFromPurl(purl)));
        onlyIn2.removeIf(purl -> processedNames.contains(getPackageNameFromPurl(purl)));

        System.out.println("SBOM Comparison:");
        System.out.println("  " + sbom1Path + ": " + packages1.size() + " components");
        System.out.println("  " + sbom2Path + ": " + packages2.size() + " components");
        System.out.println();
        System.out.println("  Same version: " + inBoth.size());
        System.out.println("  Version differences: " + versionDiffs.size());
        System.out.println("  Only in " + sbom1Path + ": " + onlyIn1.size());
        System.out.println("  Only in " + sbom2Path + ": " + onlyIn2.size());

        if (!versionDiffs.isEmpty()) {
            System.out.println();
            System.out.println("Version differences:");
            versionDiffs.entrySet().stream()
                .limit(10)
                .forEach(entry -> {
                    String[] purls = entry.getValue();
                    System.out.println("  - " + entry.getKey());
                    System.out.println("    " + sbom1Path + ": " + purls[0].substring(purls[0].lastIndexOf('@') + 1));
                    System.out.println("    " + sbom2Path + ": " + purls[1].substring(purls[1].lastIndexOf('@') + 1));
                });
            if (versionDiffs.size() > 10) {
                System.out.println("  ... and " + (versionDiffs.size() - 10) + " more");
            }
        }

        if (!onlyIn1.isEmpty()) {
            System.out.println();
            System.out.println("Components only in " + sbom1Path + ":");
            onlyIn1.stream().limit(10).forEach(purl -> System.out.println("  - " + purl));
            if (onlyIn1.size() > 10) {
                System.out.println("  ... and " + (onlyIn1.size() - 10) + " more");
            }
        }

        if (!onlyIn2.isEmpty()) {
            System.out.println();
            System.out.println("Components only in " + sbom2Path + ":");
            onlyIn2.stream().limit(10).forEach(purl -> System.out.println("  - " + purl));
            if (onlyIn2.size() > 10) {
                System.out.println("  ... and " + (onlyIn2.size() - 10) + " more");
            }
        }
    }

    /**
     * Handle 'validate' subcommand
     */
    private static void handleValidate(String[] args) throws Exception {
        if (args.length < 2) {
            System.err.println("Usage: deptrast validate <input-sbom>");
            return;
        }

        String inputFilePath = args[1];

        // Read and parse SBOM
        String content = new String(java.nio.file.Files.readAllBytes(java.nio.file.Paths.get(inputFilePath)));
        JsonObject sbom = JsonParser.parseString(content).getAsJsonObject();

        boolean valid = true;
        List<String> errors = new ArrayList<>();
        List<String> warnings = new ArrayList<>();
        List<String> checks = new ArrayList<>();

        // Check required fields
        if (!sbom.has("bomFormat")) {
            errors.add("Missing required field: bomFormat");
            valid = false;
        } else {
            checks.add("bomFormat: " + sbom.get("bomFormat").getAsString());
        }

        if (!sbom.has("specVersion")) {
            errors.add("Missing required field: specVersion");
            valid = false;
        } else {
            checks.add("specVersion: " + sbom.get("specVersion").getAsString());
        }

        if (!sbom.has("components")) {
            errors.add("Missing required field: components");
            valid = false;
        }

        // Check optional metadata
        if (sbom.has("metadata")) {
            JsonObject metadata = sbom.getAsJsonObject("metadata");
            if (metadata.has("timestamp")) {
                checks.add("metadata.timestamp: " + metadata.get("timestamp").getAsString());
            }
            if (metadata.has("tools")) {
                checks.add("metadata.tools: present");
            }
        }

        // Check serialNumber
        if (sbom.has("serialNumber")) {
            checks.add("serialNumber: present (URN format)");
        }

        // Check components
        int componentCount = 0;
        int withPurl = 0;
        int withBomRef = 0;
        int withVersion = 0;

        if (sbom.has("components")) {
            JsonArray components = sbom.getAsJsonArray("components");
            componentCount = components.size();

            for (JsonElement elem : components) {
                JsonObject component = elem.getAsJsonObject();
                if (component.has("purl") && !component.get("purl").isJsonNull()) {
                    withPurl++;
                }
                if (component.has("bom-ref") && !component.get("bom-ref").isJsonNull()) {
                    withBomRef++;
                }
                if (component.has("version") && !component.get("version").isJsonNull()) {
                    withVersion++;
                }
            }

            checks.add("components: " + componentCount + " total");
            checks.add("components with PURL: " + withPurl + " (" +
                      (componentCount > 0 ? (withPurl * 100 / componentCount) : 0) + "%)");
            checks.add("components with bom-ref: " + withBomRef + " (" +
                      (componentCount > 0 ? (withBomRef * 100 / componentCount) : 0) + "%)");
            checks.add("components with version: " + withVersion + " (" +
                      (componentCount > 0 ? (withVersion * 100 / componentCount) : 0) + "%)");

            int missingPurl = componentCount - withPurl;
            int missingBomRef = componentCount - withBomRef;

            if (missingPurl > 0) {
                warnings.add(missingPurl + " component(s) missing PURL");
            }
            if (missingBomRef > 0) {
                warnings.add(missingBomRef + " component(s) missing bom-ref");
            }
        }

        // Check dependencies
        int depCount = 0;
        int depsWithDependsOn = 0;

        if (!sbom.has("dependencies")) {
            warnings.add("No dependencies array (SBOM lacks dependency graph)");
        } else {
            JsonArray dependencies = sbom.getAsJsonArray("dependencies");
            depCount = dependencies.size();

            for (JsonElement elem : dependencies) {
                JsonObject dep = elem.getAsJsonObject();
                if (dep.has("dependsOn") && dep.getAsJsonArray("dependsOn").size() > 0) {
                    depsWithDependsOn++;
                }
            }

            checks.add("dependencies: " + depCount + " entries");
            checks.add("dependencies with dependsOn: " + depsWithDependsOn);

            if (depCount == 0) {
                warnings.add("Dependencies array is empty");
            }
        }

        // Print results
        System.out.println("SBOM Validation Results:");
        System.out.println("  File: " + inputFilePath);
        System.out.println();

        // Show what was checked
        System.out.println("Validation Checks:");
        for (String check : checks) {
            System.out.println("  ✓ " + check);
        }

        if (!errors.isEmpty() || !warnings.isEmpty()) {
            if (!errors.isEmpty()) {
                System.out.println();
                System.out.println("Errors:");
                errors.forEach(err -> System.out.println("  ✗ " + err));
            }
            if (!warnings.isEmpty()) {
                System.out.println();
                System.out.println("Warnings:");
                warnings.forEach(warn -> System.out.println("  ⚠ " + warn));
            }
        }

        System.out.println();
        if (valid && warnings.isEmpty()) {
            System.out.println("Result: ✓ Valid CycloneDX SBOM with no issues");
        } else if (valid) {
            System.out.println("Result: ✓ Valid CycloneDX SBOM with " + warnings.size() + " warning(s)");
        } else {
            System.out.println("Result: ✗ Invalid SBOM - " + errors.size() + " error(s)");
        }

        if (!valid) {
            return;
        }
    }

    /**
     * Generate simple list output format
     */
    private static String generateListOutput(Collection<Package> packages) {
        StringBuilder output = new StringBuilder();
        for (Package pkg : packages) {
            output.append(pkg.getFullName()).append(NEW_LINE);
        }
        return output.toString();
    }

    /**
     * Generate tree output format
     */
    private static String generateTreeOutput(List<DependencyNode> dependencyTree,
                                             Collection<Package> allTrackedPackages,
                                             String projectName) {
        StringBuilder output = new StringBuilder();
        output.append("Dependency Tree:").append(NEW_LINE).append(NEW_LINE);

        // Add project root node for tree format
        DependencyNode projectRootNode = new DependencyNode(
            new Package("project", projectName, "1.0.0"), 0, false);
        for (DependencyNode node : new ArrayList<>(dependencyTree)) {
            projectRootNode.addChild(node);
        }

        output.append(projectRootNode.getTreeRepresentation());
        output.append(NEW_LINE).append("Dependency Statistics:").append(NEW_LINE);
        output.append("  Total Packages: ").append(allTrackedPackages.size()).append(NEW_LINE);
        output.append("  Root Packages: ").append(dependencyTree.size()).append(NEW_LINE);

        return output.toString();
    }

    /**
     * Print usage information
     */
    private static void printUsage() {
        System.out.println("Usage: deptrast <subcommand> [args...] [options]");
        System.out.println();
        System.out.println("Subcommands:");
        System.out.println("  create <input> <output>   Create SBOM or other formats from source files");
        System.out.println("  enrich <sbom> <output>    Add dependency graph to existing SBOM");
        System.out.println("  print <sbom>              Display SBOM in different formats");
        System.out.println("  stats <sbom>              Show statistics about SBOM");
        System.out.println("  compare <sbom1> <sbom2>   Compare two SBOMs");
        System.out.println("  validate <sbom>           Validate SBOM structure");
        System.out.println("  help                      Show this help message");
        System.out.println();
        System.out.println("Create Options:");
        System.out.println("  --input=roots|list        Input type (default: auto-detected)");
        System.out.println("                            roots - Root packages (fetch transitives)");
        System.out.println("                            list  - Complete flat list (find roots)");
        System.out.println("  --output=sbom|roots|tree|list  Output format (default: sbom)");
        System.out.println("                            sbom  - Full CycloneDX SBOM (JSON)");
        System.out.println("                            roots - SBOM with only root packages");
        System.out.println("                            tree  - Tree visualization (text)");
        System.out.println("                            list  - Flat list (one per line)");
        System.out.println("  --format=tree|maven       Tree format (default: tree)");
        System.out.println("  --project-name=<name>     Project name for tree output");
        System.out.println("  --use-existing-deps       Use existing dependency graph from SBOM (fast)");
        System.out.println("                            Skips API calls, ideal for format conversions");
        System.out.println("  --rebuild-deps            Rebuild dependency graph from scratch (default)");
        System.out.println("                            Makes API calls, ensures accuracy");
        System.out.println("  --verbose, -v             Verbose logging");
        System.out.println("  --loglevel=<level>        Log level (TRACE, DEBUG, INFO, WARN, ERROR)");
        System.out.println();
        System.out.println("Examples:");
        System.out.println("  # Create SBOM from pom.xml");
        System.out.println("  deptrast create pom.xml output.sbom");
        System.out.println();
        System.out.println("  # Create flat list from pom.xml");
        System.out.println("  deptrast create pom.xml output.txt --output=list");
        System.out.println();
        System.out.println("  # Create tree visualization from flat list");
        System.out.println("  deptrast create libraries.txt - --output=tree");
        System.out.println();
        System.out.println("  # Enrich existing SBOM with dependency graph");
        System.out.println("  deptrast enrich input.sbom output.sbom");
        System.out.println();
        System.out.println("  # Print SBOM as tree");
        System.out.println("  deptrast print input.sbom --output=tree");
        System.out.println();
        System.out.println("  # Compare two SBOMs");
        System.out.println("  deptrast compare sbom1.json sbom2.json");
        System.out.println();
        System.out.println("  # Validate SBOM structure");
        System.out.println("  deptrast validate input.sbom");
        System.out.println();
        System.out.println("  # Fast mode - Use existing dependency graph");
        System.out.println("  deptrast create input.sbom output.json --use-existing-deps");
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

            // Sort components alphabetically by purl for consistent ordering
            components.sort((c1, c2) -> {
                String purl1 = c1.getPurl() != null ? c1.getPurl() : "";
                String purl2 = c2.getPurl() != null ? c2.getPurl() : "";
                return purl1.compareTo(purl2);
            });

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

            // Sort dependencies alphabetically by ref for consistent ordering
            dependencies.sort((d1, d2) -> {
                String ref1 = d1.getRef() != null ? d1.getRef() : "";
                String ref2 = d2.getRef() != null ? d2.getRef() : "";
                return ref1.compareTo(ref2);
            });

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