package com.contrastsecurity.deptrast.util;

import com.contrastsecurity.deptrast.model.Package;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;
import java.util.concurrent.TimeUnit;
import javax.net.ssl.*;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

/**
 * Utility class for parsing input files containing package information
 */
public class FileParser {
    private static final Logger logger = LoggerFactory.getLogger(FileParser.class);
    private static final String MAVEN_CENTRAL_URL = "https://repo1.maven.org/maven2";

    // Initialize HTTP client with IPv4 preference
    private static final OkHttpClient httpClient;

    static {
        // Force IPv4 to avoid IPv6 connectivity issues
        System.setProperty("java.net.preferIPv4Stack", "true");

        OkHttpClient.Builder clientBuilder = new OkHttpClient.Builder()
                .connectTimeout(30, TimeUnit.SECONDS)
                .readTimeout(30, TimeUnit.SECONDS)
                .retryOnConnectionFailure(true);

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
            // Continue with default SSL settings
        }

        httpClient = clientBuilder.build();
    }

    /**
     * Parse a file containing package information
     * Each line should be in the format: system:name:version
     * For example: maven:com.google.guava:guava:31.1-jre
     *
     * @param filePath path to the file
     * @return list of packages
     */
    public static List<Package> parsePackagesFromFile(String filePath) {
        List<Package> packages = new ArrayList<>();
        Path path = Paths.get(filePath);
        
        if (!Files.exists(path)) {
            logger.error("File not found: {}", filePath);
            return packages;
        }
        
        try (BufferedReader reader = new BufferedReader(new FileReader(filePath))) {
            String line;
            int lineNumber = 0;
            
            while ((line = reader.readLine()) != null) {
                lineNumber++;
                line = line.trim();
                
                // Skip empty lines and comments
                if (line.isEmpty() || line.startsWith("#")) {
                    continue;
                }
                
                try {
                    String[] parts = line.split(":");
                    if (parts.length < 3) {
                        logger.warn("Invalid format at line {}: {}. Expected system:name:version", lineNumber, line);
                        continue;
                    }
                    
                    String system = parts[0];
                    
                    if ("maven".equals(system)) {
                        // Format: maven:groupId:artifactId:version
                        if (parts.length >= 4) {
                            String name;
                            String version;
                            
                            // Handle Maven format correctly
                            if (parts.length == 4) {
                                // maven:groupId:artifactId:version
                                name = parts[1] + ":" + parts[2];
                                version = parts[3];
                            } else {
                                // Something is wrong with the format, try to recover
                                StringBuilder nameBuilder = new StringBuilder(parts[1]);
                                for (int i = 2; i < parts.length - 1; i++) {
                                    nameBuilder.append(":").append(parts[i]);
                                }
                                name = nameBuilder.toString();
                                version = parts[parts.length - 1];
                            }
                            
                            Package pkg = new Package(system, name, version);
                            packages.add(pkg);
                            logger.info("Added package: {}", pkg.getFullName());
                        } else {
                            logger.warn("Invalid Maven format at line {}: {}. Expected maven:groupId:artifactId:version", lineNumber, line);
                        }
                    } else if ("npm".equals(system)) {
                        // Format: npm:packageName:version
                        if (parts.length == 3) {
                            String name = parts[1];
                            String version = parts[2];
                            Package pkg = new Package(system, name, version);
                            packages.add(pkg);
                            logger.info("Added package: {}", pkg.getFullName());
                        } else {
                            logger.warn("Invalid npm format at line {}: {}. Expected npm:packageName:version", lineNumber, line);
                        }
                    } else {
                        logger.warn("Unsupported package system at line {}: {}", lineNumber, line);
                    }
                } catch (Exception e) {
                    logger.error("Error parsing line {}: {}", lineNumber, e.getMessage());
                }
            }
        } catch (IOException e) {
            logger.error("Error reading file {}: {}", filePath, e.getMessage());
        }

        return packages;
    }

    /**
     * Parse a CycloneDX SBOM file
     *
     * @param filePath path to the SBOM file
     * @return list of packages
     */
    public static List<Package> parseSbomFile(String filePath) {
        List<Package> packages = new ArrayList<>();

        try {
            // Read and parse JSON file
            String content = new String(Files.readAllBytes(Paths.get(filePath)));
            JsonObject sbom = JsonParser.parseString(content).getAsJsonObject();

            // Get components array
            JsonArray components = sbom.getAsJsonArray("components");
            if (components != null) {
                for (JsonElement element : components) {
                    JsonObject component = element.getAsJsonObject();
                    JsonElement purlElement = component.get("purl");

                    if (purlElement != null && !purlElement.isJsonNull()) {
                        String purl = purlElement.getAsString();
                        if (purl.startsWith("pkg:")) {
                            // Parse purl format: pkg:maven/group/artifact@version
                            Package pkg = parsePurl(purl);
                            if (pkg != null) {
                                packages.add(pkg);
                                logger.info("Added package from SBOM: {}", pkg.getFullName());
                            }
                        }
                    }
                }
            }

            logger.info("Parsed {} packages from SBOM", packages.size());
        } catch (Exception e) {
            logger.error("Error parsing SBOM file {}: {}", filePath, e.getMessage());
        }

        return packages;
    }

    /**
     * Parse a Maven pom.xml file
     *
     * @param filePath path to the pom.xml file
     * @return list of packages
     * @deprecated Use parsePomFileWithManagement() to get dependency management info
     */
    @Deprecated
    public static List<Package> parsePomFile(String filePath) {
        PomParseResult result = parsePomFileWithManagement(filePath);
        return result.getPackages();
    }

    /**
     * Parse a Maven pom.xml file with dependency management
     *
     * @param filePath path to the pom.xml file
     * @return PomParseResult containing packages and dependency management
     */
    public static PomParseResult parsePomFileWithManagement(String filePath) {
        List<Package> packages = new ArrayList<>();
        Map<String, String> dependencyManagement = new HashMap<>();
        Map<String, Set<String>> exclusions = new HashMap<>(); // package name -> excluded dependencies

        try {
            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            DocumentBuilder builder = factory.newDocumentBuilder();
            Document doc = builder.parse(new File(filePath));
            doc.getDocumentElement().normalize();

            // Load parent POM data (properties and hierarchy of POM documents)
            ParentPomData parentData = parseParentPomData(doc, filePath, factory, builder);
            Map<String, String> properties = new HashMap<>(parentData.properties);

            logger.info("Loaded {} properties from parent POM hierarchy", parentData.properties.size());

            // Then parse properties from current POM (these override parent properties)
            Map<String, String> currentProperties = parseProperties(doc);
            properties.putAll(currentProperties);
            logger.info("Loaded {} properties total ({} from current pom.xml)", properties.size(), currentProperties.size());

            // Now parse ALL dependencyManagement sections with the FINAL merged properties
            // This ensures that property overrides in child POMs affect parent dependencyManagement
            dependencyManagement = new HashMap<>();

            // Parse dependencyManagement from parent hierarchy (oldest first)
            for (Document pomDoc : parentData.pomHierarchy) {
                Map<String, String> pomDepMgmt = parseDependencyManagement(pomDoc, properties);
                dependencyManagement.putAll(pomDepMgmt);
            }

            // Parse dependency management from current POM (overrides parents)
            Map<String, String> currentDepMgmt = parseDependencyManagement(doc, properties);
            dependencyManagement.putAll(currentDepMgmt);

            logger.info("Total {} managed dependency versions (re-evaluated with final properties)", dependencyManagement.size());

            // Find all <dependency> elements
            NodeList dependencyNodes = doc.getElementsByTagName("dependency");

            for (int i = 0; i < dependencyNodes.getLength(); i++) {
                Node node = dependencyNodes.item(i);

                if (node.getNodeType() == Node.ELEMENT_NODE) {
                    Element element = (Element) node;

                    // Skip test-scoped dependencies by default
                    String scope = getElementText(element, "scope");
                    if ("test".equals(scope)) {
                        continue;
                    }

                    String groupId = getElementText(element, "groupId");
                    String artifactId = getElementText(element, "artifactId");
                    String version = getElementText(element, "version");

                    // Parse exclusions for this dependency
                    Set<String> depExclusions = parseExclusions(element);

                    if (groupId != null && artifactId != null) {
                        // If version is not specified, try to get it from dependency management
                        if (version == null || version.isEmpty()) {
                            String key = groupId + ":" + artifactId;
                            version = dependencyManagement.get(key);
                            if (version != null) {
                                logger.info("Resolved version for {}:{} from dependencyManagement: {}", groupId, artifactId, version);
                            } else {
                                logger.warn("Skipping dependency with no version: {}:{}", groupId, artifactId);
                                continue;
                            }
                        } else if (version.contains("${")) {
                            // Try to resolve ${...} variable references from properties
                            String resolvedVersion = resolveProperty(version, properties);
                            if (resolvedVersion != null && !resolvedVersion.contains("${")) {
                                version = resolvedVersion;
                                logger.info("Resolved property version for {}:{} to {}", groupId, artifactId, version);
                            } else {
                                logger.warn("Skipping dependency with unresolvable version: {}:{}:{}", groupId, artifactId, version);
                                continue;
                            }
                        }

                        String name = groupId + ":" + artifactId;
                        Package pkg = new Package("maven", name, version);
                        packages.add(pkg);
                        logger.info("Added package from pom.xml: {}", pkg.getFullName());

                        // Store exclusions for this package if any
                        if (!depExclusions.isEmpty()) {
                            exclusions.put(name, depExclusions);
                            logger.info("Package {} has {} exclusions", name, depExclusions.size());
                        }
                    }
                }
            }

            logger.info("Parsed {} packages from pom.xml", packages.size());
        } catch (Exception e) {
            logger.error("Error parsing pom.xml file {}: {}", filePath, e.getMessage());
        }

        return new PomParseResult(packages, dependencyManagement, exclusions);
    }

    /**
     * Parse a Python requirements.txt file
     *
     * @param filePath path to the requirements.txt file
     * @return list of packages
     */
    public static List<Package> parseRequirementsFile(String filePath) {
        List<Package> packages = new ArrayList<>();

        try (BufferedReader reader = new BufferedReader(new FileReader(filePath))) {
            String line;
            int lineNumber = 0;

            while ((line = reader.readLine()) != null) {
                lineNumber++;
                line = line.trim();

                // Skip empty lines and comments
                if (line.isEmpty() || line.startsWith("#")) {
                    continue;
                }

                // Parse requirement line (e.g., "requests==2.28.1" or "requests>=2.28.1")
                String[] parts = line.split("==|>=|<=|~=|!=");
                if (parts.length >= 2) {
                    String name = parts[0].trim();
                    String version = parts[1].trim().split(";")[0].trim(); // Remove environment markers

                    Package pkg = new Package("pypi", name, version);
                    packages.add(pkg);
                    logger.info("Added package from requirements.txt: {}", pkg.getFullName());
                } else {
                    logger.warn("Invalid format at line {}: {}. Expected package==version", lineNumber, line);
                }
            }

            logger.info("Parsed {} packages from requirements.txt", packages.size());
        } catch (IOException e) {
            logger.error("Error reading requirements.txt file {}: {}", filePath, e.getMessage());
        }

        return packages;
    }

    /**
     * Parse a Gradle build file
     *
     * @param filePath path to the build.gradle or build.gradle.kts file
     * @return list of packages
     */
    public static List<Package> parseGradleFile(String filePath) {
        List<Package> packages = new ArrayList<>();

        try (BufferedReader reader = new BufferedReader(new FileReader(filePath))) {
            String line;
            int lineNumber = 0;
            boolean inDependenciesBlock = false;

            while ((line = reader.readLine()) != null) {
                lineNumber++;
                String trimmed = line.trim();

                // Track if we're inside dependencies block
                if (trimmed.startsWith("dependencies")) {
                    inDependenciesBlock = true;
                    continue;
                }

                // Exit dependencies block on closing brace
                if (inDependenciesBlock && trimmed.startsWith("}")) {
                    inDependenciesBlock = false;
                    continue;
                }

                // Parse dependencies inside the block
                if (inDependenciesBlock) {
                    Package pkg = parseGradleDependency(trimmed, lineNumber);
                    if (pkg != null) {
                        packages.add(pkg);
                        logger.info("Added package from Gradle: {}", pkg.getFullName());
                    }
                }
            }

            logger.info("Parsed {} packages from Gradle file", packages.size());
        } catch (IOException e) {
            logger.error("Error reading Gradle file {}: {}", filePath, e.getMessage());
        }

        return packages;
    }

    /**
     * Parse a single Gradle dependency line
     *
     * @param line the dependency line
     * @param lineNumber line number for logging
     * @return Package object or null
     */
    private static Package parseGradleDependency(String line, int lineNumber) {
        // Skip test dependencies
        if (line.contains("testImplementation") || line.contains("testCompile") ||
            line.contains("androidTestImplementation")) {
            return null;
        }

        // Extract the dependency string from various formats:
        // implementation 'group:artifact:version'
        // implementation "group:artifact:version"
        // implementation group: 'group', name: 'artifact', version: 'version'
        // api 'group:artifact:version'

        try {
            // Pattern 1: implementation 'group:artifact:version' or "group:artifact:version"
            if (line.contains("'") || line.contains("\"")) {
                int start = Math.max(line.indexOf("'"), line.indexOf("\""));
                if (start == -1) start = line.indexOf("'");
                if (start == -1) start = line.indexOf("\"");

                int end = line.indexOf("'", start + 1);
                if (end == -1) end = line.indexOf("\"", start + 1);

                if (start != -1 && end != -1 && end > start) {
                    String depString = line.substring(start + 1, end);

                    // Parse group:artifact:version format
                    String[] parts = depString.split(":");
                    if (parts.length >= 3) {
                        String group = parts[0];
                        String artifact = parts[1];
                        String version = parts[2];

                        // Determine ecosystem (most Gradle is Maven, but could be others)
                        String system = "maven";
                        if (group.startsWith("npm.") || artifact.startsWith("npm-")) {
                            system = "npm";
                        }

                        String name = group + ":" + artifact;
                        return new Package(system, name, version);
                    }
                }
            }

            // Pattern 2: Map notation - group: 'group', name: 'artifact', version: 'version'
            if (line.contains("group:") && line.contains("name:") && line.contains("version:")) {
                String group = extractGradleMapValue(line, "group");
                String artifact = extractGradleMapValue(line, "name");
                String version = extractGradleMapValue(line, "version");

                if (group != null && artifact != null && version != null) {
                    String name = group + ":" + artifact;
                    return new Package("maven", name, version);
                }
            }

        } catch (Exception e) {
            logger.warn("Error parsing Gradle dependency at line {}: {}", lineNumber, e.getMessage());
        }

        return null;
    }

    /**
     * Extract a value from Gradle map notation
     *
     * @param line the line containing the map
     * @param key the key to extract
     * @return the value or null
     */
    private static String extractGradleMapValue(String line, String key) {
        int keyPos = line.indexOf(key + ":");
        if (keyPos == -1) return null;

        String after = line.substring(keyPos + key.length() + 1).trim();
        int start = Math.max(after.indexOf("'"), after.indexOf("\""));
        if (start == -1) return null;

        int end = after.indexOf(after.charAt(start), start + 1);
        if (end == -1) return null;

        return after.substring(start + 1, end);
    }

    /**
     * Parse a package URL (purl) into a Package object
     *
     * @param purl the package URL (e.g., "pkg:maven/org.springframework/spring-core@5.3.0")
     * @return Package object or null if parsing fails
     */
    private static Package parsePurl(String purl) {
        try {
            // Remove "pkg:" prefix
            String withoutPrefix = purl.substring(4);

            // Split into type and rest
            int typeEnd = withoutPrefix.indexOf('/');
            if (typeEnd == -1) return null;

            String type = withoutPrefix.substring(0, typeEnd);
            String rest = withoutPrefix.substring(typeEnd + 1);

            // Split into name and version at @
            int versionStart = rest.lastIndexOf('@');
            if (versionStart == -1) return null;

            String namepart = rest.substring(0, versionStart);
            String version = rest.substring(versionStart + 1);

            // For Maven, combine group/artifact into name
            if ("maven".equals(type)) {
                String name = namepart.replace('/', ':');
                return new Package("maven", name, version);
            } else {
                // For other types, use the name as-is
                return new Package(type, namepart, version);
            }
        } catch (Exception e) {
            logger.error("Error parsing purl {}: {}", purl, e.getMessage());
            return null;
        }
    }

    /**
     * Parse all properties from the <properties> section of a pom.xml
     *
     * @param doc parsed XML document
     * @return map of property name to value
     */
    private static Map<String, String> parseProperties(Document doc) {
        Map<String, String> properties = new HashMap<>();

        NodeList propertiesNodes = doc.getElementsByTagName("properties");
        if (propertiesNodes.getLength() > 0) {
            Element propertiesElement = (Element) propertiesNodes.item(0);
            NodeList children = propertiesElement.getChildNodes();

            for (int i = 0; i < children.getLength(); i++) {
                Node child = children.item(i);
                if (child.getNodeType() == Node.ELEMENT_NODE) {
                    String propertyName = child.getNodeName();
                    String propertyValue = child.getTextContent().trim();
                    properties.put(propertyName, propertyValue);
                }
            }
        }

        return properties;
    }

    /**
     * Helper class to hold both properties and dependency management from parent POMs
     */
    private static class ParentPomData {
        Map<String, String> properties = new HashMap<>();
        Map<String, String> dependencyManagement = new HashMap<>();
        List<Document> pomHierarchy = new ArrayList<>();  // Store all POM documents for re-evaluation
    }

    /**
     * Result class to hold parsed packages and their dependency management
     */
    public static class PomParseResult {
        private final List<Package> packages;
        private final Map<String, String> dependencyManagement;
        private final Map<String, Set<String>> exclusions; // package name -> set of excluded "groupId:artifactId"

        public PomParseResult(List<Package> packages, Map<String, String> dependencyManagement, Map<String, Set<String>> exclusions) {
            this.packages = packages;
            this.dependencyManagement = dependencyManagement;
            this.exclusions = exclusions;
        }

        public List<Package> getPackages() {
            return packages;
        }

        public Map<String, String> getDependencyManagement() {
            return dependencyManagement;
        }

        public Map<String, Set<String>> getExclusions() {
            return exclusions;
        }
    }

    /**
     * Parse properties and dependency management from parent POM hierarchy
     *
     * @param doc current document
     * @param currentFilePath path to current pom.xml
     * @param factory DocumentBuilderFactory to reuse
     * @param builder DocumentBuilder to reuse
     * @return ParentPomData containing properties and dependency management
     */
    private static ParentPomData parseParentPomData(
            Document doc,
            String currentFilePath,
            DocumentBuilderFactory factory,
            DocumentBuilder builder) {

        ParentPomData result = new ParentPomData();

        try {
            // Look for <parent> element
            NodeList parentNodes = doc.getElementsByTagName("parent");
            if (parentNodes.getLength() == 0) {
                return result;
            }

            Element parentElement = (Element) parentNodes.item(0);

            // Get parent coordinates for Maven Central download
            String parentGroupId = getElementText(parentElement, "groupId");
            String parentArtifactId = getElementText(parentElement, "artifactId");
            String parentVersion = getElementText(parentElement, "version");

            // Get relativePath (defaults to ../pom.xml if not specified)
            String relativePath = getElementText(parentElement, "relativePath");
            if (relativePath == null || relativePath.isEmpty()) {
                relativePath = "../pom.xml";
            }

            Document parentDoc = null;
            String parentDocPath = null;

            // Check if current file is from Maven Central (synthetic path)
            boolean isFromMavenCentral = currentFilePath.startsWith("maven-central:");

            if (isFromMavenCentral) {
                // Parent of a Maven Central POM - download it directly
                logger.info("Parent of Maven Central POM {}:{}:{}, downloading from Maven Central",
                        parentGroupId, parentArtifactId, parentVersion);
                if (parentGroupId != null && parentArtifactId != null && parentVersion != null) {
                    parentDoc = downloadPomFromMavenCentral(parentGroupId, parentArtifactId, parentVersion, builder);
                    if (parentDoc != null) {
                        parentDocPath = String.format("maven-central:%s:%s:%s",
                                parentGroupId, parentArtifactId, parentVersion);
                    }
                }

                if (parentDoc == null) {
                    logger.warn("Could not download parent POM {}:{}:{} from Maven Central",
                            parentGroupId, parentArtifactId, parentVersion);
                    return result;
                }
            } else {
                // Try to find parent POM locally first
                Path currentPath = Paths.get(currentFilePath).toAbsolutePath().getParent();
                Path parentPath = currentPath.resolve(relativePath).normalize();
                File parentPomFile = parentPath.toFile();

                if (parentPomFile.exists()) {
                    logger.info("Found parent POM at: {}", parentPath);
                    parentDoc = builder.parse(parentPomFile);
                    parentDoc.getDocumentElement().normalize();
                    parentDocPath = parentPath.toString();
                } else {
                    logger.debug("Parent POM not found at: {}, will try Maven Central", parentPath);

                    // Try to download from Maven Central
                    if (parentGroupId != null && parentArtifactId != null && parentVersion != null) {
                        parentDoc = downloadPomFromMavenCentral(parentGroupId, parentArtifactId, parentVersion, builder);
                        if (parentDoc != null) {
                            // Use a synthetic path for downloaded POMs
                            parentDocPath = String.format("maven-central:%s:%s:%s",
                                    parentGroupId, parentArtifactId, parentVersion);
                        }
                    }

                    if (parentDoc == null) {
                        logger.warn("Could not resolve parent POM {}:{}:{}", parentGroupId, parentArtifactId, parentVersion);
                        return result;
                    }
                }
            }

            // Recursively get parent's parent data first (grandparent)
            ParentPomData grandparentData = parseParentPomData(
                    parentDoc, parentDocPath, factory, builder);
            result.properties.putAll(grandparentData.properties);
            result.pomHierarchy.addAll(grandparentData.pomHierarchy);

            // Then get parent's own properties (these override grandparent)
            Map<String, String> parentOwnProperties = parseProperties(parentDoc);
            result.properties.putAll(parentOwnProperties);

            // Store this POM document for later dependencyManagement re-evaluation
            result.pomHierarchy.add(parentDoc);

            // Note: We don't parse dependencyManagement here anymore
            // It will be parsed later with final merged properties

        } catch (Exception e) {
            logger.warn("Error parsing parent POM: {}", e.getMessage());
        }

        return result;
    }

    /**
     * Parse properties from parent POM if it exists (deprecated - use parseParentPomData instead)
     *
     * @param doc current document
     * @param currentFilePath path to current pom.xml
     * @param factory DocumentBuilderFactory to reuse
     * @param builder DocumentBuilder to reuse
     * @return map of parent properties or empty map
     */
    private static Map<String, String> parseParentPomProperties(
            Document doc,
            String currentFilePath,
            DocumentBuilderFactory factory,
            DocumentBuilder builder) {

        ParentPomData data = parseParentPomData(doc, currentFilePath, factory, builder);
        return data.properties;
    }

    /**
     * Resolve a property reference like ${spring.version} using the properties map
     * Supports nested properties (properties that reference other properties)
     *
     * @param value the value potentially containing ${...} references
     * @param properties map of property name to value
     * @return resolved value or null if unresolvable
     */
    private static String resolveProperty(String value, Map<String, String> properties) {
        if (value == null || !value.contains("${")) {
            return value;
        }

        String resolved = value;
        int maxIterations = 10; // Prevent infinite loops
        int iterations = 0;

        // Keep resolving until no more ${...} references or max iterations
        while (resolved.contains("${") && iterations < maxIterations) {
            int startIdx = resolved.indexOf("${");
            int endIdx = resolved.indexOf("}", startIdx);

            if (startIdx == -1 || endIdx == -1) {
                break;
            }

            String propertyName = resolved.substring(startIdx + 2, endIdx);
            String propertyValue = properties.get(propertyName);

            if (propertyValue == null) {
                // Can't resolve this property
                return null;
            }

            resolved = resolved.substring(0, startIdx) + propertyValue + resolved.substring(endIdx + 1);
            iterations++;
        }

        // If still contains ${...} after max iterations, it's unresolvable
        if (resolved.contains("${")) {
            return null;
        }

        return resolved;
    }

    /**
     * Download a POM file from Maven Central
     *
     * @param groupId Maven group ID
     * @param artifactId Maven artifact ID
     * @param version Maven version
     * @param builder DocumentBuilder to parse the POM
     * @return Document or null if download fails
     */
    private static Document downloadPomFromMavenCentral(
            String groupId,
            String artifactId,
            String version,
            DocumentBuilder builder) {

        try {
            // Build Maven Central URL: https://repo1.maven.org/maven2/group/id/artifact-id/version/artifact-id-version.pom
            String groupPath = groupId.replace('.', '/');
            String url = String.format("%s/%s/%s/%s/%s-%s.pom",
                    MAVEN_CENTRAL_URL, groupPath, artifactId, version, artifactId, version);

            logger.info("Downloading parent POM from Maven Central: {}:{}:{}", groupId, artifactId, version);
            logger.debug("URL: {}", url);

            Request request = new Request.Builder()
                    .url(url)
                    .get()
                    .build();

            try (Response response = httpClient.newCall(request).execute()) {
                if (!response.isSuccessful()) {
                    logger.warn("Failed to download parent POM {}:{}:{} from Maven Central: HTTP {}",
                            groupId, artifactId, version, response.code());
                    return null;
                }

                // Parse the downloaded POM
                try (InputStream inputStream = response.body().byteStream()) {
                    Document doc = builder.parse(inputStream);
                    doc.getDocumentElement().normalize();
                    logger.info("Successfully downloaded and parsed parent POM {}:{}:{}", groupId, artifactId, version);
                    return doc;
                }
            }
        } catch (Exception e) {
            logger.warn("Error downloading parent POM {}:{}:{}: {}", groupId, artifactId, version, e.getMessage());
            return null;
        }
    }

    /**
     * Parse dependencyManagement section from a POM document
     *
     * @param doc the POM document
     * @param properties properties map for resolving versions
     * @return map of groupId:artifactId to version
     */
    private static Map<String, String> parseDependencyManagement(Document doc, Map<String, String> properties) {
        Map<String, String> managedVersions = new HashMap<>();

        try {
            NodeList managementNodes = doc.getElementsByTagName("dependencyManagement");
            if (managementNodes.getLength() == 0) {
                return managedVersions;
            }

            Element managementElement = (Element) managementNodes.item(0);
            NodeList dependenciesLists = managementElement.getElementsByTagName("dependencies");

            if (dependenciesLists.getLength() == 0) {
                return managedVersions;
            }

            Element dependenciesElement = (Element) dependenciesLists.item(0);
            NodeList dependencyNodes = dependenciesElement.getElementsByTagName("dependency");

            for (int i = 0; i < dependencyNodes.getLength(); i++) {
                Node node = dependencyNodes.item(i);

                if (node.getNodeType() == Node.ELEMENT_NODE) {
                    Element element = (Element) node;

                    String groupId = getElementText(element, "groupId");
                    String artifactId = getElementText(element, "artifactId");
                    String version = getElementText(element, "version");

                    if (groupId != null && artifactId != null && version != null) {
                        // Resolve property references
                        if (version.contains("${")) {
                            String resolvedVersion = resolveProperty(version, properties);
                            if (resolvedVersion != null && !resolvedVersion.contains("${")) {
                                version = resolvedVersion;
                            } else {
                                logger.debug("Could not resolve version property {} for {}:{}", version, groupId, artifactId);
                                continue;
                            }
                        }

                        String key = groupId + ":" + artifactId;
                        managedVersions.put(key, version);
                    }
                }
            }

            logger.info("Parsed {} managed dependency versions from dependencyManagement", managedVersions.size());
        } catch (Exception e) {
            logger.warn("Error parsing dependencyManagement: {}", e.getMessage());
        }

        return managedVersions;
    }

    /**
     * Parse exclusions from a dependency element
     *
     * @param dependencyElement the dependency element
     * @return set of excluded dependencies in format "groupId:artifactId"
     */
    private static Set<String> parseExclusions(Element dependencyElement) {
        Set<String> exclusions = new HashSet<>();

        try {
            NodeList exclusionsList = dependencyElement.getElementsByTagName("exclusions");
            if (exclusionsList.getLength() == 0) {
                return exclusions;
            }

            Element exclusionsElement = (Element) exclusionsList.item(0);
            NodeList exclusionNodes = exclusionsElement.getElementsByTagName("exclusion");

            for (int i = 0; i < exclusionNodes.getLength(); i++) {
                Node node = exclusionNodes.item(i);

                if (node.getNodeType() == Node.ELEMENT_NODE) {
                    Element exclusionElement = (Element) node;

                    String groupId = getElementText(exclusionElement, "groupId");
                    String artifactId = getElementText(exclusionElement, "artifactId");

                    if (groupId != null && artifactId != null) {
                        String exclusionKey = groupId + ":" + artifactId;
                        exclusions.add(exclusionKey);
                        logger.debug("Found exclusion: {}", exclusionKey);
                    }
                }
            }
        } catch (Exception e) {
            logger.warn("Error parsing exclusions: {}", e.getMessage());
        }

        return exclusions;
    }

    /**
     * Get text content of a child element
     *
     * @param parent parent element
     * @param tagName tag name to find
     * @return text content or null
     */
    private static String getElementText(Element parent, String tagName) {
        NodeList nodes = parent.getElementsByTagName(tagName);
        if (nodes.getLength() > 0) {
            Node node = nodes.item(0);
            return node.getTextContent().trim();
        }
        return null;
    }
}