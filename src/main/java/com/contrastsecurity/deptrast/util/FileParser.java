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
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;

/**
 * Utility class for parsing input files containing package information
 */
public class FileParser {
    private static final Logger logger = LoggerFactory.getLogger(FileParser.class);

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
     */
    public static List<Package> parsePomFile(String filePath) {
        List<Package> packages = new ArrayList<>();

        try {
            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            DocumentBuilder builder = factory.newDocumentBuilder();
            Document doc = builder.parse(new File(filePath));
            doc.getDocumentElement().normalize();

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

                    if (groupId != null && artifactId != null && version != null) {
                        // Remove ${...} variable references - we can't resolve them without full Maven context
                        if (version.contains("${")) {
                            logger.warn("Skipping dependency with variable version: {}:{}:{}", groupId, artifactId, version);
                            continue;
                        }

                        String name = groupId + ":" + artifactId;
                        Package pkg = new Package("maven", name, version);
                        packages.add(pkg);
                        logger.info("Added package from pom.xml: {}", pkg.getFullName());
                    }
                }
            }

            logger.info("Parsed {} packages from pom.xml", packages.size());
        } catch (Exception e) {
            logger.error("Error parsing pom.xml file {}: {}", filePath, e.getMessage());
        }

        return packages;
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