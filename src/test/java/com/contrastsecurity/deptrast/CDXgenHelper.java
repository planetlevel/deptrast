package com.contrastsecurity.deptrast;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.TimeUnit;

/**
 * Helper class to run CDXgen and compare results with deptrast
 */
public class CDXgenHelper {

    private static final String CDXGEN_COMMAND = "cdxgen";
    private static boolean cdxgenAvailable = false;
    private static boolean cdxgenChecked = false;

    /**
     * Check if CDXgen is available on the system
     */
    public static boolean isCDXgenAvailable() {
        if (cdxgenChecked) {
            return cdxgenAvailable;
        }

        try {
            Process process = new ProcessBuilder(CDXGEN_COMMAND, "--version")
                .redirectErrorStream(true)
                .start();

            boolean completed = process.waitFor(10, TimeUnit.SECONDS);
            cdxgenAvailable = completed && process.exitValue() == 0;
        } catch (Exception e) {
            cdxgenAvailable = false;
        }

        cdxgenChecked = true;
        return cdxgenAvailable;
    }

    /**
     * Run CDXgen on an input file and return the path to the generated SBOM
     */
    public static Path runCDXgen(String inputFile, String outputFile) throws IOException, InterruptedException {
        if (!isCDXgenAvailable()) {
            throw new IllegalStateException("CDXgen is not available. Please install it with: npm install -g @cyclonedx/cdxgen");
        }

        ProcessBuilder pb = new ProcessBuilder(
            CDXGEN_COMMAND,
            "-o", outputFile,
            inputFile
        );

        pb.redirectErrorStream(true);
        Process process = pb.start();

        // Capture output for debugging
        StringBuilder output = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line).append("\n");
            }
        }

        boolean completed = process.waitFor(120, TimeUnit.SECONDS);
        if (!completed) {
            process.destroyForcibly();
            throw new IOException("CDXgen process timed out");
        }

        if (process.exitValue() != 0) {
            throw new IOException("CDXgen failed with exit code " + process.exitValue() + "\nOutput: " + output);
        }

        Path outputPath = Paths.get(outputFile);
        if (!Files.exists(outputPath)) {
            throw new IOException("CDXgen did not create output file: " + outputFile);
        }

        return outputPath;
    }

    /**
     * Normalize a PURL by removing query parameters (like ?type=jar)
     */
    private static String normalizePurl(String purl) {
        // Remove query parameters (everything after ?)
        int queryIndex = purl.indexOf('?');
        if (queryIndex > 0) {
            return purl.substring(0, queryIndex);
        }
        return purl;
    }

    /**
     * Parse an SBOM file and extract component identifiers
     */
    public static Set<String> extractComponents(String sbomFilePath) throws IOException {
        Set<String> components = new HashSet<>();

        String content = new String(Files.readAllBytes(Paths.get(sbomFilePath)));
        JsonObject sbom = JsonParser.parseString(content).getAsJsonObject();

        JsonArray componentsArray = sbom.getAsJsonArray("components");
        if (componentsArray != null) {
            for (JsonElement element : componentsArray) {
                JsonObject component = element.getAsJsonObject();

                // Extract identifier - prefer purl, fallback to name:version
                String identifier;
                JsonElement purlElement = component.get("purl");
                if (purlElement != null && !purlElement.isJsonNull()) {
                    identifier = normalizePurl(purlElement.getAsString());
                } else {
                    // Fallback to name:version
                    String name = component.has("name") ? component.get("name").getAsString() : "unknown";
                    String version = component.has("version") ? component.get("version").getAsString() : "unknown";

                    // Include group if available (for Maven)
                    if (component.has("group") && !component.get("group").isJsonNull()) {
                        String group = component.get("group").getAsString();
                        identifier = group + ":" + name + ":" + version;
                    } else {
                        identifier = name + ":" + version;
                    }
                }

                components.add(identifier);
            }
        }

        return components;
    }

    /**
     * Compare two sets of components and return the percentage match
     */
    public static double compareComponents(Set<String> deptrast, Set<String> cdxgen) {
        if (cdxgen.isEmpty()) {
            return 100.0;
        }

        // Count how many CDXgen components are found in deptrast
        int matched = 0;
        for (String component : cdxgen) {
            if (deptrast.contains(component)) {
                matched++;
            }
        }

        return (matched * 100.0) / cdxgen.size();
    }

    /**
     * Find missing components (in CDXgen but not in deptrast)
     */
    public static Set<String> findMissingComponents(Set<String> deptrast, Set<String> cdxgen) {
        Set<String> missing = new HashSet<>(cdxgen);
        missing.removeAll(deptrast);
        return missing;
    }

    /**
     * Get count of components from SBOM file
     */
    public static int getComponentCount(String sbomFilePath) throws IOException {
        String content = new String(Files.readAllBytes(Paths.get(sbomFilePath)));
        JsonObject sbom = JsonParser.parseString(content).getAsJsonObject();

        JsonArray componentsArray = sbom.getAsJsonArray("components");
        return componentsArray != null ? componentsArray.size() : 0;
    }

    /**
     * Get count of dependencies from SBOM file
     */
    public static int getDependencyCount(String sbomFilePath) throws IOException {
        String content = new String(Files.readAllBytes(Paths.get(sbomFilePath)));
        JsonObject sbom = JsonParser.parseString(content).getAsJsonObject();

        JsonArray dependenciesArray = sbom.getAsJsonArray("dependencies");
        return dependenciesArray != null ? dependenciesArray.size() : 0;
    }

    /**
     * Validation result for an SBOM
     */
    public static class ValidationResult {
        public boolean valid;
        public int componentCount;
        public int dependencyCount;
        public int componentsWithPurl;
        public int componentsWithBomRef;
        public String errorMessage;

        public ValidationResult(boolean valid, int componentCount, int dependencyCount,
                              int componentsWithPurl, int componentsWithBomRef) {
            this.valid = valid;
            this.componentCount = componentCount;
            this.dependencyCount = dependencyCount;
            this.componentsWithPurl = componentsWithPurl;
            this.componentsWithBomRef = componentsWithBomRef;
        }

        public ValidationResult(String errorMessage) {
            this.valid = false;
            this.errorMessage = errorMessage;
        }
    }

    /**
     * Validate SBOM structure and return validation result
     */
    public static ValidationResult validateSbom(String sbomFilePath) throws IOException {
        String content = new String(Files.readAllBytes(Paths.get(sbomFilePath)));
        JsonObject sbom = JsonParser.parseString(content).getAsJsonObject();

        // Check required fields
        if (!sbom.has("bomFormat")) {
            return new ValidationResult("Missing required field: bomFormat");
        }
        if (!sbom.has("specVersion")) {
            return new ValidationResult("Missing required field: specVersion");
        }
        if (!sbom.has("components")) {
            return new ValidationResult("Missing required field: components");
        }

        // Check bomFormat value
        String bomFormat = sbom.get("bomFormat").getAsString();
        if (!"CycloneDX".equals(bomFormat)) {
            return new ValidationResult("Invalid bomFormat: " + bomFormat);
        }

        // Count components and their attributes
        int componentCount = 0;
        int withPurl = 0;
        int withBomRef = 0;

        JsonArray components = sbom.getAsJsonArray("components");
        if (components != null) {
            componentCount = components.size();
            for (JsonElement elem : components) {
                JsonObject component = elem.getAsJsonObject();
                if (component.has("purl") && !component.get("purl").isJsonNull()) {
                    withPurl++;
                }
                if (component.has("bom-ref") && !component.get("bom-ref").isJsonNull()) {
                    withBomRef++;
                }
            }
        }

        // Count dependencies
        int dependencyCount = 0;
        if (sbom.has("dependencies")) {
            JsonArray dependencies = sbom.getAsJsonArray("dependencies");
            dependencyCount = dependencies != null ? dependencies.size() : 0;
        }

        return new ValidationResult(true, componentCount, dependencyCount, withPurl, withBomRef);
    }
}
