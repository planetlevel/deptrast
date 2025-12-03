package com.contrastsecurity.deptrast.version;

import java.util.HashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Parser for vendor-specific version formats.
 *
 * Handles special version formats like HeroDevs Never-Ending Support (NES):
 * Format: {@code <original>-<artifact>-<patched>}
 * Example: {@code 5.3.39-spring-framework-5.3.47}
 */
public class VersionParser {

    /**
     * HeroDevs NES format: {@code <original>-<artifact>-<patched>}
     * The artifact name must NOT contain hyphens followed by version numbers
     *
     * Examples:
     * - 5.3.39-spring-framework-5.3.47
     * - 2.7.18-spring-boot-2.7.27
     * - 5.8.16-spring-security-5.8.22
     */
    private static final Pattern HERODEVS_PATTERN = Pattern.compile(
        "^([0-9]+\\.[0-9]+\\.[0-9]+(?:[A-Za-z0-9._]*)?)" +  // Original version (no trailing hyphen)
        "-([a-z][a-z0-9_-]*[a-z0-9_])" +                    // Artifact name
        "-([0-9]+\\.[0-9]+\\.[0-9]+(?:[A-Za-z0-9._]*)?)$"   // Patched version
    );

    /**
     * Parse a version string, handling special formats like HeroDevs NES.
     *
     * @param version The version string to parse
     * @return VersionInfo with appropriate versions for different use cases
     */
    public static VersionInfo parse(String version) {
        if (version == null || version.isEmpty()) {
            return new VersionInfo(version, version, version, false, null);
        }

        Matcher matcher = HERODEVS_PATTERN.matcher(version);
        if (matcher.matches()) {
            String originalVersion = matcher.group(1);
            String artifactName = matcher.group(2);
            String patchedVersion = matcher.group(3);

            Map<String, String> metadata = new HashMap<>();
            metadata.put("herodevs:nes", "true");
            metadata.put("herodevs:upstream-version", originalVersion);
            metadata.put("herodevs:patched-version", patchedVersion);
            metadata.put("herodevs:artifact", artifactName);
            metadata.put("supplier", "HeroDevs");

            return new VersionInfo(
                patchedVersion,     // sbomVersion - use patched version in SBOM
                originalVersion,    // depsDevVersion - use original for deps.dev
                version,            // originalString
                true,               // isHeroDevs
                metadata
            );
        }

        // Standard version - no special handling needed
        return new VersionInfo(version, version, version, false, null);
    }

    /**
     * Get the version to use for deps.dev API queries.
     *
     * For HeroDevs versions, returns the upstream version.
     * For standard versions, returns the version as-is.
     *
     * @param version The version string to parse
     * @return The version to use for deps.dev queries
     */
    public static String getDepsDevVersion(String version) {
        return parse(version).getDepsDevVersion();
    }

    /**
     * Get the version to use in SBOM output.
     *
     * For HeroDevs versions, returns the patched version.
     * For standard versions, returns the version as-is.
     *
     * @param version The version string to parse
     * @return The version to use in SBOM
     */
    public static String getSbomVersion(String version) {
        return parse(version).getSbomVersion();
    }
}
