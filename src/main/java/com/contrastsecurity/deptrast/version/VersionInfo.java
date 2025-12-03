package com.contrastsecurity.deptrast.version;

import java.util.Collections;
import java.util.Map;

/**
 * Parsed version information.
 *
 * Contains different version representations for different use cases:
 * - sbomVersion: Version to use in SBOM (typically the patched/actual version)
 * - depsDevVersion: Version to use for deps.dev API queries (typically the upstream version)
 * - originalString: The original version string as-is
 * - isHeroDevs: Whether this is a HeroDevs NES version
 * - metadata: Additional metadata about the version
 */
public class VersionInfo {
    private final String sbomVersion;
    private final String depsDevVersion;
    private final String originalString;
    private final boolean isHeroDevs;
    private final Map<String, String> metadata;

    /**
     * Create a new VersionInfo.
     *
     * @param sbomVersion Version to use in SBOM output
     * @param depsDevVersion Version to use for deps.dev API queries
     * @param originalString The original version string
     * @param isHeroDevs Whether this is a HeroDevs NES version
     * @param metadata Additional metadata about the version (can be null)
     */
    public VersionInfo(String sbomVersion, String depsDevVersion, String originalString,
                      boolean isHeroDevs, Map<String, String> metadata) {
        this.sbomVersion = sbomVersion;
        this.depsDevVersion = depsDevVersion;
        this.originalString = originalString;
        this.isHeroDevs = isHeroDevs;
        this.metadata = metadata != null ? Collections.unmodifiableMap(metadata) : Collections.emptyMap();
    }

    /**
     * Get the version to use in SBOM output.
     * For HeroDevs versions, this is the patched version.
     *
     * @return The SBOM version
     */
    public String getSbomVersion() {
        return sbomVersion;
    }

    /**
     * Get the version to use for deps.dev API queries.
     * For HeroDevs versions, this is the upstream version.
     *
     * @return The deps.dev version
     */
    public String getDepsDevVersion() {
        return depsDevVersion;
    }

    /**
     * Get the original version string as provided.
     *
     * @return The original version string
     */
    public String getOriginalString() {
        return originalString;
    }

    /**
     * Check if this is a HeroDevs NES version.
     *
     * @return true if this is a HeroDevs version
     */
    public boolean isHeroDevs() {
        return isHeroDevs;
    }

    /**
     * Get additional metadata about the version.
     * For HeroDevs versions, includes upstream version, patched version, etc.
     *
     * @return Unmodifiable map of metadata (never null)
     */
    public Map<String, String> getMetadata() {
        return metadata;
    }

    @Override
    public String toString() {
        return "VersionInfo{" +
                "sbomVersion='" + sbomVersion + '\'' +
                ", depsDevVersion='" + depsDevVersion + '\'' +
                ", originalString='" + originalString + '\'' +
                ", isHeroDevs=" + isHeroDevs +
                ", metadata=" + metadata +
                '}';
    }
}
