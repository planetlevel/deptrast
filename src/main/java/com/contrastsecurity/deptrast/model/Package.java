package com.contrastsecurity.deptrast.model;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * Represents a software package
 *
 * Dependency relationships are tracked in the DependencyNode tree structure.
 * Scope and metadata are mutable to support conflict resolution marking.
 */
public class Package {
    private final String name;
    private final String system;
    private final String version;
    private String scope;  // Maven scope: compile, runtime, test, provided, system, optional, excluded
    private String scopeReason;  // Reason for scope assignment (e.g., "conflict-resolution-loser", "not-observed-at-runtime")
    private String winningVersion;  // If this is a losing version, what version won?
    private String scopeStrategy;  // Conflict resolution strategy used: "maven" or "highest"
    private List<String> defeatedVersions;  // If this is a winner, list of versions it defeated
    private boolean isOverrideWinner;  // True if this won via dependency management override
    private Map<String, String> versionMetadata;  // Metadata about version (e.g., HeroDevs info)

    public Package(String system, String name, String version) {
        this(system, name, version, "compile");  // Default to compile scope
    }

    public Package(String system, String name, String version, String scope) {
        this(system, name, version, scope, null);
    }

    public Package(String system, String name, String version, String scope, Map<String, String> versionMetadata) {
        this.system = system;
        this.name = name;
        this.version = version;
        this.scope = scope != null ? scope : "compile";
        this.scopeReason = null;
        this.winningVersion = null;
        this.scopeStrategy = null;
        this.defeatedVersions = new ArrayList<>();
        this.isOverrideWinner = false;
        this.versionMetadata = versionMetadata != null ? new HashMap<>(versionMetadata) : null;
    }

    public String getName() {
        return name;
    }

    public String getSystem() {
        return system;
    }

    public String getVersion() {
        return version;
    }

    public String getScope() {
        return scope;
    }

    public void setScope(String scope) {
        this.scope = scope;
    }

    public String getScopeReason() {
        return scopeReason;
    }

    public void setScopeReason(String scopeReason) {
        this.scopeReason = scopeReason;
    }

    public String getWinningVersion() {
        return winningVersion;
    }

    public void setWinningVersion(String winningVersion) {
        this.winningVersion = winningVersion;
    }

    public String getScopeStrategy() {
        return scopeStrategy;
    }

    public void setScopeStrategy(String scopeStrategy) {
        this.scopeStrategy = scopeStrategy;
    }

    public List<String> getDefeatedVersions() {
        return defeatedVersions;
    }

    public void addDefeatedVersion(String version) {
        if (!defeatedVersions.contains(version)) {
            defeatedVersions.add(version);
        }
    }

    public boolean isOverrideWinner() {
        return isOverrideWinner;
    }

    public void setOverrideWinner(boolean overrideWinner) {
        isOverrideWinner = overrideWinner;
    }

    public Map<String, String> getVersionMetadata() {
        return versionMetadata != null ? Collections.unmodifiableMap(versionMetadata) : Collections.emptyMap();
    }

    public void setVersionMetadata(Map<String, String> versionMetadata) {
        this.versionMetadata = versionMetadata != null ? new HashMap<>(versionMetadata) : null;
    }

    public String getFullName() {
        return system.toLowerCase() + ":" + name + ":" + version;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        Package aPackage = (Package) o;
        return Objects.equals(name, aPackage.name) &&
                Objects.equals(system, aPackage.system) &&
                Objects.equals(version, aPackage.version) &&
                Objects.equals(scope, aPackage.scope);
    }

    @Override
    public int hashCode() {
        return Objects.hash(name, system, version, scope);
    }

    @Override
    public String toString() {
        return getFullName();
    }
}