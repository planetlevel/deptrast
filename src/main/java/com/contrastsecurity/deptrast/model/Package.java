package com.contrastsecurity.deptrast.model;

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

    public Package(String system, String name, String version) {
        this(system, name, version, "compile");  // Default to compile scope
    }

    public Package(String system, String name, String version, String scope) {
        this.system = system;
        this.name = name;
        this.version = version;
        this.scope = scope != null ? scope : "compile";
        this.scopeReason = null;
        this.winningVersion = null;
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