package com.contrastsecurity.deptrast.model;

import java.util.Objects;

/**
 * Represents a software package (immutable value object)
 *
 * Dependency relationships are tracked in PackageCache, not in Package objects.
 */
public class Package {
    private final String name;
    private final String system;
    private final String version;

    public Package(String system, String name, String version) {
        this.system = system;
        this.name = name;
        this.version = version;
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
                Objects.equals(version, aPackage.version);
    }

    @Override
    public int hashCode() {
        return Objects.hash(name, system, version);
    }

    @Override
    public String toString() {
        return getFullName();
    }
}