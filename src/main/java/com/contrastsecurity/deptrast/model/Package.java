package com.contrastsecurity.deptrast.model;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;

/**
 * Represents a software package with its dependencies
 */
public class Package {
    private String name;
    private String system;
    private String version;
    private List<Package> dependencies;
    // New: packages that depend on this package (parents)
    private Set<Package> parents;

    public Package(String system, String name, String version) {
        this.system = system;
        this.name = name;
        this.version = version;
        this.dependencies = new ArrayList<>();
        this.parents = new HashSet<>();
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

    public List<Package> getDependencies() {
        return dependencies;
    }

    public void addDependency(Package dependency) {
        if (!this.dependencies.contains(dependency)) {
            this.dependencies.add(dependency);
            // Add the reverse relationship
            dependency.addParent(this);
        }
    }

    public Set<Package> getParents() {
        return parents;
    }

    public void addParent(Package parent) {
        this.parents.add(parent);
    }

    public boolean isRoot() {
        return parents.isEmpty();
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