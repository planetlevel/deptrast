package com.contrastsecurity.deptrast.model;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Class to hold detailed dependency information for a package across all versions
 */
public class PackageDependencyInfo {
    private final String baseName;
    private final List<Package> versions;
    private final Map<String, Set<DependencyPath>> dependencyPaths;
    private boolean hasReverseDependencies;
    
    /**
     * Create a new package dependency info object
     * 
     * @param baseName The base name of the package (system:name)
     */
    public PackageDependencyInfo(String baseName) {
        this.baseName = baseName;
        this.versions = new ArrayList<>();
        this.dependencyPaths = new HashMap<>();
        this.hasReverseDependencies = false;
    }
    
    /**
     * Add a version of this package
     * 
     * @param pkg The package version
     */
    public void addVersion(Package pkg) {
        versions.add(pkg);
    }
    
    /**
     * Add a dependency path showing how this package is included
     * 
     * @param parent The package that depends on this package
     * @param child The specific version of this package that is included
     */
    public void addDependencyPath(Package parent, Package child) {
        String parentKey = parent.getFullName();
        Set<DependencyPath> paths = dependencyPaths.computeIfAbsent(parentKey, k -> new HashSet<>());
        paths.add(new DependencyPath(parent, child));
    }
    
    /**
     * Get all versions of this package
     * 
     * @return List of all package versions
     */
    public List<Package> getVersions() {
        return versions;
    }
    
    /**
     * Get all dependency paths by which this package is included
     * 
     * @return Map of parent package keys to dependency paths
     */
    public Map<String, Set<DependencyPath>> getDependencyPaths() {
        return dependencyPaths;
    }
    
    /**
     * Check if this package has any versions with reverse dependencies
     * 
     * @return true if any version of this package is a dependency of another package
     */
    public boolean hasReverseDependencies() {
        return hasReverseDependencies;
    }
    
    /**
     * Set whether this package has reverse dependencies
     * 
     * @param hasReverseDependencies true if the package has reverse dependencies
     */
    public void setHasReverseDependencies(boolean hasReverseDependencies) {
        this.hasReverseDependencies = hasReverseDependencies;
    }
    
    /**
     * Get the base name of this package
     * 
     * @return The base name (system:name)
     */
    public String getBaseName() {
        return baseName;
    }
    
    /**
     * Check if there are version conflicts
     * 
     * @return true if there are multiple versions of this package
     */
    public boolean hasVersionConflicts() {
        return versions.size() > 1;
    }
    
    /**
     * Class to represent a dependency path
     */
    public static class DependencyPath {
        private final Package parent;
        private final Package child;
        
        public DependencyPath(Package parent, Package child) {
            this.parent = parent;
            this.child = child;
        }
        
        public Package getParent() {
            return parent;
        }
        
        public Package getChild() {
            return child;
        }
        
        @Override
        public boolean equals(Object obj) {
            if (this == obj) return true;
            if (obj == null || getClass() != obj.getClass()) return false;
            DependencyPath that = (DependencyPath) obj;
            return parent.getFullName().equals(that.parent.getFullName()) && 
                   child.getFullName().equals(that.child.getFullName());
        }
        
        @Override
        public int hashCode() {
            return 31 * parent.getFullName().hashCode() + child.getFullName().hashCode();
        }
    }
}