package com.contrastsecurity.deptrast.service;

import com.contrastsecurity.deptrast.model.Package;
import com.contrastsecurity.deptrast.model.PackageDependencyInfo;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * A shared cache for package dependencies to avoid redundant API calls
 */
public class PackageCache {
    private static PackageCache instance;
    
    private final Map<String, List<Package>> dependencyCache;
    
    private final Map<String, Package> packageCache;
    
    private final Map<String, Set<Package>> reverseDependencyCache;
    
    private PackageCache() {
        this.dependencyCache = new HashMap<>();
        this.packageCache = new HashMap<>();
        this.reverseDependencyCache = new HashMap<>();
    }
    
    /**
     * Get the singleton instance of the package cache
     */
    public static synchronized PackageCache getInstance() {
        if (instance == null) {
            instance = new PackageCache();
        }
        return instance;
    }
    
    /**
     * Store package dependencies in the cache
     * 
     * @param pkg the package
     * @param dependencies the dependencies of the package
     */
    public void cacheDependencies(Package pkg, List<Package> dependencies) {
        String key = pkg.getFullName();
        dependencyCache.put(key, dependencies);
        
        packageCache.put(key, pkg);
        
        for (Package dep : dependencies) {
            String depKey = dep.getFullName();
            packageCache.put(depKey, dep);
            
            reverseDependencyCache.computeIfAbsent(depKey, k -> new HashSet<>()).add(pkg);
        }
    }
    
    /**
     * Check if dependencies for a package are cached
     * 
     * @param pkg the package to check
     * @return true if the dependencies are cached, false otherwise
     */
    public boolean hasCachedDependencies(Package pkg) {
        return dependencyCache.containsKey(pkg.getFullName());
    }
    
    /**
     * Get cached dependencies for a package
     * 
     * @param pkg the package to get dependencies for
     * @return the list of dependencies, or null if not cached
     */
    public List<Package> getCachedDependencies(Package pkg) {
        return dependencyCache.get(pkg.getFullName());
    }
    
    /**
     * Get a cached package by its full name
     * 
     * @param fullName the full name of the package (system:name:version)
     * @return the cached package, or null if not cached
     */
    public Package getCachedPackage(String fullName) {
        return packageCache.get(fullName);
    }
    
    /**
     * Add a package to the cache
     * 
     * @param pkg the package to cache
     */
    public void cachePackage(Package pkg) {
        packageCache.put(pkg.getFullName(), pkg);
    }
    
    /**
     * Clear the cache
     */
    public void clear() {
        dependencyCache.clear();
        packageCache.clear();
        reverseDependencyCache.clear();
    }
    
    /**
     * Get the number of packages in the cache
     */
    public int size() {
        return packageCache.size();
    }
    
    /**
     * Get all package keys in the cache
     */
    public Set<String> getAllPackageKeys() {
        return packageCache.keySet();
    }
    
    /**
     * Check if any packages depend on the given package
     * 
     * @param pkg the package to check
     * @return true if the package is a dependency of another package
     */
    public boolean hasReverseDependencies(Package pkg) {
        Set<Package> reverseDeps = reverseDependencyCache.get(pkg.getFullName());
        return reverseDeps != null && !reverseDeps.isEmpty();
    }
    
    /**
     * Get all packages that depend on the given package
     * 
     * @param pkg the package to get reverse dependencies for
     * @return set of packages that depend on this package, or empty set if none
     */
    public Set<Package> getReverseDependencies(Package pkg) {
        Set<Package> reverseDeps = reverseDependencyCache.get(pkg.getFullName());
        return reverseDeps != null ? reverseDeps : new HashSet<>();
    }
    
    /**
     * Get all packages that depend on any version of the given package
     * 
     * @param pkg the package to get reverse dependencies for
     * @return set of packages that depend on any version of this package
     */
    public Set<Package> getAllVersionReverseDependencies(Package pkg) {
        String baseName = getBasePackageName(pkg);
        Set<Package> result = new HashSet<>();
        
        // Find all versions of this package
        for (Package cachedPkg : packageCache.values()) {
            if (getBasePackageName(cachedPkg).equals(baseName)) {
                // For each version, get its reverse dependencies
                Set<Package> reverseDeps = getReverseDependencies(cachedPkg);
                if (reverseDeps != null) {
                    result.addAll(reverseDeps);
                }
            }
        }
        
        return result;
    }
    
    /**
     * Get all versions of a package that are tracked in the cache
     * 
     * @param pkg a package to find other versions of
     * @return list of all versions of the package
     */
    public List<Package> getAllVersions(Package pkg) {
        String baseName = getBasePackageName(pkg);
        List<Package> versions = new ArrayList<>();
        
        for (Package cachedPkg : packageCache.values()) {
            if (getBasePackageName(cachedPkg).equals(baseName)) {
                versions.add(cachedPkg);
            }
        }
        
        return versions;
    }
    
    /**
     * Get detailed dependency information including version conflicts
     * 
     * @return a map where keys are base package names and values are detailed dependency info
     */
    public Map<String, PackageDependencyInfo> getDetailedDependencyInfo() {
        Map<String, PackageDependencyInfo> result = new HashMap<>();
        Map<String, List<Package>> packagesByBaseName = new HashMap<>();
        
        for (Package pkg : packageCache.values()) {
            String baseName = getBasePackageName(pkg);
            packagesByBaseName.computeIfAbsent(baseName, k -> new ArrayList<>()).add(pkg);
        }
        
        // Create detailed dependency info for each base name
        for (Map.Entry<String, List<Package>> entry : packagesByBaseName.entrySet()) {
            String baseName = entry.getKey();
            List<Package> versions = entry.getValue();
            
            PackageDependencyInfo info = new PackageDependencyInfo(baseName);
            
            for (Package version : versions) {
                info.addVersion(version);
                
                Set<Package> reverseDeps = getReverseDependencies(version);
                for (Package parent : reverseDeps) {
                    info.addDependencyPath(parent, version);
                }
            }
            
            boolean hasReverseDependencies = false;
            for (Package version : versions) {
                if (hasReverseDependencies(version)) {
                    hasReverseDependencies = true;
                    break;
                }
            }
            info.setHasReverseDependencies(hasReverseDependencies);
            
            result.put(baseName, info);
        }
        
        return result;
    }
    
    /**
     * Get all packages that have no reverse dependencies
     * (packages that are not dependencies of any other package)
     * 
     * This implementation is version-flexible, meaning that if ANY version of a package
     * has reverse dependencies, then ALL versions of that package are considered to have
     * reverse dependencies and thus none are considered "root" packages.
     * 
     * @return set of packages with no reverse dependencies
     */
    public Set<Package> getPackagesWithNoReverseDependencies() {
        Set<Package> result = new HashSet<>();
        Map<String, Boolean> baseNameHasReverseDeps = new HashMap<>();
        Map<String, List<Package>> packagesByBaseName = new HashMap<>();
        
        for (Package pkg : packageCache.values()) {
            String baseName = getBasePackageName(pkg);
            packagesByBaseName.computeIfAbsent(baseName, k -> new ArrayList<>()).add(pkg);
        }
        
        for (Map.Entry<String, List<Package>> entry : packagesByBaseName.entrySet()) {
            String baseName = entry.getKey();
            List<Package> versions = entry.getValue();
            
            boolean anyVersionHasReverseDeps = false;
            for (Package pkg : versions) {
                if (hasReverseDependencies(pkg)) {
                    anyVersionHasReverseDeps = true;
                    break;
                }
            }
            
            baseNameHasReverseDeps.put(baseName, anyVersionHasReverseDeps);
        }
        
        for (Package pkg : packageCache.values()) {
            String baseName = getBasePackageName(pkg);
            if (Boolean.FALSE.equals(baseNameHasReverseDeps.get(baseName))) {
                result.add(pkg);
            }
        }
        
        return result;
    }
    
    /**
     * Get the base name of a package (system:name without version)
     * 
     * @param pkg the package
     * @return the base name of the package
     */
    private String getBasePackageName(Package pkg) {
        return pkg.getSystem().toLowerCase() + ":" + pkg.getName();
    }
}