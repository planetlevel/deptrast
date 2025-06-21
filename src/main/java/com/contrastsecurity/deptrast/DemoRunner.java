package com.contrastsecurity.deptrast;

import com.contrastsecurity.deptrast.model.Package;
import com.contrastsecurity.deptrast.model.DependencyNode;
import com.contrastsecurity.deptrast.model.DepsDevResponse;
import com.google.gson.Gson;

import java.util.*;

/**
 * Demo runner with hardcoded data to show the concept
 */
public class DemoRunner {

    public static void main(String[] args) {
        System.out.println("Dependency Tree Analysis Demo");
        System.out.println("---------------------------------");
        
        // Create a set of artificial packages to simulate what we would get from deps.dev API
        Map<String, Package> packagesMap = new HashMap<>();
        
        // Create the test packages from the libraries.txt
        createTestPackages(packagesMap);
        
        // Simulate the relationships between packages
        setupTestDependencies(packagesMap);
        
        // Identify root packages (those with no parents)
        List<Package> rootPackages = new ArrayList<>();
        for (Package pkg : packagesMap.values()) {
            if (pkg.isRoot()) {
                rootPackages.add(pkg);
                System.out.println("Identified root package: " + pkg.getFullName());
            }
        }
        
        System.out.println("\nFound " + rootPackages.size() + " root dependencies");
        
        // Build dependency tree starting from the root packages
        List<DependencyNode> rootNodes = new ArrayList<>();
        for (Package rootPkg : rootPackages) {
            DependencyNode node = new DependencyNode(rootPkg, 0);
            buildTree(node, 0, 3); // Limit depth to 3 for demo
            rootNodes.add(node);
        }
        
        // Print the dependency trees
        System.out.println("\nDependency Tree:");
        for (DependencyNode rootNode : rootNodes) {
            System.out.println(rootNode.getTreeRepresentation());
        }
    }
    
    private static void createTestPackages(Map<String, Package> packagesMap) {
        // Create spring-petclinic as the root package
        Package springPetClinic = new Package("maven", "org.springframework.samples:spring-petclinic", "1.5.1");
        packagesMap.put(springPetClinic.getFullName(), springPetClinic);
        
        // Create some direct dependencies
        addPackage(packagesMap, "maven", "org.springframework.boot:spring-boot-starter-actuator", "1.5.4.RELEASE");
        addPackage(packagesMap, "maven", "org.springframework.boot:spring-boot-starter-web", "1.5.4.RELEASE");
        addPackage(packagesMap, "maven", "org.springframework.boot:spring-boot-starter-data-jpa", "1.5.4.RELEASE");
        addPackage(packagesMap, "maven", "org.springframework.boot:spring-boot-starter-cache", "1.5.4.RELEASE");
        addPackage(packagesMap, "maven", "org.springframework.boot:spring-boot-starter-thymeleaf", "1.5.4.RELEASE");
        addPackage(packagesMap, "maven", "org.springframework.boot:spring-boot-starter-test", "1.5.4.RELEASE");
        addPackage(packagesMap, "maven", "org.springframework:spring-orm", "4.3.9.RELEASE");
        
        // Create some transitive dependencies
        addPackage(packagesMap, "maven", "org.springframework.boot:spring-boot-starter", "1.5.4.RELEASE");
        addPackage(packagesMap, "maven", "org.springframework.boot:spring-boot-starter-logging", "1.5.4.RELEASE");
        addPackage(packagesMap, "maven", "ch.qos.logback:logback-classic", "1.1.11");
        addPackage(packagesMap, "maven", "ch.qos.logback:logback-core", "1.1.11");
        addPackage(packagesMap, "maven", "org.slf4j:slf4j-api", "1.7.25");
        addPackage(packagesMap, "maven", "org.springframework:spring-context", "4.3.9.RELEASE");
        addPackage(packagesMap, "maven", "org.hibernate:hibernate-core", "5.0.4.Final");
    }
    
    private static Package addPackage(Map<String, Package> packagesMap, String system, String name, String version) {
        Package pkg = new Package(system, name, version);
        packagesMap.put(pkg.getFullName(), pkg);
        return pkg;
    }
    
    private static void setupTestDependencies(Map<String, Package> packagesMap) {
        // Set up the relationships for spring-petclinic
        Package springPetClinic = packagesMap.get("maven:org.springframework.samples:spring-petclinic:1.5.1");
        addDependency(packagesMap, springPetClinic, "org.springframework.boot:spring-boot-starter-actuator", "1.5.4.RELEASE");
        addDependency(packagesMap, springPetClinic, "org.springframework.boot:spring-boot-starter-web", "1.5.4.RELEASE");
        addDependency(packagesMap, springPetClinic, "org.springframework.boot:spring-boot-starter-data-jpa", "1.5.4.RELEASE");
        addDependency(packagesMap, springPetClinic, "org.springframework.boot:spring-boot-starter-cache", "1.5.4.RELEASE");
        addDependency(packagesMap, springPetClinic, "org.springframework.boot:spring-boot-starter-thymeleaf", "1.5.4.RELEASE");
        addDependency(packagesMap, springPetClinic, "org.springframework:spring-orm", "4.3.9.RELEASE");
        
        // Set up relationships for spring-boot-starter-actuator
        Package actuator = packagesMap.get("maven:org.springframework.boot:spring-boot-starter-actuator:1.5.4.RELEASE");
        addDependency(packagesMap, actuator, "org.springframework.boot:spring-boot-starter", "1.5.4.RELEASE");
        
        // Set up relationships for spring-boot-starter
        Package starter = packagesMap.get("maven:org.springframework.boot:spring-boot-starter:1.5.4.RELEASE");
        addDependency(packagesMap, starter, "org.springframework.boot:spring-boot-starter-logging", "1.5.4.RELEASE");
        addDependency(packagesMap, starter, "org.springframework:spring-context", "4.3.9.RELEASE");
        
        // Set up relationships for spring-boot-starter-logging
        Package starterLogging = packagesMap.get("maven:org.springframework.boot:spring-boot-starter-logging:1.5.4.RELEASE");
        addDependency(packagesMap, starterLogging, "ch.qos.logback:logback-classic", "1.1.11");
        
        // Set up relationships for logback-classic
        Package logbackClassic = packagesMap.get("maven:ch.qos.logback:logback-classic:1.1.11");
        addDependency(packagesMap, logbackClassic, "ch.qos.logback:logback-core", "1.1.11");
        addDependency(packagesMap, logbackClassic, "org.slf4j:slf4j-api", "1.7.25");
        
        // Set up relationships for spring-boot-starter-data-jpa
        Package dataJpa = packagesMap.get("maven:org.springframework.boot:spring-boot-starter-data-jpa:1.5.4.RELEASE");
        addDependency(packagesMap, dataJpa, "org.hibernate:hibernate-core", "5.0.4.Final");
    }
    
    private static void addDependency(Map<String, Package> packagesMap, Package parent, String depName, String depVersion) {
        Package dependency = packagesMap.get("maven:" + depName + ":" + depVersion);
        if (dependency != null) {
            parent.addDependency(dependency);
        }
    }
    
    private static void buildTree(DependencyNode node, int depth, int maxDepth) {
        if (depth >= maxDepth) {
            return;
        }
        
        Package pkg = node.getPackage();
        for (Package dependency : pkg.getDependencies()) {
            DependencyNode childNode = new DependencyNode(dependency, depth + 1);
            node.addChild(childNode);
            buildTree(childNode, depth + 1, maxDepth);
        }
    }
}