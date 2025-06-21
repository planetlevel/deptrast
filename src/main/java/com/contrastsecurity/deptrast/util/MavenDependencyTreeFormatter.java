package com.contrastsecurity.deptrast.util;

import com.contrastsecurity.deptrast.model.DependencyNode;
import com.contrastsecurity.deptrast.model.Package;

import java.util.*;

/**
 * Utility class for formatting dependency trees in Maven dependency:tree format
 */
public class MavenDependencyTreeFormatter {

    /**
     * Format the dependency tree in Maven dependency:tree format
     *
     * @param rootProject name of the root project
     * @param rootPackages list of root packages
     * @return the formatted dependency tree
     */
    public static String formatMavenDependencyTree(String rootProject, List<DependencyNode> rootPackages) {
        StringBuilder result = new StringBuilder();
        result.append("[INFO] --- dependency:tree ---\n");
        result.append("[INFO] ").append(rootProject).append("\n");
        
        // Track what dependencies have already been included to avoid duplicates
        Set<String> processedDependencies = new HashSet<>();
        
        // Process each root node
        for (int i = 0; i < rootPackages.size(); i++) {
            DependencyNode rootNode = rootPackages.get(i);
            boolean isLast = (i == rootPackages.size() - 1);
            String rootPrefix = isLast ? "[INFO] \\- " : "[INFO] +- ";
            
            // Format root node
            result.append(rootPrefix).append(formatMavenPackage(rootNode.getPackage())).append("\n");
            
            // Process children
            processChildren(rootNode, result, "[INFO] ", isLast ? "   " : "|  ", processedDependencies);
        }
        
        return result.toString();
    }
    
    /**
     * Process children of a node and format them recursively
     */
    private static void processChildren(DependencyNode node, StringBuilder result, 
                                     String basePrefix, String indent,
                                     Set<String> processedDependencies) {
        List<DependencyNode> children = node.getChildren();
        if (children.isEmpty()) {
            return;
        }
        
        // Sort children for consistency
        List<DependencyNode> sortedChildren = new ArrayList<>(children);
        sortedChildren.sort(Comparator.comparing(n -> n.getPackage().getFullName()));
        
        for (int i = 0; i < sortedChildren.size(); i++) {
            DependencyNode child = sortedChildren.get(i);
            boolean isLastChild = (i == sortedChildren.size() - 1);
            String pkg = child.getPackage().getFullName();
            
            // Format the current child
            String childPrefix = basePrefix + indent;
            String nodeMarker = isLastChild ? "\\- " : "+- ";
            result.append(childPrefix).append(nodeMarker).append(formatMavenPackage(child.getPackage())).append("\n");
            
            // Process the child's children only if we haven't seen this dependency before
            if (!processedDependencies.contains(pkg)) {
                processedDependencies.add(pkg);
                String newIndent = isLastChild ? "   " : "|  ";
                processChildren(child, result, childPrefix, newIndent, processedDependencies);
            }
        }
    }
    
    /**
     * Format a package in Maven format
     * 
     * @param pkg the package to format
     * @return the formatted package string
     */
    private static String formatMavenPackage(Package pkg) {
        String system = pkg.getSystem().toLowerCase();
        String scope = "compile";
        
        // Extract group and artifact IDs from name for Maven packages
        String name = pkg.getName();
        
        if ("maven".equals(system)) {
            String[] parts = name.split(":");
            if (parts.length >= 2) {
                return parts[0] + ":" + parts[1] + ":jar:" + pkg.getVersion() + ":" + scope;
            } else {
                // If the name doesn't have the expected format, use it as is
                return name + ":jar:" + pkg.getVersion() + ":" + scope;
            }
        } else {
            // For non-Maven packages, still use Maven format but include the system
            return system + ":" + name + ":jar:" + pkg.getVersion() + ":" + scope;
        }
    }
}