package com.contrastsecurity.deptrast.model;

import java.util.ArrayList;
import java.util.List;

/**
 * Represents a node in the dependency graph (not a tree - nodes can be shared)
 */
public class DependencyNode {
    private static final String RED_DOT = "🔴";
    private Package pkg;
    private List<DependencyNode> children;
    private boolean isRoot;

    public DependencyNode(Package pkg) {
        this(pkg, false);
    }

    public DependencyNode(Package pkg, boolean isRoot) {
        this.pkg = pkg;
        this.children = new ArrayList<>();
        this.isRoot = isRoot;
    }

    public Package getPackage() {
        return pkg;
    }
    
    public void setPackage(Package pkg) {
        this.pkg = pkg;
    }

    public List<DependencyNode> getChildren() {
        return children;
    }

    public void addChild(DependencyNode child) {
        // Avoid duplicates
        if (!this.children.contains(child)) {
            this.children.add(child);
        }
    }
    
    public void markAsRoot() {
        this.isRoot = true;
    }
    
    public boolean isRoot() {
        return isRoot;
    }

    /**
     * Generates a tree representation of the dependency (depth computed on-the-fly)
     */
    public String getTreeRepresentation() {
        StringBuilder builder = new StringBuilder();
        printTree(builder, "", true, 0);
        return builder.toString();
    }

    private void printTree(StringBuilder builder, String prefix, boolean isLast, int depth) {
        builder.append(prefix);
        // Skip showing project root node name
        if (!pkg.getSystem().equals("project")) {
            builder.append(isLast ? "└── " : "├── ");
            builder.append(isRoot ? RED_DOT + " " : "").append(pkg.getFullName()).append("\n");
        }

        for (int i = 0; i < children.size(); i++) {
            DependencyNode child = children.get(i);
            boolean lastChild = (i == children.size() - 1);
            child.printTree(builder, prefix + (isLast ? "    " : "│   "), lastChild, depth + 1);
        }
    }
}