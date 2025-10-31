package com.contrastsecurity.deptrast.constants;

/**
 * Supported package management systems.
 */
public enum PackageSystem {
    MAVEN("maven"),
    NPM("npm"),
    PYPI("pypi"),
    NUGET("nuget"),
    GO("go"),
    CARGO("cargo");

    private final String value;

    PackageSystem(String value) {
        this.value = value;
    }

    public String getValue() {
        return value;
    }

    /**
     * Get PackageSystem from string value.
     *
     * @param value String representation
     * @return PackageSystem enum or null if not found
     */
    public static PackageSystem fromString(String value) {
        if (value == null) {
            return null;
        }
        for (PackageSystem system : values()) {
            if (system.value.equalsIgnoreCase(value)) {
                return system;
            }
        }
        return null;
    }

    @Override
    public String toString() {
        return value;
    }
}
