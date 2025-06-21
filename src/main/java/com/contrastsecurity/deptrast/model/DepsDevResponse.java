package com.contrastsecurity.deptrast.model;

import java.util.List;
import java.util.Map;

/**
 * Model for deps.dev API response
 */
public class DepsDevResponse {
    private Version version;

    public Version getVersion() {
        return version;
    }

    public void setVersion(Version version) {
        this.version = version;
    }

    public static class Version {
        private List<Dependency> dependencies;

        public List<Dependency> getDependencies() {
            return dependencies;
        }

        public void setDependencies(List<Dependency> dependencies) {
            this.dependencies = dependencies;
        }
    }

    public static class Dependency {
        private String name;
        private String system;
        private String version;
        private Map<String, String> metadata;

        public String getName() {
            return name;
        }

        public void setName(String name) {
            this.name = name;
        }

        public String getSystem() {
            return system;
        }

        public void setSystem(String system) {
            this.system = system;
        }

        public String getVersion() {
            return version;
        }

        public void setVersion(String version) {
            this.version = version;
        }

        public Map<String, String> getMetadata() {
            return metadata;
        }

        public void setMetadata(Map<String, String> metadata) {
            this.metadata = metadata;
        }
    }
}