package com.contrastsecurity.deptrast.util;

import com.contrastsecurity.deptrast.model.Package;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;

/**
 * Utility class for parsing input files containing package information
 */
public class FileParser {
    private static final Logger logger = LoggerFactory.getLogger(FileParser.class);

    /**
     * Parse a file containing package information
     * Each line should be in the format: system:name:version
     * For example: maven:com.google.guava:guava:31.1-jre
     *
     * @param filePath path to the file
     * @return list of packages
     */
    public static List<Package> parsePackagesFromFile(String filePath) {
        List<Package> packages = new ArrayList<>();
        Path path = Paths.get(filePath);
        
        if (!Files.exists(path)) {
            logger.error("File not found: {}", filePath);
            return packages;
        }
        
        try (BufferedReader reader = new BufferedReader(new FileReader(filePath))) {
            String line;
            int lineNumber = 0;
            
            while ((line = reader.readLine()) != null) {
                lineNumber++;
                line = line.trim();
                
                // Skip empty lines and comments
                if (line.isEmpty() || line.startsWith("#")) {
                    continue;
                }
                
                try {
                    String[] parts = line.split(":");
                    if (parts.length < 3) {
                        logger.warn("Invalid format at line {}: {}. Expected system:name:version", lineNumber, line);
                        continue;
                    }
                    
                    String system = parts[0];
                    
                    if ("maven".equals(system)) {
                        // Format: maven:groupId:artifactId:version
                        if (parts.length >= 4) {
                            String name;
                            String version;
                            
                            // Handle Maven format correctly
                            if (parts.length == 4) {
                                // maven:groupId:artifactId:version
                                name = parts[1] + ":" + parts[2];
                                version = parts[3];
                            } else {
                                // Something is wrong with the format, try to recover
                                StringBuilder nameBuilder = new StringBuilder(parts[1]);
                                for (int i = 2; i < parts.length - 1; i++) {
                                    nameBuilder.append(":").append(parts[i]);
                                }
                                name = nameBuilder.toString();
                                version = parts[parts.length - 1];
                            }
                            
                            Package pkg = new Package(system, name, version);
                            packages.add(pkg);
                            logger.info("Added package: {}", pkg.getFullName());
                        } else {
                            logger.warn("Invalid Maven format at line {}: {}. Expected maven:groupId:artifactId:version", lineNumber, line);
                        }
                    } else if ("npm".equals(system)) {
                        // Format: npm:packageName:version
                        if (parts.length == 3) {
                            String name = parts[1];
                            String version = parts[2];
                            Package pkg = new Package(system, name, version);
                            packages.add(pkg);
                            logger.info("Added package: {}", pkg.getFullName());
                        } else {
                            logger.warn("Invalid npm format at line {}: {}. Expected npm:packageName:version", lineNumber, line);
                        }
                    } else {
                        logger.warn("Unsupported package system at line {}: {}", lineNumber, line);
                    }
                } catch (Exception e) {
                    logger.error("Error parsing line {}: {}", lineNumber, e.getMessage());
                }
            }
        } catch (IOException e) {
            logger.error("Error reading file {}: {}", filePath, e.getMessage());
        }
        
        return packages;
    }
}