# Deptrast

[![Java CI with Maven](https://github.com/planetlevel/deptrast/actions/workflows/build.yml/badge.svg)](https://github.com/planetlevel/deptrast/actions/workflows/build.yml)

A Java application that constructs a useful *security* dependency tree from a list of components observed at runtime.

![Example Dependency Tree](example.png)
NOTE: the error is expected as the project contains a private test-project.jar which can't be looked up.

## Features

- Reads a flat list of all dependencies from a text file
- Fetches dependency information from the deps.dev REST API
- Identifies root dependencies (packages that have no parents)
- Builds a complete dependency graph with parent-child relationships
- Supports output in standard tree format or Maven dependency:tree format
- Uses concurrent API requests for better performance
- Optimized to avoid redundant API calls through intelligent caching
- Supports multiple package ecosystems (Maven, NPM, etc.)

## Example Use

> java -jar target/deptrast-1.0.jar test-data/libraries.txt

## Security

Imagine your build has these root dependencies which require these transitive dependencies...
* lib1 -> depv1
* lib2 -> depv2
* lib3 -> depv3

But build systems are crazy, and it resolves them all to depv3 in the built software.
* lib1 -> depv3
* lib2 -> depv3
* lib3 -> depv3
    
The actual dep chosen by the build system could be depv1, depv2, depv3, or sometimes a different version not in the build anywhere.   Deptrast builds the second tree above using the actual library observed in the running software, so that any vulnerabilities in depv3 will be reported against lib1, lib2, and lib3.

 If you use deptrast to report vulnerabilities, you should realize that you won't see vulnerabilities in depv1 or depv2. This is probably what you want, since you're not actually running those versions.  Still, it's possible that if a change is made to the project that upsets the dependency calculus, some other library could be chosen. For example, imagine lib3 gets updated and removes the dependency on depv3, then the build system might choose choose depv2 for lib1 and lib2.  And if depv2 has a vulnerability it might now be in production, ironically because you updated lib3.

## Requirements

- Java 11 or higher
- Maven for building the project

## Security

See [SECURITY.md](SECURITY.md) for information about the project's security policy, vulnerability reporting, and best practices.

## Building the Project

```bash
mvn clean package
```

This will create an executable JAR file as `target/deptrast-1.0.jar`.

## Usage

```bash
java -jar target/deptrast-1.0.jar <input-file> [max-depth] [--maven-format=<root-project>] [--detailed-report=<output-file>] [--sbom=<output-file>] [--verbose|-v]
```

- `<input-file>`: Path to a file containing all your project's packages (required)
- `[max-depth]`: Optional maximum depth for dependency resolution (default: 25)
- `[--maven-format=<root-project>]`: Optional flag to output in Maven dependency:tree format with the specified root project name
- `[--detailed-report=<output-file>]`: Generate a detailed report of dependency paths and version conflicts
- `[--sbom=<output-file>]`: Generate CycloneDX 1.6 SBOM JSON file with dependency information
- `[--verbose|-v]`: Enable verbose logging output (disabled by default)

### Input File Format

Each line in the input file should contain a package in the format: `system:name:version`

For Maven packages: `maven:groupId:artifactId:version`
For NPM packages: `npm:packageName:version`

Example:
```
maven:org.springframework.boot:spring-boot-starter-web:3.1.0
maven:com.google.guava:guava:31.1-jre
npm:react:18.2.0
npm:express:4.18.2
```

Lines starting with `#` are treated as comments and ignored.

### Example

```bash
java -jar target/deptrast-1.0.jar libraries.txt
```

This will analyze all packages in `libraries.txt`, determine the root dependencies, and build a dependency tree. Root dependencies will be marked with a red dot (🔴) for easy identification.

### Maven Dependency:tree Format

To output the dependency tree in Maven's format:

```bash
java -jar target/deptrast-1.0.jar libraries.txt --maven-format=my-project
```

This will generate output compatible with Maven's `dependency:tree` command, using 'my-project' as the root node. The Maven format doesn't include the red dot indicators and follows Maven's standard output format.

