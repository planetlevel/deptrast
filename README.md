# Deptrast

[![Java CI with Maven](https://github.com/planetlevel/deptrast/actions/workflows/build.yml/badge.svg)](https://github.com/planetlevel/deptrast/actions/workflows/build.yml)

**The ultimate dependency tree converter, enhancer, and streamliner**

Deptrast will take whatever dependency information you have, from just about any source, and make it into what you need.  Make an SBOM anytime, you don't have to run a build!  Live your life.

 ✅ pom.xml -> Full ASCII Tree with all transitive dependencies
 
 ✅ SBOM with only root dependencies and no dependency graph -> Fully awesome SBOM
 
 ✅ Random list of jar files -> SBOM
 
 ✅ requirements.txt -> Maven-style text output
 
 ✅ List of components from runtime analysis with no dependency graph -> Fully awesome SBOM
 
 ✅ Etc...

Security folks will want to detect exactly what components are actually running in production! And there are many tools that will scan deployed systems or monitor them at runtime -- but they often just give you a flat list with no dependency tree information. That makes it difficult to fix problems. Fortunately, deptrast can unscramble runtime dependencies and organize them into something very close to the original build configuration.  And probably more accurate!

![Example Dependency Tree](example.png)

## Features

### Input Formats
- **Flat list** - Runtime dependency lists (system:name:version per line)
- **Maven pom.xml** - Parse Maven project dependencies (skips test scope)
- **Gradle** - Parse build.gradle and build.gradle.kts files
- **Python requirements.txt** - Parse Python dependencies
- **CycloneDX SBOM** - Parse existing SBOM files

### Output Formats
- **ASCII Tree** - Unicode tree visualization with root indicators (🔴)
- **Maven dependency:tree** - Compatible with Maven's format
- **CycloneDX SBOM** - Generate or enhance SBOM JSON (v1.6)

### Core Capabilities
- Constructs complete dependency graphs using the deps.dev REST API
- Reconciles declared versions with actual runtime versions (handles Maven's dependency resolution)
- Identifies minimal set of root dependencies using strict version matching
- Supports multiple package ecosystems (Maven, NPM, PyPI)
- **SBOM Enhancement** - When input and output are both SBOM, preserves original metadata and adds dependency graph

## Example Use

> java -jar target/deptrast-2.0.jar test-data/libraries.txt -

## Requirements

- Java 11 or higher
- Maven for building the project

## Project Security

See [SECURITY.md](SECURITY.md) for information about the project's security policy, vulnerability reporting, and best practices. For setup instructions for security scanning, including how to configure the NVD API key for dependency checks, see [SECURITY-SETUP.md](docs/SECURITY-SETUP.md).

## Building the Project

```bash
mvn clean package
```

This will create an executable JAR file as `target/deptrast-2.0.0.jar`.

## Usage

```bash
deptrast <input-file> <output-file> [options]
```

### Required Arguments

- `<input-file>` - Input file path
- `<output-file>` - Output file path (use `"-"` for stdout)

### Input Options

- `--iformat=<format>` - Input format (default: auto)
  - `auto` - Auto-detect from file extension
  - `flat` - Flat list (system:name:version per line)
  - `pom` - Maven pom.xml
  - `gradle` - Gradle build.gradle / build.gradle.kts
  - `pypi` - Python requirements.txt
  - `sbom` - CycloneDX SBOM JSON

- `--itype=<type>` - Input type (default: smart)
  - `all` - All dependencies (find roots by analysis)
  - `roots` - Root dependencies (fetch transitive deps from API)
  - `smart` - Auto-detect based on format (pom/gradle/pypi→roots, flat/sbom→all)

### Output Options

- `--oformat=<format>` - Output format (default: tree)
  - `tree` - ASCII tree with unicode characters
  - `maven` - Maven dependency:tree format
  - `sbom` - CycloneDX 1.6 SBOM JSON

- `--otype=<type>` - Output type (default: all)
  - `all` - All packages (roots + transitive dependencies)
  - `roots` - Root packages only

- `--project-name=<name>` - Project name for root node (tree/maven output)

### Other Options

- `--verbose`, `-v` - Enable verbose logging

### Input File Formats

#### Flat List Format
Each line should contain a package in the format: `system:name:version`

- Maven packages: `maven:groupId:artifactId:version`
- NPM packages: `npm:packageName:version`
- PyPI packages: `pypi:packageName:version`

Example:
```
maven:org.springframework.boot:spring-boot-starter-web:3.1.0
maven:com.google.guava:guava:31.1-jre
npm:react:18.2.0
npm:express:4.18.2
pypi:requests:2.28.1
```

Lines starting with `#` are treated as comments and ignored.

#### Maven pom.xml
Standard Maven pom.xml files. Deptrast extracts dependencies from `<dependencies>` blocks, automatically skipping:
- Test-scoped dependencies
- Dependencies with Maven variable versions (e.g., `${spring.version}`)

#### Gradle build.gradle / build.gradle.kts
Gradle build files in Groovy or Kotlin syntax. Supported formats:
```gradle
implementation 'group:artifact:version'
implementation "group:artifact:version"
implementation group: 'group', name: 'artifact', version: 'version'
```
Test dependencies (testImplementation, testCompile) are automatically skipped.

#### Python requirements.txt
Standard Python requirements files. Supports version operators:
```
requests==2.28.1
flask>=2.0.0
numpy~=1.23.0
```

#### CycloneDX SBOM
CycloneDX SBOM JSON files (v1.x). Deptrast extracts components via purl (Package URL) parsing.

### Examples

**Basic usage (tree output to stdout):**
```bash
deptrast libraries.txt -
```

**Generate SBOM:**
```bash
deptrast libraries.txt output.sbom --oformat=sbom
```

**Maven format to file:**
```bash
deptrast libraries.txt deps.txt --oformat=maven --project-name=my-app
```

**Verbose output:**
```bash
deptrast libraries.txt - --verbose
```

**Convert SBOM to tree:**
```bash
deptrast input.sbom - --iformat=sbom
```

**Analyze pom.xml:**
```bash
deptrast pom.xml - --iformat=pom --itype=roots
```

**Python requirements.txt to SBOM:**
```bash
deptrast requirements.txt output.sbom --iformat=pypi --oformat=sbom
```

**Analyze Gradle build file:**
```bash
deptrast build.gradle - --iformat=gradle --itype=roots
```

**Enhance existing SBOM with dependencies:**
```bash
deptrast input.sbom enhanced.sbom --iformat=sbom --oformat=sbom
```
This preserves all original SBOM metadata (tools, timestamps, custom fields) and adds/updates the dependencies section with computed dependency relationships.

**Generate SBOM with only root dependencies:**
```bash
deptrast libraries.txt roots-only.sbom --oformat=sbom --otype=roots
```
Outputs only the root packages in the SBOM, excluding all transitive dependencies.

### How It Works

Deptrast analyzes packages in the input file, fetches their complete dependency graphs from deps.dev, reconciles versions with actual runtime versions, identifies the minimal set of root dependencies, and builds an accurate dependency tree. Root dependencies are marked with a red dot (🔴) for easy identification.

**Input Type Modes:**
- `--itype=all` - When you provide a complete list of runtime dependencies (e.g., from a flat file or SBOM), deptrast identifies which are roots
- `--itype=roots` - When you provide just root dependencies (e.g., from pom.xml or requirements.txt), deptrast fetches all transitive dependencies
- `--itype=smart` - Auto-detects the appropriate mode based on input format

