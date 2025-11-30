# Deptrast

[![Java CI with Maven](https://github.com/planetlevel/deptrast/actions/workflows/build.yml/badge.svg)](https://github.com/planetlevel/deptrast/actions/workflows/build.yml)

**The ultimate dependency tree converter, enhancer, and streamliner**

Deptrast will take whatever dependency information you have, from just about any source, and make it into what you need.  Make an SBOM anytime, you don't have to run a build!  Live your life.

- [x] pom.xml -> Full ASCII Tree with all transitive dependencies
- [x] SBOM with only root dependencies and no dependency graph -> Fully awesome SBOM
- [x] Random list of jar files -> SBOM
- [x] requirements.txt -> Maven-style text output
- [x] List of components from runtime analysis with no dependency graph -> Fully awesome SBOM
- [x] Etc...

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

## Installation

Choose either Java or Python implementation - both provide the identical CLI interface.

### Java (Recommended)
```bash
# Download pre-built JAR from GitHub Releases
# https://github.com/planetlevel/deptrast/releases

# Or build from source
mvn clean package

# Create an alias for convenience
alias deptrast='java -jar /path/to/deptrast-4.0.0.jar'
```

**Requirements:** Java 11 or higher

### Python
```bash
# Install from source
pip install ./python

# Or install directly from GitHub
pip install git+https://github.com/planetlevel/deptrast.git#subdirectory=python
```

**Requirements:** Python 3.8 or higher

## Quick Start

```bash
# Create SBOM from pom.xml
deptrast create pom.xml output.sbom

# Enrich existing SBOM with dependency graph
deptrast enrich input.sbom enriched.sbom

# Print SBOM as tree visualization
deptrast print input.sbom --output=tree
```

## Project Security

See [SECURITY.md](SECURITY.md) for information about the project's security policy, vulnerability reporting, and best practices.

## Usage

```bash
deptrast <subcommand> [args...] [options]
```

### Subcommands

- **`create <input> <output>`** - Create SBOM or other formats from source files
- **`enrich <sbom> <output>`** - Add dependency graph to existing SBOM
- **`print <sbom>`** - Display SBOM in different formats
- **`stats <sbom>`** - Show statistics about SBOM
- **`compare <sbom1> <sbom2>`** - Compare two SBOMs
- **`validate <sbom>`** - Validate SBOM structure
- **`help`** - Show help message

### Common Options

#### Input Type (`create` command only)
- `--input=roots|list` - How to interpret input (default: auto-detected)
  - `roots` - Root packages (fetch transitive deps from API)
  - `list` - Complete flat list (find roots by analysis)
  - Auto-detection: pom/gradle/pypi → roots, flat/sbom → list

#### Output Format
- `--output=sbom|roots|tree|list` - Output format (default: sbom)
  - `sbom` - Full CycloneDX SBOM (JSON) with all packages
  - `roots` - SBOM with only root packages
  - `tree` - Tree visualization (text)
  - `list` - Flat list (one package per line)

#### Tree Format
- `--format=tree|maven` - Tree visualization format (default: tree)
  - `tree` - Unicode tree with root indicators (🔴)
  - `maven` - Maven dependency:tree compatible format

#### Dependency Graph Options (`create` command only)
- `--use-existing-deps` - Use existing dependency graph from SBOM (fast mode, no API calls)
  - Only works when input is an SBOM file
  - Skips rebuilding the dependency tree, using the existing `dependencies` array
  - Much faster since it avoids API calls to deps.dev
  - Ideal for: `print`, `validate`, format conversions
- `--rebuild-deps` - Rebuild dependency graph from scratch (default for `create`, `enrich`)
  - Makes API calls to deps.dev to validate and rebuild the full dependency tree
  - Slower but ensures accuracy and handles version reconciliation
  - Ideal for: creating new SBOMs, validating dependency trees

**Smart Defaults:**
- `print` command: Uses `--use-existing-deps` by default (fast)
- `create` and `enrich` commands: Use `--rebuild-deps` by default (accurate)

#### Other Options
- `--project-name=<name>` - Project name for tree output
- `--verbose`, `-v` - Enable verbose logging
- `--loglevel=<level>` - Set log level (TRACE, DEBUG, INFO, WARN, ERROR)

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
Standard Maven pom.xml files. Deptrast extracts dependencies from `<dependencies>` blocks with smart handling:
- **Scoped dependencies** - Automatically mapped to CycloneDX scopes
- **Property variables** - Resolved from `<properties>` section (e.g., `${spring.version}`)
- **Parent POM properties** - Recursively loads properties from parent POMs via `<relativePath>`
- **Nested properties** - Supports properties that reference other properties
- **Unresolvable variables** - Skipped with warning (e.g., properties from remote artifacts)

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
CycloneDX SBOM JSON files (v1.6). Deptrast extracts components via purl (Package URL) parsing.

### Examples

#### Create Command

**Create SBOM from pom.xml:**
```bash
deptrast create pom.xml output.sbom
```

**Create SBOM from flat list:**
```bash
deptrast create libraries.txt output.sbom
```

**Create flat list from pom.xml:**
```bash
deptrast create pom.xml output.txt --output=list
```

**Create tree visualization from flat list:**
```bash
deptrast create libraries.txt - --output=tree
```

**Output to stdout:**
```bash
deptrast create pom.xml - --output=sbom
```

**Python requirements.txt to SBOM:**
```bash
deptrast create requirements.txt output.sbom
```

**Analyze Gradle build file:**
```bash
deptrast create build.gradle output.sbom
```

**Create SBOM with only root dependencies:**
```bash
deptrast create libraries.txt roots-only.sbom --output=roots
```

**Maven dependency:tree format:**
```bash
deptrast create pom.xml - --output=tree --format=maven --project-name=my-app
```

**Fast mode - Use existing dependency graph:**
```bash
# Convert SBOM to tree instantly (no API calls)
deptrast create input.sbom - --output=tree --use-existing-deps

# Convert SBOM to different format (fast)
deptrast create input.sbom output.json --use-existing-deps
```

**Slow mode - Rebuild dependency graph:**
```bash
# Rebuild dependency graph with validation (slow but accurate)
deptrast create input.sbom validated.sbom --rebuild-deps
```

#### Enrich Command

**Add dependency graph to existing SBOM:**
```bash
deptrast enrich input.sbom enriched.sbom
```
This preserves all original SBOM metadata (tools, timestamps, custom fields) and adds/updates the dependencies section with computed dependency relationships.

#### Print Command

**Display SBOM as tree:**
```bash
deptrast print input.sbom --output=tree
```

**Display SBOM as flat list:**
```bash
deptrast print input.sbom --output=list
```

**Display only root packages:**
```bash
deptrast print input.sbom --output=roots
```

#### Stats Command

**Show SBOM statistics:**
```bash
deptrast stats input.sbom
```
Output includes total packages, root packages, and transitive dependencies count.

#### Compare Command

**Compare two SBOMs:**
```bash
deptrast compare sbom1.json sbom2.json
```
Shows packages in both, only in first, and only in second SBOM.

#### Validate Command

**Validate SBOM structure:**
```bash
deptrast validate input.sbom
```
Checks required fields and reports warnings for missing metadata.

#### Other Options

**Verbose logging:**
```bash
deptrast create libraries.txt - --verbose
# Or with specific log level
deptrast create libraries.txt - --loglevel=DEBUG
```

## Building the Project

```bash
mvn clean package
```

This will create and test an executable JAR file as `target/deptrast-x.x.x.jar`.

