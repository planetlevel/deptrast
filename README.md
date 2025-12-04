# Deptrast

[![Java CI with Maven](https://github.com/planetlevel/deptrast/actions/workflows/build.yml/badge.svg)](https://github.com/planetlevel/deptrast/actions/workflows/build.yml)

**The ultimate dependency tree converter, enhancer, and streamliner**

Deptrast will take whatever dependency information you have, from just about any source, and make a detailed and accurate SBOM without having to rely on getting a build system to actually work!  Live your life. Deptrast also includes a number of utilties for comparing, visualizing, analyzing, and validating SBOMS.

## 🌐 Free SBOM Explorer

**Try it now - no installation required!**
**[Launch Interactive SBOM Viewer](https://planetlevel.github.io/deptrast/index.html)**

Load any CycloneDX SBOM and explore your dependency tree with our free interactive visualization tool. Works entirely in your browser - your data never leaves your machine!

![Interactive SBOM Visualization](deptrast-sbom.png)

## Supported input sources

Turn just about any set of dependencies into a full SBOM:
- [x] Maven, Gradle, Python, etc...
- [x] SBOM with only root dependencies and no dependency graph
- [x] Random list of jar files
- [x] requirements.txt
- [x] List of components from runtime analysis
- [x] Etc...

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

### Python
```bash
# Install from source
pip install ./python

# Or install directly from GitHub
pip install git+https://github.com/planetlevel/deptrast.git#subdirectory=python
```

## Quick Start

```bash
# Create SBOM from pom.xml
deptrast create pom.xml output.sbom

# Enrich existing SBOM with dependency graph
deptrast enrich input.sbom enriched.sbom

# Print SBOM as tree visualization
deptrast print input.sbom --output=tree
```

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

