# Deptrast (Python Version)

**The ultimate dependency tree converter, enhancer, and streamliner** - Python edition

This is a clean Python implementation of deptrast with the same features as the Java version.

## Features

- Parse multiple input formats (flat lists, Maven pom.xml, Gradle, Python requirements.txt, SBOM)
- Fetch complete dependency graphs from deps.dev API
- Smart root dependency detection
- Generate CycloneDX SBOMs
- Tree visualizations (Unicode and Maven-style)
- Version reconciliation with dependency management

## Installation

```bash
# Install in development mode
cd python
pip install -e .

# Or install dependencies only
pip install -r requirements.txt
```

## Usage

Same CLI as the Java version:

```bash
# Create SBOM from pom.xml
deptrast create pom.xml output.sbom

# Enrich existing SBOM
deptrast enrich input.sbom enriched.sbom

# Print as tree
deptrast print input.sbom --output=tree

# Create from flat list
deptrast create libraries.txt output.sbom
```

## Requirements

- Python 3.8+
- requests
- cyclonedx-python-lib

## Development

```bash
# Install dev dependencies
pip install -e ".[dev]"

# Run tests
pytest
```
