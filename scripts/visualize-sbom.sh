#!/bin/bash
# Quick script to visualize an SBOM file

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

if [ $# -eq 0 ]; then
    echo "Usage: $0 <sbom-file>"
    echo ""
    echo "Examples:"
    echo "  $0 my-project.sbom"
    echo "  $0 src/test/resources/petclinic-deptrast-from-maven.sbom"
    exit 1
fi

SBOM_FILE="$1"

if [ ! -f "$SBOM_FILE" ]; then
    echo "Error: File not found: $SBOM_FILE"
    exit 1
fi

echo "Visualizing SBOM: $SBOM_FILE"
python3 "$PROJECT_ROOT/python/deptrast/commands/graph.py" "$SBOM_FILE"
