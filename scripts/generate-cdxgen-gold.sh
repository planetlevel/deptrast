#!/bin/bash
# Generate CDXgen gold standard SBOM for testing
# This creates the reference SBOM that deptrast is compared against

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
TEST_DATA_DIR="$PROJECT_DIR/src/test/resources/test-data"

POM_FILE="$TEST_DATA_DIR/petclinic-pom.xml"
OUTPUT_FILE="$TEST_DATA_DIR/petclinic-cdxgen.sbom"

# Check if cdxgen is installed
if ! command -v cdxgen &> /dev/null; then
    echo "Error: cdxgen is not installed"
    echo "Install it with: npm install -g @cyclonedx/cdxgen"
    exit 1
fi

echo "Generating CDXgen SBOM from $POM_FILE..."
echo "Output: $OUTPUT_FILE"
echo ""

# Generate SBOM using cdxgen with --required-only flag (production dependencies only)
# This matches the behavior of deptrast with --itype=roots
cdxgen --required-only "$POM_FILE" -o "$OUTPUT_FILE"

# Check if generation was successful
if [ -f "$OUTPUT_FILE" ]; then
    COMPONENT_COUNT=$(jq '.components | length' "$OUTPUT_FILE")
    echo ""
    echo "✅ Success! Generated SBOM with $COMPONENT_COUNT components"
    echo ""
    echo "To compare with deptrast output, run:"
    echo "  python3 scripts/compare-sboms.py src/test/resources/test-data/petclinic-deptrast-from-maven.sbom src/test/resources/test-data/petclinic-cdxgen.sbom"
else
    echo "❌ Error: Failed to generate SBOM"
    exit 1
fi
