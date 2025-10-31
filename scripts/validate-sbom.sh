#!/bin/bash
# SBOM Validation Script
# Checks CycloneDX SBOM for required and recommended fields

if [ $# -eq 0 ]; then
    echo "Usage: $0 <sbom-file.json>"
    exit 1
fi

SBOM_FILE="$1"

if [ ! -f "$SBOM_FILE" ]; then
    echo "Error: File not found: $SBOM_FILE"
    exit 1
fi

echo "========================================="
echo "SBOM Validation Report"
echo "========================================="
echo "File: $SBOM_FILE"
echo ""

# Check if it's valid JSON
if ! jq empty "$SBOM_FILE" 2>/dev/null; then
    echo "❌ Invalid JSON"
    exit 1
fi
echo "✅ Valid JSON"

# Required fields
echo ""
echo "Required Fields:"
jq -r 'if .bomFormat then "✅ bomFormat: \(.bomFormat)" else "❌ Missing bomFormat" end' "$SBOM_FILE"
jq -r 'if .specVersion then "✅ specVersion: \(.specVersion)" else "❌ Missing specVersion" end' "$SBOM_FILE"
jq -r 'if .version then "✅ version: \(.version)" else "❌ Missing version" end' "$SBOM_FILE"
jq -r 'if .serialNumber then "✅ serialNumber: \(.serialNumber)" else "❌ Missing serialNumber" end' "$SBOM_FILE"

# Component counts
echo ""
echo "Content Statistics:"
COMPONENT_COUNT=$(jq '.components | length' "$SBOM_FILE")
DEPENDENCY_COUNT=$(jq '.dependencies | length' "$SBOM_FILE")
echo "  Components: $COMPONENT_COUNT"
echo "  Dependencies: $DEPENDENCY_COUNT"

# Metadata checks
echo ""
echo "Metadata:"
jq -r 'if .metadata.timestamp then "✅ Timestamp: \(.metadata.timestamp)" else "⚠️  No timestamp" end' "$SBOM_FILE"
jq -r 'if .metadata.tools then "✅ Tools: \(.metadata.tools | length) tool(s)" else "⚠️  No tools listed" end' "$SBOM_FILE"
jq -r 'if .metadata.component then "✅ Main component: \(.metadata.component.name)" else "⚠️  No main component (recommended for applications)" end' "$SBOM_FILE"

# Component validation
echo ""
echo "Component Validation:"
MISSING_PURL=$(jq '[.components[] | select(.purl == null)] | length' "$SBOM_FILE")
MISSING_VERSION=$(jq '[.components[] | select(.version == null)] | length' "$SBOM_FILE")
MISSING_TYPE=$(jq '[.components[] | select(.type == null)] | length' "$SBOM_FILE")

if [ "$MISSING_PURL" -eq 0 ]; then
    echo "✅ All components have PURL"
else
    echo "⚠️  $MISSING_PURL component(s) missing PURL"
fi

if [ "$MISSING_VERSION" -eq 0 ]; then
    echo "✅ All components have version"
else
    echo "⚠️  $MISSING_VERSION component(s) missing version"
fi

if [ "$MISSING_TYPE" -eq 0 ]; then
    echo "✅ All components have type"
else
    echo "⚠️  $MISSING_TYPE component(s) missing type"
fi

# Dependency validation
echo ""
echo "Dependency Graph:"
if [ "$DEPENDENCY_COUNT" -gt 0 ]; then
    echo "✅ Dependency graph present"
    ORPHAN_DEPS=$(jq '[.dependencies[].ref] - [.components[].purl] | length' "$SBOM_FILE")
    if [ "$ORPHAN_DEPS" -eq 0 ]; then
        echo "✅ All dependency refs match components"
    else
        echo "⚠️  $ORPHAN_DEPS dependency ref(s) don't match components"
    fi
else
    echo "⚠️  No dependency graph"
fi

echo ""
echo "========================================="
echo "Validation Complete"
echo "========================================="
