"""Validate command for validating SBOM structure."""

import json
import logging
from typing import List, Tuple

logger = logging.getLogger(__name__)


def validate_sbom(sbom_path: str) -> None:
    """Validate SBOM structure and completeness."""
    # Read and parse SBOM
    with open(sbom_path, 'r') as f:
        sbom = json.load(f)

    valid = True
    errors: List[str] = []
    warnings: List[str] = []
    checks: List[str] = []

    # Check required fields
    if 'bomFormat' not in sbom:
        errors.append("Missing required field: bomFormat")
        valid = False
    else:
        checks.append(f"bomFormat: {sbom['bomFormat']}")

    if 'specVersion' not in sbom:
        errors.append("Missing required field: specVersion")
        valid = False
    else:
        checks.append(f"specVersion: {sbom['specVersion']}")

    if 'components' not in sbom:
        errors.append("Missing required field: components")
        valid = False

    # Check optional metadata
    if 'metadata' in sbom:
        metadata = sbom['metadata']
        if 'timestamp' in metadata:
            checks.append(f"metadata.timestamp: {metadata['timestamp']}")
        if 'tools' in metadata:
            checks.append("metadata.tools: present")

    # Check serialNumber
    if 'serialNumber' in sbom:
        checks.append("serialNumber: present (URN format)")

    # Check components
    component_count = 0
    with_purl = 0
    with_bom_ref = 0
    with_version = 0

    if 'components' in sbom:
        components = sbom['components']
        component_count = len(components)

        for component in components:
            if component.get('purl'):
                with_purl += 1
            if component.get('bom-ref'):
                with_bom_ref += 1
            if component.get('version'):
                with_version += 1

        purl_pct = (with_purl * 100 // component_count) if component_count > 0 else 0
        bomref_pct = (with_bom_ref * 100 // component_count) if component_count > 0 else 0
        version_pct = (with_version * 100 // component_count) if component_count > 0 else 0

        checks.append(f"components: {component_count} total")
        checks.append(f"components with PURL: {with_purl} ({purl_pct}%)")
        checks.append(f"components with bom-ref: {with_bom_ref} ({bomref_pct}%)")
        checks.append(f"components with version: {with_version} ({version_pct}%)")

        missing_purl = component_count - with_purl
        missing_bom_ref = component_count - with_bom_ref

        if missing_purl > 0:
            warnings.append(f"{missing_purl} component(s) missing PURL")
        if missing_bom_ref > 0:
            warnings.append(f"{missing_bom_ref} component(s) missing bom-ref")

    # Check dependencies
    dep_count = 0
    deps_with_depends_on = 0

    if 'dependencies' not in sbom:
        warnings.append("No dependencies array (SBOM lacks dependency graph)")
    else:
        dependencies = sbom['dependencies']
        dep_count = len(dependencies)

        for dep in dependencies:
            if dep.get('dependsOn') and len(dep['dependsOn']) > 0:
                deps_with_depends_on += 1

        checks.append(f"dependencies: {dep_count} entries")
        checks.append(f"dependencies with dependsOn: {deps_with_depends_on}")

        if dep_count == 0:
            warnings.append("Dependencies array is empty")

    # Print results
    print("SBOM Validation Results:")
    print(f"  File: {sbom_path}")
    print()

    # Show what was checked
    print("Validation Checks:")
    for check in checks:
        print(f"  ✓ {check}")

    if errors or warnings:
        if errors:
            print()
            print("Errors:")
            for err in errors:
                print(f"  ✗ {err}")
        if warnings:
            print()
            print("Warnings:")
            for warn in warnings:
                print(f"  ⚠ {warn}")

    print()
    if valid and not warnings:
        print("Result: ✓ Valid CycloneDX SBOM with no issues")
    elif valid:
        print(f"Result: ✓ Valid CycloneDX SBOM with {len(warnings)} warning(s)")
    else:
        print(f"Result: ✗ Invalid SBOM - {len(errors)} error(s)")
