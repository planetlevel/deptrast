"""Compare command for comparing two SBOMs."""

import json
import logging
from typing import Dict, Set, Tuple, List

logger = logging.getLogger(__name__)


def normalize_purl(purl: str) -> str:
    """Normalize a purl by removing qualifiers (everything after ?)."""
    if '?' in purl:
        return purl.split('?')[0]
    return purl


def get_package_name_from_purl(purl: str) -> str:
    """Extract package name without version from a purl."""
    # Remove qualifiers first
    normalized = normalize_purl(purl)
    # Remove version (everything after last @)
    if '@' in normalized:
        return normalized.rsplit('@', 1)[0]
    return normalized


def parse_sbom_purls(sbom_path: str) -> List[str]:
    """Parse SBO M and extract all purls."""
    with open(sbom_path, 'r') as f:
        sbom = json.load(f)

    purls = []
    components = sbom.get('components', [])
    for component in components:
        purl = component.get('purl')
        if purl:
            purls.append(normalize_purl(purl))

    return purls


def compare_sboms(sbom1_path: str, sbom2_path: str) -> None:
    """Compare two SBOMs and show differences."""
    # Parse both SBOMs
    purls1 = parse_sbom_purls(sbom1_path)
    purls2 = parse_sbom_purls(sbom2_path)

    # Build package name -> full purl maps for version comparison
    package_names1: Dict[str, str] = {}
    package_names2: Dict[str, str] = {}

    for purl in purls1:
        package_names1[get_package_name_from_purl(purl)] = purl
    for purl in purls2:
        package_names2[get_package_name_from_purl(purl)] = purl

    # Convert to sets for comparison
    purls1_set = set(purls1)
    purls2_set = set(purls2)

    # Find exact matches
    in_both = purls1_set & purls2_set

    # Find packages only in one or the other
    only_in1 = purls1_set - purls2_set
    only_in2 = purls2_set - purls1_set

    # Find version differences (same package name, different version)
    version_diffs: Dict[str, Tuple[str, str]] = {}
    processed_names: Set[str] = set()

    for purl1 in only_in1:
        package_name = get_package_name_from_purl(purl1)
        if package_name in package_names2:
            purl2 = package_names2[package_name]
            version1 = purl1.rsplit('@', 1)[1] if '@' in purl1 else 'unknown'
            version2 = purl2.rsplit('@', 1)[1] if '@' in purl2 else 'unknown'
            version_diffs[package_name] = (version1, version2)
            processed_names.add(package_name)

    # Remove version diffs from the "only in" sets
    only_in1 = {p for p in only_in1 if get_package_name_from_purl(p) not in processed_names}
    only_in2 = {p for p in only_in2 if get_package_name_from_purl(p) not in processed_names}

    # Print results
    print("SBOM Comparison:")
    print(f"  {sbom1_path}: {len(purls1)} components")
    print(f"  {sbom2_path}: {len(purls2)} components")
    print()
    print(f"  Same version: {len(in_both)}")
    print(f"  Version differences: {len(version_diffs)}")
    print(f"  Only in {sbom1_path}: {len(only_in1)}")
    print(f"  Only in {sbom2_path}: {len(only_in2)}")

    if version_diffs:
        print()
        print("Version differences:")
        sorted_diffs = sorted(version_diffs.items())
        for i, (package_name, (version1, version2)) in enumerate(sorted_diffs):
            if i >= 10:
                print(f"  ... and {len(version_diffs) - 10} more")
                break
            print(f"  - {package_name}")
            print(f"    {sbom1_path}: {version1}")
            print(f"    {sbom2_path}: {version2}")

    if only_in1:
        print()
        print(f"Components only in {sbom1_path}:")
        sorted_only1 = sorted(only_in1)
        for i, purl in enumerate(sorted_only1):
            if i >= 10:
                print(f"  ... and {len(only_in1) - 10} more")
                break
            print(f"  - {purl}")

    if only_in2:
        print()
        print(f"Components only in {sbom2_path}:")
        sorted_only2 = sorted(only_in2)
        for i, purl in enumerate(sorted_only2):
            if i >= 10:
                print(f"  ... and {len(only_in2) - 10} more")
                break
            print(f"  - {purl}")
