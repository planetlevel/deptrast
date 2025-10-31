#!/usr/bin/env python3
"""Compare two SBOM files"""
import json
import sys
from collections import defaultdict

def parse_components(sbom_path):
    """Extract components from SBOM"""
    with open(sbom_path) as f:
        sbom = json.load(f)

    components = {}

    def extract_from_component(comp):
        group = comp.get('group', '')
        name = comp.get('name', '')
        version = comp.get('version', '')
        key = f"{group}:{name}" if group else name
        components[key] = version

        # Recursively extract nested components
        if 'components' in comp:
            for child in comp['components']:
                extract_from_component(child)

    # Extract from top-level components
    if 'components' in sbom:
        for comp in sbom['components']:
            extract_from_component(comp)

    return components

def main():
    if len(sys.argv) != 3:
        print("Usage: compare-sboms.py <sbom1.json> <sbom2.json>")
        print("\nCompares two SBOM files and shows differences in components and versions.")
        sys.exit(1)

    sbom1_file = sys.argv[1]
    sbom2_file = sys.argv[2]

    print(f"Loading SBOMs...")
    print(f"  SBOM 1: {sbom1_file}")
    print(f"  SBOM 2: {sbom2_file}")

    sbom1_components = parse_components(sbom1_file)
    sbom2_components = parse_components(sbom2_file)

    print(f"\nComponent counts:")
    print(f"  SBOM 1: {len(sbom1_components)}")
    print(f"  SBOM 2: {len(sbom2_components)}")

    # Find packages in both
    common_packages = set(sbom1_components.keys()) & set(sbom2_components.keys())
    sbom1_only = set(sbom1_components.keys()) - set(sbom2_components.keys())
    sbom2_only = set(sbom2_components.keys()) - set(sbom1_components.keys())

    # Check version matches
    version_matches = []
    version_mismatches = []

    for pkg in sorted(common_packages):
        sbom1_ver = sbom1_components[pkg]
        sbom2_ver = sbom2_components[pkg]
        if sbom1_ver == sbom2_ver:
            version_matches.append((pkg, sbom1_ver))
        else:
            version_mismatches.append((pkg, sbom1_ver, sbom2_ver))

    print(f"\n{'='*80}")
    print(f"COMPARISON RESULTS")
    print(f"{'='*80}")

    print(f"\nPackages in BOTH (with matching versions): {len(version_matches)}")
    for pkg, ver in sorted(version_matches):
        print(f"  ✓ {pkg}@{ver}")

    if version_mismatches:
        print(f"\nPackages in BOTH (with VERSION MISMATCH): {len(version_mismatches)}")
        for pkg, sbom1_ver, sbom2_ver in sorted(version_mismatches):
            print(f"  ⚠ {pkg}")
            print(f"      SBOM 1: {sbom1_ver}")
            print(f"      SBOM 2: {sbom2_ver}")

    if sbom1_only:
        print(f"\nPackages ONLY in SBOM 1: {len(sbom1_only)}")
        for pkg in sorted(sbom1_only):
            ver = sbom1_components[pkg]
            print(f"  + {pkg}@{ver}")

    if sbom2_only:
        print(f"\nPackages ONLY in SBOM 2: {len(sbom2_only)}")
        for pkg in sorted(sbom2_only):
            ver = sbom2_components[pkg]
            print(f"  - {pkg}@{ver}")

    # Statistics
    total_unique = len(sbom1_components) + len(sbom2_components) - len(common_packages)
    match_percent = (len(version_matches) / len(common_packages) * 100) if common_packages else 0
    overlap_percent = (len(common_packages) / total_unique * 100) if total_unique else 0

    print(f"\n{'='*80}")
    print(f"SUMMARY STATISTICS")
    print(f"{'='*80}")
    print(f"Total unique packages:          {total_unique}")
    print(f"Common packages:                {len(common_packages)} ({overlap_percent:.1f}% overlap)")
    print(f"  - Version matches:            {len(version_matches)} ({match_percent:.1f}%)")
    print(f"  - Version mismatches:         {len(version_mismatches)}")
    print(f"SBOM 1 only packages:           {len(sbom1_only)}")
    print(f"SBOM 2 only packages:           {len(sbom2_only)}")

if __name__ == '__main__':
    main()
