#!/usr/bin/env python3
"""Compare deptrast and cdxgen SBOM outputs"""
import json
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
    deptrast_file = "/tmp/test-dedup.json"
    cdxgen_file = "../spring-petclinic/b9ae508b-b9b8-42bb-9496-8f49b85846fa-sbom-cyclonedx.json"

    print("Loading SBOMs...")
    deptrast_components = parse_components(deptrast_file)
    cdxgen_components = parse_components(cdxgen_file)

    print(f"\nComponent counts:")
    print(f"  deptrast: {len(deptrast_components)}")
    print(f"  cdxgen:   {len(cdxgen_components)}")

    # Find packages in both
    common_packages = set(deptrast_components.keys()) & set(cdxgen_components.keys())
    deptrast_only = set(deptrast_components.keys()) - set(cdxgen_components.keys())
    cdxgen_only = set(cdxgen_components.keys()) - set(deptrast_components.keys())

    # Check version matches
    version_matches = []
    version_mismatches = []

    for pkg in sorted(common_packages):
        dep_ver = deptrast_components[pkg]
        cdx_ver = cdxgen_components[pkg]
        if dep_ver == cdx_ver:
            version_matches.append((pkg, dep_ver))
        else:
            version_mismatches.append((pkg, dep_ver, cdx_ver))

    print(f"\n{'='*80}")
    print(f"COMPARISON RESULTS")
    print(f"{'='*80}")

    print(f"\nPackages in BOTH (with matching versions): {len(version_matches)}")
    for pkg, ver in sorted(version_matches):
        print(f"  ✓ {pkg}@{ver}")

    if version_mismatches:
        print(f"\nPackages in BOTH (with VERSION MISMATCH): {len(version_mismatches)}")
        for pkg, dep_ver, cdx_ver in sorted(version_mismatches):
            print(f"  ⚠ {pkg}")
            print(f"      deptrast: {dep_ver}")
            print(f"      cdxgen:   {cdx_ver}")

    if deptrast_only:
        print(f"\nPackages ONLY in deptrast: {len(deptrast_only)}")
        for pkg in sorted(deptrast_only):
            ver = deptrast_components[pkg]
            print(f"  + {pkg}@{ver}")

    if cdxgen_only:
        print(f"\nPackages ONLY in cdxgen: {len(cdxgen_only)}")
        for pkg in sorted(cdxgen_only):
            ver = cdxgen_components[pkg]
            print(f"  - {pkg}@{ver}")

    # Statistics
    total_unique = len(deptrast_components) + len(cdxgen_components) - len(common_packages)
    match_percent = (len(version_matches) / len(common_packages) * 100) if common_packages else 0
    overlap_percent = (len(common_packages) / total_unique * 100) if total_unique else 0

    print(f"\n{'='*80}")
    print(f"SUMMARY STATISTICS")
    print(f"{'='*80}")
    print(f"Total unique packages:          {total_unique}")
    print(f"Common packages:                {len(common_packages)} ({overlap_percent:.1f}% overlap)")
    print(f"  - Version matches:            {len(version_matches)} ({match_percent:.1f}%)")
    print(f"  - Version mismatches:         {len(version_mismatches)}")
    print(f"deptrast-only packages:         {len(deptrast_only)}")
    print(f"cdxgen-only packages:           {len(cdxgen_only)}")

if __name__ == '__main__':
    main()
