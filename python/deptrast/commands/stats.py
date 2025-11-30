"""Stats command for showing SBOM statistics."""

import json
import logging
from typing import Set

logger = logging.getLogger(__name__)


def show_stats(sbom_path: str) -> None:
    """Show statistics about an SBOM file."""
    # Read SBOM directly (don't re-fetch from API!)
    with open(sbom_path, 'r') as f:
        sbom = json.load(f)

    # Count components
    components = sbom.get('components', [])
    total_packages = len(components)

    # Find root packages by analyzing dependency graph
    dependencies = sbom.get('dependencies', [])

    # Build set of all component refs that are dependencies of something else
    non_root_refs: Set[str] = set()
    all_refs: Set[str] = set()

    for dep in dependencies:
        ref = dep.get('ref')
        if ref:
            all_refs.add(ref)
            depends_on = dep.get('dependsOn', [])
            non_root_refs.update(depends_on)

    # Root packages are those in all_refs but not in non_root_refs
    # (i.e., they appear in the dependency graph but are not dependencies of anything)
    root_refs = all_refs - non_root_refs
    root_packages = len(root_refs)

    # Transitive packages = total - roots
    transitive_packages = total_packages - root_packages

    print("SBOM Statistics:")
    print(f"  Total Packages: {total_packages}")
    print(f"  Root Packages: {root_packages}")
    print(f"  Transitive Packages: {transitive_packages}")
