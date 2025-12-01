"""Stats command for showing SBOM statistics."""

import json
import logging
from typing import Set

logger = logging.getLogger(__name__)


def show_stats(sbom_path: str, scope_filter: str = None) -> None:
    """Show statistics about an SBOM file.

    Args:
        sbom_path: Path to SBOM file
        scope_filter: Optional scope to filter by (e.g., 'required', 'excluded', 'optional')
    """
    # Read SBOM directly (don't re-fetch from API!)
    with open(sbom_path, 'r') as f:
        sbom = json.load(f)

    # Get components and optionally filter by scope
    all_components = sbom.get('components', [])

    if scope_filter:
        components = [c for c in all_components if c.get('scope', 'required') == scope_filter]
    else:
        components = all_components

    total_packages = len(components)

    # Find root packages by analyzing dependency graph
    dependencies = sbom.get('dependencies', [])

    # Build set of component refs that match the filter
    filtered_refs: Set[str] = set()
    for component in components:
        purl = component.get('purl')
        if purl:
            # The bom-ref is typically the purl
            bom_ref = component.get('bom-ref', purl)
            filtered_refs.add(bom_ref)

    # Build set of all component refs that are dependencies of something else
    non_root_refs: Set[str] = set()
    all_refs: Set[str] = set()

    for dep in dependencies:
        ref = dep.get('ref')
        if ref and ref in filtered_refs:
            all_refs.add(ref)
            depends_on = dep.get('dependsOn', [])
            # Only count dependencies that are also in our filtered set
            for dep_ref in depends_on:
                if dep_ref in filtered_refs:
                    non_root_refs.add(dep_ref)

    # Root packages are those in all_refs but not in non_root_refs
    # (i.e., they appear in the dependency graph but are not dependencies of anything)
    root_refs = all_refs - non_root_refs
    root_packages = len(root_refs)

    # Transitive packages = total - roots
    transitive_packages = total_packages - root_packages

    print("SBOM Statistics:")
    if scope_filter:
        print(f"  Scope filter: {scope_filter}")
    print(f"  Total Packages: {total_packages}")
    print(f"  Root Packages: {root_packages}")
    print(f"  Transitive Packages: {transitive_packages}")
