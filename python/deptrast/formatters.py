"""Output formatters for various formats."""

import json
import logging
import re
from datetime import datetime
from typing import List, Collection, Dict
from uuid import uuid4

from packageurl import PackageURL
from cyclonedx.model import ExternalReference, ExternalReferenceType, XsUri
from cyclonedx.model.bom import Bom
from cyclonedx.model.component import Component, ComponentType, ComponentScope
from cyclonedx.model.contact import OrganizationalContact
from cyclonedx.model.tool import Tool
from cyclonedx.output.json import JsonV1Dot6

from .models import Package, DependencyNode

logger = logging.getLogger(__name__)


class OutputFormatter:
    """Formatter for various output formats."""

    @staticmethod
    def format_as_list(packages: Collection[Package]) -> str:
        """Format packages as a flat list (one per line)."""
        lines = [pkg.full_name for pkg in packages]
        return '\n'.join(lines) + '\n'

    @staticmethod
    def format_as_tree(
        dependency_trees: List[DependencyNode],
        all_packages: Collection[Package],
        project_name: str = 'project'
    ) -> str:
        """Format as a tree visualization."""
        lines = ["Dependency Tree:", ""]

        # Create a project root node
        project_root = DependencyNode(
            package=Package(system='project', name=project_name, version='1.0.0')
        )
        for tree in dependency_trees:
            project_root.add_child(tree)

        lines.append(project_root.get_tree_representation())

        lines.extend([
            "",
            "Dependency Statistics:",
            f"  Total Packages: {len(all_packages)}",
            f"  Root Packages: {len(dependency_trees)}"
        ])

        return '\n'.join(lines) + '\n'

    @staticmethod
    def format_as_maven_tree(
        project_name: str,
        dependency_trees: List[DependencyNode]
    ) -> str:
        """Format as Maven dependency:tree output."""
        lines = [f"[INFO] {project_name}"]

        visited = set()
        for tree in dependency_trees:
            lines.extend(OutputFormatter._format_maven_node(tree, "", True, depth=0, visited=visited))

        return '\n'.join(lines) + '\n'

    @staticmethod
    def _format_maven_node(node: DependencyNode, prefix: str, is_last: bool, depth: int = 0, visited: set = None) -> List[str]:
        """Format a single node in Maven tree style."""
        if visited is None:
            visited = set()

        lines = []

        # Check for cycles
        node_id = node.package.full_name
        if node_id in visited:
            # Just show the node without recursing
            if depth > 0:
                connector = "\\- " if is_last else "+- "
                lines.append(f"[INFO] {prefix}{connector}{node_id} (cycle)")
            else:
                lines.append(f"[INFO] +- {node_id} (cycle)")
            return lines

        visited.add(node_id)

        # Connector
        if depth > 0:
            connector = "\\- " if is_last else "+- "
            lines.append(f"[INFO] {prefix}{connector}{node.package.full_name}")
        else:
            lines.append(f"[INFO] +- {node.package.full_name}")

        # Children
        for i, child in enumerate(node.children):
            is_last_child = (i == len(node.children) - 1)
            child_prefix = prefix + ("   " if is_last else "|  ")
            lines.extend(OutputFormatter._format_maven_node(child, child_prefix, is_last_child, depth + 1, visited))

        return lines

    @staticmethod
    def format_as_sbom(
        packages: Collection[Package],
        dependency_trees: List[DependencyNode],
        command_line: str = None
    ) -> str:
        """Generate a CycloneDX SBOM in JSON format."""
        from . import __version__

        bom = Bom()

        # Set serial number - just use UUID, the library will format it
        bom.serial_number = uuid4()

        # Create metadata with tool information as a component (like Java version)
        # Use GitHub-based purl since deptrast is open source on GitHub
        tool_purl = PackageURL.from_string(f"pkg:github/planetlevel/deptrast@{__version__}")

        # Create external reference for VCS
        vcs_ref = ExternalReference(
            type=ExternalReferenceType.VCS,
            url=XsUri("https://github.com/planetlevel/deptrast")
        )

        tool_component = Component(
            name="deptrast",
            version=__version__,
            type=ComponentType.APPLICATION,
            group="com.contrastsecurity",
            publisher="Contrast Security",
            purl=tool_purl,
            bom_ref=f"pkg:github/planetlevel/deptrast@{__version__}",
            external_references=[vcs_ref]
        )

        # Add authors to tool component
        tool_author = OrganizationalContact(name="Jeff Williams")
        tool_component.authors.add(tool_author)

        # Add to tools.components
        bom.metadata.tools.components.add(tool_component)
        # Timestamp will be manually set in JSON to match Java's format
        bom.metadata.timestamp = datetime.utcnow().replace(microsecond=0)

        # Build dependency map from tree structure
        dependency_map = OutputFormatter._build_dependency_map(dependency_trees)

        # Add all packages as components
        for pkg in packages:
            component = OutputFormatter._package_to_component(pkg)
            bom.components.add(component)

        # Generate basic JSON first
        outputter = JsonV1Dot6(bom)
        sbom_str = outputter.output_as_string()

        # Parse and add dependencies manually (easier than using the API)
        sbom = json.loads(sbom_str)

        # Build dependencies array
        dependencies = []
        for pkg in packages:
            purl = OutputFormatter._build_purl(pkg)

            # Get direct dependencies
            direct_deps = dependency_map.get(pkg, [])
            depends_on = [OutputFormatter._build_purl(dep) for dep in direct_deps if dep in packages]

            # Always include dependsOn (even if empty) to match Java
            # Sort dependsOn array for consistent ordering
            depends_on.sort()

            dep_entry = {
                "ref": purl,
                "dependsOn": depends_on
            }

            dependencies.append(dep_entry)

        # Sort dependencies alphabetically by ref for consistent ordering
        dependencies.sort(key=lambda d: d.get('ref', ''))

        # Add dependencies to SBOM
        sbom['dependencies'] = dependencies

        # Reorder component fields to match Java output: type, bom-ref, group, name, version, scope, purl, tags
        reordered_components = []
        for comp in sbom.get('components', []):
            ordered_comp = {
                'type': comp.get('type'),
                'bom-ref': comp.get('bom-ref'),
                'group': comp.get('group'),
                'name': comp.get('name'),
                'version': comp.get('version'),
                'scope': comp.get('scope'),
                'purl': comp.get('purl'),
                'tags': comp.get('tags')
            }
            # Remove None values
            ordered_comp = {k: v for k, v in ordered_comp.items() if v is not None}
            reordered_components.append(ordered_comp)

        # Sort components alphabetically by purl for consistent ordering
        reordered_components.sort(key=lambda c: c.get('purl', ''))

        # Reorder metadata.tools.components fields to match Java
        metadata = sbom.get('metadata', {})
        if 'tools' in metadata and 'components' in metadata['tools']:
            reordered_tool_comps = []
            for tool_comp in metadata['tools']['components']:
                ordered_tool = {
                    'type': tool_comp.get('type'),
                    'bom-ref': tool_comp.get('bom-ref'),
                    'authors': tool_comp.get('authors'),
                    'publisher': tool_comp.get('publisher'),
                    'group': tool_comp.get('group'),
                    'name': tool_comp.get('name'),
                    'version': tool_comp.get('version'),
                    'purl': tool_comp.get('purl'),
                    'externalReferences': tool_comp.get('externalReferences')
                }
                # Remove None values
                ordered_tool = {k: v for k, v in ordered_tool.items() if v is not None}
                reordered_tool_comps.append(ordered_tool)
            metadata['tools']['components'] = reordered_tool_comps

        # Add commandLine property if provided
        if command_line:
            if 'properties' not in metadata:
                metadata['properties'] = []
            metadata['properties'].append({
                'name': 'commandLine',
                'value': command_line
            })

        # Fix timestamp format to match Java (UTC with Z suffix, no microseconds)
        if 'timestamp' in metadata:
            # Convert to UTC Z format like Java: "2025-11-28T21:37:57Z"
            ts = metadata['timestamp']
            # Remove timezone offset (e.g., -05:00, +00:00) and add Z
            # Match pattern like 2025-11-28T21:40:39-05:00 or 2025-11-28T21:40:39+00:00
            match = re.match(r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})', ts)
            if match:
                metadata['timestamp'] = match.group(1) + 'Z'

        # Reorder to match Java output: metadata first, then components, then dependencies
        ordered_sbom = {
            'bomFormat': sbom.get('bomFormat'),
            'specVersion': sbom.get('specVersion'),
            'serialNumber': sbom.get('serialNumber'),
            'version': sbom.get('version', 1),
            'metadata': metadata,
            'components': reordered_components,
            'dependencies': sbom.get('dependencies')
        }

        # Use separators to match Java (no trailing space after comma, space before and after colon)
        sbom_json = json.dumps(ordered_sbom, indent=2, separators=(',', ' : '))

        # Replace empty arrays [] with [ ] to match Java formatting
        sbom_json = sbom_json.replace('[]', '[ ]')

        return sbom_json

    @staticmethod
    def enhance_sbom_with_dependencies(
        original_sbom_content: str,
        packages: Collection[Package],
        dependency_trees: List[DependencyNode]
    ) -> str:
        """Enhance an existing SBOM by adding/updating the dependencies section."""
        # Parse original SBOM
        sbom = json.loads(original_sbom_content)

        # Build dependency map from tree structure
        dependency_map = OutputFormatter._build_dependency_map(dependency_trees)

        # Build purl lookup maps
        purl_by_package: Dict[Package, str] = {}
        bomref_by_package: Dict[Package, str] = {}

        components = sbom.get('components', [])
        for component in components:
            purl = component.get('purl')
            if not purl:
                continue

            # Find matching package
            for pkg in packages:
                expected_purl = OutputFormatter._build_purl(pkg)
                if purl == expected_purl:
                    purl_by_package[pkg] = purl

                    # Get or create bom-ref
                    bomref = component.get('bom-ref')
                    if not bomref:
                        bomref = purl
                        component['bom-ref'] = bomref
                    bomref_by_package[pkg] = bomref
                    break

        # Build dependencies array
        dependencies = []
        for pkg in packages:
            bomref = bomref_by_package.get(pkg)
            if not bomref:
                continue

            dep_entry = {"ref": bomref}

            # Get direct dependencies
            direct_deps = dependency_map.get(pkg, [])
            if direct_deps:
                depends_on = []
                for dep_pkg in direct_deps:
                    dep_bomref = bomref_by_package.get(dep_pkg)
                    if dep_bomref:
                        depends_on.append(dep_bomref)

                if depends_on:
                    dep_entry["dependsOn"] = depends_on

            dependencies.append(dep_entry)

        # Update SBOM with dependencies
        sbom['dependencies'] = dependencies

        return json.dumps(sbom, indent=2)

    @staticmethod
    def _build_dependency_map(trees: List[DependencyNode]) -> Dict[Package, List[Package]]:
        """Build a map of Package -> direct dependencies from the tree structure."""
        dependency_map: Dict[Package, List[Package]] = {}
        visited = set()

        for tree in trees:
            OutputFormatter._collect_dependencies_from_tree(tree, dependency_map, visited)

        return dependency_map

    @staticmethod
    def _collect_dependencies_from_tree(
        node: DependencyNode,
        dependency_map: Dict[Package, List[Package]],
        visited: set
    ) -> None:
        """Recursively collect dependency relationships from tree."""
        if not node:
            return

        # Check for cycles
        node_id = node.package.full_name
        if node_id in visited:
            return
        visited.add(node_id)

        pkg = node.package
        children = [child.package for child in node.children]

        # Deduplicate children list (defensive - shouldn't be needed but handles edge cases)
        seen = set()
        unique_children = []
        for child in children:
            child_key = child.full_name
            if child_key not in seen:
                seen.add(child_key)
                unique_children.append(child)

        # Only overwrite if we don't already have a better entry
        # (one with children beats one without)
        if pkg not in dependency_map or len(unique_children) > 0:
            dependency_map[pkg] = unique_children

        # Recurse into children
        for child in node.children:
            OutputFormatter._collect_dependencies_from_tree(child, dependency_map, visited)

    @staticmethod
    def _maven_scope_to_cyclonedx(maven_scope: str) -> ComponentScope:
        """
        Map Maven scope to CycloneDX ComponentScope.

        Maven scopes:
          compile, runtime, required -> REQUIRED (needed at runtime)
          test, provided, system, excluded -> EXCLUDED (not needed at runtime)
          optional -> OPTIONAL (optional at runtime)
        """
        if not maven_scope:
            maven_scope = "compile"  # Default Maven scope

        scope_lower = maven_scope.lower()

        if scope_lower == "optional":
            return ComponentScope.OPTIONAL
        elif scope_lower in ("test", "provided", "system", "excluded"):
            return ComponentScope.EXCLUDED
        elif scope_lower in ("compile", "runtime", "required"):
            return ComponentScope.REQUIRED
        else:
            # Default to REQUIRED for unknown scopes
            return ComponentScope.REQUIRED

    @staticmethod
    def _package_to_component(pkg: Package) -> Component:
        """Convert a Package to a CycloneDX Component."""
        # For Maven packages, separate group and artifact
        name = pkg.name
        group = None
        if pkg.system.lower() == 'maven' and ':' in pkg.name:
            parts = pkg.name.split(':', 1)
            group = parts[0]
            name = parts[1]

        # Build purl string first
        purl_str = OutputFormatter._build_purl(pkg)
        purl_obj = PackageURL.from_string(purl_str)

        # Build tags list to indicate scope reason and winning version
        tags = []
        if pkg.scope_reason:
            tags.append(f"scope:{pkg.scope_reason}")
        if pkg.winning_version:
            tags.append(f"winner:{pkg.winning_version}")

        component = Component(
            name=name,
            version=pkg.version,
            type=ComponentType.LIBRARY,
            group=group,
            purl=purl_obj,
            bom_ref=purl_str,
            tags=tags if tags else None
        )

        # Map package scope to CycloneDX scope (applies to all package types)
        if pkg.scope:
            cdx_scope = OutputFormatter._maven_scope_to_cyclonedx(pkg.scope)
            component.scope = cdx_scope

        return component

    @staticmethod
    def _build_purl(pkg: Package) -> str:
        """Build a Package URL (purl) string for a package."""
        if pkg.system.lower() == 'maven':
            # Convert groupId:artifactId to groupId/artifactId
            name = pkg.name.replace(':', '/')
            return f"pkg:maven/{name}@{pkg.version}"
        else:
            return f"pkg:{pkg.system.lower()}/{pkg.name}@{pkg.version}"
