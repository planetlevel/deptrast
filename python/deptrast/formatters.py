"""Output formatters for various formats."""

import json
import logging
from datetime import datetime
from typing import List, Collection, Dict
from uuid import uuid4

from packageurl import PackageURL
from cyclonedx.model import ExternalReference, ExternalReferenceType, XsUri
from cyclonedx.model.bom import Bom
from cyclonedx.model.component import Component, ComponentType
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
            package=Package(system='project', name=project_name, version='1.0.0'),
            depth=0
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

        for tree in dependency_trees:
            lines.extend(OutputFormatter._format_maven_node(tree, "", True))

        return '\n'.join(lines) + '\n'

    @staticmethod
    def _format_maven_node(node: DependencyNode, prefix: str, is_last: bool) -> List[str]:
        """Format a single node in Maven tree style."""
        lines = []

        # Connector
        if node.depth > 0:
            connector = "\\- " if is_last else "+- "
            lines.append(f"[INFO] {prefix}{connector}{node.package.full_name}")
        else:
            lines.append(f"[INFO] +- {node.package.full_name}")

        # Children
        for i, child in enumerate(node.children):
            is_last_child = (i == len(node.children) - 1)
            child_prefix = prefix + ("   " if is_last else "|  ")
            lines.extend(OutputFormatter._format_maven_node(child, child_prefix, is_last_child))

        return lines

    @staticmethod
    def format_as_sbom(
        packages: Collection[Package],
        dependency_trees: List[DependencyNode]
    ) -> str:
        """Generate a CycloneDX SBOM in JSON format."""
        bom = Bom()

        # Set serial number - just use UUID, the library will format it
        bom.serial_number = uuid4()

        # Create metadata with tool information
        tool = Tool(
            vendor="Contrast Security",
            name="deptrast",
            version="3.0.1"
        )
        bom.metadata.tools.tools.add(tool)
        bom.metadata.timestamp = datetime.utcnow()

        # Add author
        author = OrganizationalContact(name="Jeff Williams")
        bom.metadata.authors.add(author)

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
            dep_entry = {"ref": purl}

            # Get direct dependencies
            direct_deps = dependency_map.get(pkg, [])
            if direct_deps:
                depends_on = [OutputFormatter._build_purl(dep) for dep in direct_deps if dep in packages]
                if depends_on:
                    dep_entry["dependsOn"] = depends_on

            dependencies.append(dep_entry)

        # Add dependencies to SBOM
        sbom['dependencies'] = dependencies

        return json.dumps(sbom, indent=2)

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

        for tree in trees:
            OutputFormatter._collect_dependencies_from_tree(tree, dependency_map)

        return dependency_map

    @staticmethod
    def _collect_dependencies_from_tree(
        node: DependencyNode,
        dependency_map: Dict[Package, List[Package]]
    ) -> None:
        """Recursively collect dependency relationships from tree."""
        if not node:
            return

        pkg = node.package
        children = [child.package for child in node.children]
        dependency_map[pkg] = children

        # Recurse into children
        for child in node.children:
            OutputFormatter._collect_dependencies_from_tree(child, dependency_map)

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

        component = Component(
            name=name,
            version=pkg.version,
            type=ComponentType.LIBRARY,
            group=group,
            purl=purl_obj,
            bom_ref=purl_str
        )

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
