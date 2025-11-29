"""Input file parsers for various formats."""

import json
import logging
import re
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import List, Dict, Set, Tuple, Optional

from .models import Package

logger = logging.getLogger(__name__)


class FileParser:
    """Parser for various input file formats."""

    @staticmethod
    def parse_flat_file(file_path: str) -> List[Package]:
        """
        Parse a flat file with system:name:version per line.

        Example:
            maven:org.springframework.boot:spring-boot-starter-web:3.1.0
            npm:react:18.2.0
            pypi:requests:2.28.1
        """
        packages = []

        with open(file_path, 'r') as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()

                # Skip empty lines and comments
                if not line or line.startswith('#'):
                    continue

                # Parse system:name:version format
                parts = line.split(':')
                if len(parts) < 3:
                    logger.warning(f"Line {line_num}: Invalid format '{line}' - expected system:name:version")
                    continue

                system = parts[0]
                # Handle maven groupId:artifactId format
                if system.lower() == 'maven' and len(parts) >= 4:
                    name = f"{parts[1]}:{parts[2]}"
                    version = parts[3]
                else:
                    name = parts[1]
                    version = ':'.join(parts[2:])  # Handle versions with colons

                packages.append(Package(system=system, name=name, version=version))

        logger.info(f"Parsed {len(packages)} packages from flat file")
        return packages

    @staticmethod
    def parse_sbom_file(file_path: str) -> List[Package]:
        """Parse a CycloneDX SBOM JSON file."""
        with open(file_path, 'r') as f:
            sbom = json.load(f)

        packages = []
        components = sbom.get('components', [])

        for component in components:
            purl = component.get('purl')
            if not purl:
                continue

            # Parse purl: pkg:maven/groupId/artifactId@version
            pkg = FileParser._parse_purl(purl)
            if pkg:
                packages.append(pkg)

        logger.info(f"Parsed {len(packages)} packages from SBOM")
        return packages

    @staticmethod
    def _parse_purl(purl: str) -> Optional[Package]:
        """Parse a Package URL (purl) string."""
        # Format: pkg:system/name@version or pkg:maven/group/artifact@version
        match = re.match(r'pkg:([^/]+)/(.+?)@(.+?)(?:\?.*)?$', purl)
        if not match:
            logger.warning(f"Invalid purl format: {purl}")
            return None

        system = match.group(1)
        name_part = match.group(2)
        version = match.group(3)

        # For Maven, name is groupId/artifactId
        if system == 'maven':
            # Replace / with : for consistency with Java version
            name = name_part.replace('/', ':')
        else:
            name = name_part

        return Package(system=system, name=name, version=version)

    @staticmethod
    def _should_include_scope(dep_scope: str, scope_filter: str) -> bool:
        """
        Determine if a dependency scope should be included based on the filter.
        Follows Maven scope semantics.
        """
        if scope_filter == 'all':
            return True

        dep_scope_lower = dep_scope.lower() if dep_scope else 'compile'
        scope_filter_lower = scope_filter.lower()

        if scope_filter_lower == dep_scope_lower:
            return True

        # Runtime scope includes both compile and runtime
        if scope_filter_lower == 'runtime' and dep_scope_lower in ('compile', 'runtime'):
            return True

        return False

    @staticmethod
    def parse_pom_file(file_path: str, scope_filter: str = 'all') -> Tuple[List[Package], Dict[str, str], Dict[str, Set[str]]]:
        """
        Parse a Maven pom.xml file using pymaven for full parent POM resolution.

        Args:
            file_path: Path to the pom.xml file
            scope_filter: Maven scope to include (runtime, compile, provided, test, or all)

        Returns:
            Tuple of (packages, dependency_management, exclusions)
        """
        from .pymaven.client import MavenClient
        from .pymaven.pom import Pom

        # Parse POM metadata to get coordinate
        tree = ET.parse(file_path)
        root = tree.getroot()
        ns = {'m': 'http://maven.apache.org/POM/4.0.0'}

        # Extract basic coordinates from POM
        group_id_elem = root.find('m:groupId', ns)
        artifact_id_elem = root.find('m:artifactId', ns)
        version_elem = root.find('m:version', ns)

        # If not found directly, try parent
        if group_id_elem is None:
            parent_elem = root.find('m:parent', ns)
            if parent_elem is not None:
                group_id_elem = parent_elem.find('m:groupId', ns)
        if version_elem is None:
            parent_elem = root.find('m:parent', ns)
            if parent_elem is not None:
                version_elem = parent_elem.find('m:version', ns)

        group_id = group_id_elem.text if group_id_elem is not None else 'unknown'
        artifact_id = artifact_id_elem.text if artifact_id_elem is not None else 'unknown'
        version = version_elem.text if version_elem is not None else '1.0'

        coordinate = f"{group_id}:{artifact_id}:{version}"

        # Use pymaven to parse with parent resolution
        client = MavenClient('https://repo1.maven.org/maven2/')
        pom = Pom.parse(coordinate, file_path, client=client)

        # Extract dependency management with property substitution
        dep_mgmt = {}
        for (dep_group, dep_artifact), (dep_version, scope, optional) in pom.dependency_management.items():
            key = f"{dep_group}:{dep_artifact}"
            # Apply property substitution to versions from parent
            version_str = str(dep_version)
            version_str = pom._replace_properties(version_str, pom.properties)
            dep_mgmt[key] = version_str

        # Extract dependencies (exclude test scope, include only required, exclude imports/parent/relocations)
        packages = []
        exclusions: Dict[str, Set[str]] = {}

        for scope, deps in pom.dependencies.items():
            # Skip import (BOMs) and relocation
            if scope in ('import', 'relocation'):
                continue

            # Apply scope filtering
            if not FileParser._should_include_scope(scope, scope_filter):
                continue

            for dep, required in deps:
                # Determine effective scope: "optional" if not required, otherwise use Maven scope
                effective_scope = "optional" if not required else scope

                dep_group, dep_artifact, dep_version = dep

                # Skip parent POM (it's included in compile scope by pymaven)
                # Parent has "-parent" suffix typically
                if (dep_group == group_id and dep_artifact == artifact_id) or \
                   (hasattr(pom.parent, 'group_id') and dep_group == pom.parent.group_id and dep_artifact == pom.parent.artifact_id):
                    continue

                # Handle VersionRange objects
                if hasattr(dep_version, 'version'):
                    version_str = str(dep_version.version)
                else:
                    version_str = str(dep_version)

                name = f"{dep_group}:{dep_artifact}"
                packages.append(Package(system='maven', name=name, version=version_str, scope=effective_scope))

        # TODO: Extract exclusions from POM XML (pymaven doesn't expose them directly)
        # For now, falling back to simple XML parsing for exclusions
        deps_elements = root.findall('.//m:dependencies/m:dependency', ns)
        for dep in deps_elements:
            group_id_elem = dep.find('m:groupId', ns)
            artifact_id_elem = dep.find('m:artifactId', ns)

            if group_id_elem is None or artifact_id_elem is None:
                continue

            name = f"{group_id_elem.text}:{artifact_id_elem.text}"

            exclusions_elem = dep.find('m:exclusions', ns)
            if exclusions_elem is not None:
                excluded = set()
                for exclusion in exclusions_elem.findall('m:exclusion', ns):
                    ex_group = exclusion.find('m:groupId', ns)
                    ex_artifact = exclusion.find('m:artifactId', ns)
                    if ex_group is not None and ex_artifact is not None:
                        excluded.add(f"{ex_group.text}:{ex_artifact.text}")
                if excluded:
                    exclusions[name] = excluded

        logger.info(f"Parsed {len(packages)} packages from POM file using pymaven")
        return packages, dep_mgmt, exclusions

    @staticmethod
    def _extract_properties(root, ns, pom_path: str) -> Dict[str, str]:
        """Extract properties from POM, including parent POM properties."""
        properties = {}

        # Extract from current POM
        props_elem = root.find('m:properties', ns)
        if props_elem is not None:
            for prop in props_elem:
                # Remove namespace prefix
                key = prop.tag.split('}')[-1] if '}' in prop.tag else prop.tag
                properties[key] = prop.text

        # Extract project version
        version_elem = root.find('m:version', ns)
        if version_elem is not None:
            properties['project.version'] = version_elem.text

        # Check for parent POM
        parent_elem = root.find('m:parent', ns)
        if parent_elem is not None:
            relative_path_elem = parent_elem.find('m:relativePath', ns)
            if relative_path_elem is not None and relative_path_elem.text:
                parent_path = Path(pom_path).parent / relative_path_elem.text
                if parent_path.exists():
                    try:
                        parent_props = FileParser._extract_properties(
                            ET.parse(parent_path).getroot(), ns, str(parent_path)
                        )
                        # Parent properties don't override child properties
                        for key, value in parent_props.items():
                            if key not in properties:
                                properties[key] = value
                    except Exception as e:
                        logger.warning(f"Could not parse parent POM {parent_path}: {e}")

        return properties

    @staticmethod
    def _extract_dependency_management(root, ns, properties: Dict[str, str]) -> Dict[str, str]:
        """Extract dependency management section from POM."""
        dep_mgmt = {}

        mgmt_elem = root.find('m:dependencyManagement/m:dependencies', ns)
        if mgmt_elem is not None:
            for dep in mgmt_elem.findall('m:dependency', ns):
                group_id_elem = dep.find('m:groupId', ns)
                artifact_id_elem = dep.find('m:artifactId', ns)
                version_elem = dep.find('m:version', ns)

                if group_id_elem is not None and artifact_id_elem is not None and version_elem is not None:
                    group_id = FileParser._resolve_property(group_id_elem.text, properties)
                    artifact_id = FileParser._resolve_property(artifact_id_elem.text, properties)
                    version = FileParser._resolve_property(version_elem.text, properties)

                    key = f"{group_id}:{artifact_id}"
                    dep_mgmt[key] = version

        return dep_mgmt

    @staticmethod
    def _resolve_property(value: str, properties: Dict[str, str]) -> str:
        """Resolve ${property} references in a string."""
        if not value or '${' not in value:
            return value

        # Handle ${property} syntax
        pattern = re.compile(r'\$\{([^}]+)\}')
        matches = pattern.findall(value)

        resolved = value
        for match in matches:
            prop_value = properties.get(match)
            if prop_value:
                resolved = resolved.replace(f"${{{match}}}", prop_value)
            else:
                logger.debug(f"Could not resolve property: {match}")

        return resolved

    @staticmethod
    def parse_requirements_file(file_path: str) -> List[Package]:
        """Parse a Python requirements.txt file."""
        packages = []

        with open(file_path, 'r') as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()

                # Skip empty lines and comments
                if not line or line.startswith('#'):
                    continue

                # Parse package==version, package>=version, etc.
                # Simple parsing - just split on common operators
                for op in ['==', '>=', '<=', '~=', '!=', '>',  '<']:
                    if op in line:
                        parts = line.split(op, 1)
                        if len(parts) == 2:
                            name = parts[0].strip()
                            version = parts[1].strip()
                            # Remove any extras like [extra]
                            name = re.sub(r'\[.*\]', '', name)
                            packages.append(Package(system='pypi', name=name, version=version))
                            break
                else:
                    # No version specifier found
                    logger.warning(f"Line {line_num}: No version specifier in '{line}'")

        logger.info(f"Parsed {len(packages)} packages from requirements.txt")
        return packages

    @staticmethod
    def parse_gradle_file(file_path: str) -> List[Package]:
        """Parse a Gradle build.gradle or build.gradle.kts file."""
        packages = []

        with open(file_path, 'r') as f:
            content = f.read()

        # Regex patterns for Gradle dependencies
        # Supports: implementation 'group:artifact:version'
        # Supports: implementation group: 'group', name: 'artifact', version: 'version'
        patterns = [
            # implementation 'group:artifact:version' or "group:artifact:version"
            r"(?:implementation|compile|api|runtimeOnly)\s+['\"]([^:]+):([^:]+):([^'\"]+)['\"]",
            # implementation group: 'group', name: 'artifact', version: 'version'
            r"(?:implementation|compile|api|runtimeOnly)\s+group:\s*['\"]([^'\"]+)['\"],\s*name:\s*['\"]([^'\"]+)['\"],\s*version:\s*['\"]([^'\"]+)['\"]",
        ]

        for pattern in patterns:
            matches = re.findall(pattern, content)
            for match in matches:
                group_id, artifact_id, version = match
                name = f"{group_id}:{artifact_id}"
                packages.append(Package(system='maven', name=name, version=version))

        # Filter out test dependencies
        test_pattern = r"(?:testImplementation|testCompile|testRuntimeOnly)\s+"
        test_matches = re.findall(test_pattern, content)

        logger.info(f"Parsed {len(packages)} packages from Gradle file (excluded {len(test_matches)} test deps)")
        return packages

    @staticmethod
    def detect_format(file_path: str) -> str:
        """Detect the input file format based on file extension."""
        path = Path(file_path)
        name_lower = path.name.lower()

        if name_lower.endswith('.xml') or name_lower == 'pom.xml':
            return 'pom'
        elif name_lower.endswith('.gradle') or name_lower.endswith('.gradle.kts'):
            return 'gradle'
        elif name_lower == 'requirements.txt':
            return 'pypi'
        elif (name_lower.endswith('.sbom') or name_lower.endswith('.cdx.json') or
              (name_lower.endswith('.json') and any(x in name_lower for x in ['sbom', 'bom', 'cdx']))):
            return 'sbom'
        else:
            return 'flat'
