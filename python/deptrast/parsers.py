"""Input file parsers for various formats."""

import json
import logging
import os
import requests
import re
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import List, Dict, Set, Tuple, Optional
from urllib.parse import urlparse

from .models import Package
from .version_parser import VersionParser

logger = logging.getLogger(__name__)


def _is_url(path: str) -> bool:
    """Check if a path is a URL."""
    try:
        result = urlparse(path)
        return result.scheme in ('http', 'https')
    except:
        return False


def _read_content(path: str) -> str:
    """
    Read content from either a file path or URL.

    Args:
        path: File path or URL

    Returns:
        Content as string

    Raises:
        FileNotFoundError: If file doesn't exist
        requests.RequestException: If URL fetch fails
    """
    if _is_url(path):
        logger.info(f"Fetching content from URL: {path}")
        response = requests.get(path, timeout=30)
        response.raise_for_status()
        return response.text
    else:
        logger.info(f"Reading content from file: {path}")
        with open(path, 'r') as f:
            return f.read()


def _create_package_with_metadata(system: str, name: str, version: str, scope: str = "compile") -> Package:
    """
    Create a Package with version metadata.

    Parses vendor-specific version formats (like HeroDevs NES) and attaches
    metadata to the package for SBOM generation.

    Args:
        system: Package system (maven, npm, pypi)
        name: Package name
        version: Version string (may be vendor-specific format)
        scope: Package scope (default: compile)

    Returns:
        Package instance with version_metadata populated
    """
    version_info = VersionParser.parse(version)
    metadata = version_info.metadata if version_info.is_herodevs else None
    return Package(system=system, name=name, version=version, scope=scope, version_metadata=metadata)


# Helper functions for POM parsing (ported from Java)
MAVEN_CENTRAL_URL = "https://repo1.maven.org/maven2"


def get_element_text(parent: ET.Element, tag_name: str, ns: Dict[str, str]) -> Optional[str]:
    """Get text content of a child element."""
    elem = parent.find(f'm:{tag_name}', ns)
    if elem is not None and elem.text:
        return elem.text.strip()
    return None


def get_direct_project_element_text(root: ET.Element, tag_name: str, ns: Dict[str, str]) -> Optional[str]:
    """Get text content of a direct child of project element, excluding parent element children."""
    # Iterate through direct children only
    for child in root:
        # Skip the parent element entirely
        if child.tag.endswith('parent'):
            continue
        # Check if this is the element we want
        if child.tag.endswith(tag_name):
            if child.text:
                return child.text.strip()
    return None


def resolve_property(value: str, properties: Dict[str, str], max_iterations: int = 10) -> Optional[str]:
    """
    Resolve ${property} references in a string with nesting support.
    Returns None if unresolvable.
    """
    if not value or '${' not in value:
        return value

    resolved = value
    iterations = 0

    while '${' in resolved and iterations < max_iterations:
        start_idx = resolved.find('${')
        end_idx = resolved.find('}', start_idx)

        if start_idx == -1 or end_idx == -1:
            break

        prop_name = resolved[start_idx + 2:end_idx]
        prop_value = properties.get(prop_name)

        if prop_value is None:
            return None

        resolved = resolved[:start_idx] + prop_value + resolved[end_idx + 1:]
        iterations += 1

    if '${' in resolved:
        return None

    return resolved


def parse_properties(root: ET.Element, ns: Dict[str, str]) -> Dict[str, str]:
    """Parse all properties from <properties> section."""
    properties = {}

    props_elem = root.find('m:properties', ns)
    if props_elem is not None:
        for prop in props_elem:
            # Remove namespace from tag
            tag = prop.tag.split('}')[-1] if '}' in prop.tag else prop.tag
            if prop.text:
                properties[tag] = prop.text.strip()

    return properties


def download_pom_from_maven_central(group_id: str, artifact_id: str, version: str) -> Optional[ET.Element]:
    """Download a POM file from Maven Central and return parsed root element."""
    try:
        group_path = group_id.replace('.', '/')
        url = f"{MAVEN_CENTRAL_URL}/{group_path}/{artifact_id}/{version}/{artifact_id}-{version}.pom"

        logger.info(f"Downloading parent POM from Maven Central: {group_id}:{artifact_id}:{version}")
        logger.debug(f"URL: {url}")

        response = requests.get(url, timeout=30)
        if not response.ok:
            logger.warn(f"Failed to download parent POM {group_id}:{artifact_id}:{version}: HTTP {response.status_code}")
            return None

        root = ET.fromstring(response.content)
        logger.info(f"Successfully downloaded and parsed parent POM {group_id}:{artifact_id}:{version}")
        return root

    except Exception as e:
        logger.warn(f"Error downloading parent POM {group_id}:{artifact_id}:{version}: {e}")
        return None


def parse_parent_pom_data(root: ET.Element, current_file_path: str, ns: Dict[str, str]) -> Tuple[Dict[str, str], List[ET.Element]]:
    """
    Recursively parse parent POM hierarchy.
    Returns (properties_dict, list_of_pom_roots) where list is ordered oldest-first.
    """
    properties = {}
    pom_hierarchy = []

    # Look for <parent> element
    parent_elem = root.find('m:parent', ns)
    if parent_elem is None:
        return properties, pom_hierarchy

    # Get parent coordinates
    parent_group_id = get_element_text(parent_elem, 'groupId', ns)
    parent_artifact_id = get_element_text(parent_elem, 'artifactId', ns)
    parent_version = get_element_text(parent_elem, 'version', ns)
    relative_path = get_element_text(parent_elem, 'relativePath', ns) or '../pom.xml'

    parent_root = None
    parent_doc_path = None

    # Check if current file is from Maven Central (synthetic path)
    is_from_maven_central = current_file_path.startswith("maven-central:")

    if is_from_maven_central:
        # Parent of Maven Central POM - download directly
        logger.info(f"Parent of Maven Central POM {parent_group_id}:{parent_artifact_id}:{parent_version}, downloading")
        if parent_group_id and parent_artifact_id and parent_version:
            parent_root = download_pom_from_maven_central(parent_group_id, parent_artifact_id, parent_version)
            if parent_root:
                parent_doc_path = f"maven-central:{parent_group_id}:{parent_artifact_id}:{parent_version}"
    else:
        # Try local filesystem first
        current_path = Path(current_file_path).resolve().parent
        parent_path = (current_path / relative_path).resolve()

        if parent_path.exists():
            try:
                parent_tree = ET.parse(parent_path)
                candidate_root = parent_tree.getroot()

                # Verify coordinates match
                cand_group = get_element_text(candidate_root, 'groupId', ns)
                cand_artifact = get_element_text(candidate_root, 'artifactId', ns)

                if parent_group_id == cand_group and parent_artifact_id == cand_artifact:
                    logger.info(f"Found parent POM at: {parent_path}")
                    parent_root = candidate_root
                    parent_doc_path = str(parent_path)
                else:
                    logger.info(f"Local POM at {parent_path} has different coordinates, will try Maven Central")
            except Exception as e:
                logger.debug(f"Error reading local parent POM: {e}")

        # Try Maven Central if not found locally
        if parent_root is None and parent_group_id and parent_artifact_id and parent_version:
            parent_root = download_pom_from_maven_central(parent_group_id, parent_artifact_id, parent_version)
            if parent_root:
                parent_doc_path = f"maven-central:{parent_group_id}:{parent_artifact_id}:{parent_version}"

    if parent_root is None:
        logger.warn(f"Could not resolve parent POM {parent_group_id}:{parent_artifact_id}:{parent_version}")
        return properties, pom_hierarchy

    # Recursively get grandparent data first
    grandparent_props, grandparent_hierarchy = parse_parent_pom_data(parent_root, parent_doc_path, ns)
    properties.update(grandparent_props)
    pom_hierarchy.extend(grandparent_hierarchy)

    # Then get parent's own properties (override grandparent)
    parent_own_properties = parse_properties(parent_root, ns)
    properties.update(parent_own_properties)

    # Store this POM for later dependencyManagement re-evaluation
    pom_hierarchy.append(parent_root)

    return properties, pom_hierarchy


def parse_dependency_management(root: ET.Element, properties: Dict[str, str], ns: Dict[str, str]) -> Tuple[Dict[str, str], Dict[str, str]]:
    """Parse <dependencyManagement> section including BOM imports.

    Returns:
        Tuple of (managed_versions, managed_scopes) where both are dicts mapping groupId:artifactId to version/scope
    """
    managed_versions = {}
    managed_scopes = {}

    mgmt_elem = root.find('m:dependencyManagement', ns)
    if mgmt_elem is None:
        return managed_versions, managed_scopes

    deps_elem = mgmt_elem.find('m:dependencies', ns)
    if deps_elem is None:
        return managed_versions, managed_scopes

    for dep in deps_elem.findall('m:dependency', ns):
        group_id = get_element_text(dep, 'groupId', ns)
        artifact_id = get_element_text(dep, 'artifactId', ns)
        version = get_element_text(dep, 'version', ns)
        scope = get_element_text(dep, 'scope', ns)
        dep_type = get_element_text(dep, 'type', ns)

        # Handle BOM imports (scope=import, type=pom)
        if scope == 'import' and dep_type == 'pom':
            if group_id and artifact_id and version:
                # Resolve version if needed
                if version and '${' in version:
                    resolved_version = resolve_property(version, properties)
                    if resolved_version and '${' not in resolved_version:
                        version = resolved_version
                    else:
                        logger.debug(f"Could not resolve version {version} for BOM import {group_id}:{artifact_id}")
                        continue

                logger.info(f"Importing BOM: {group_id}:{artifact_id}:{version}")

                # Download and parse the imported BOM
                bom_root = download_pom_from_maven_central(group_id, artifact_id, version)
                if bom_root:
                    # Recursively parse BOM's dependencyManagement
                    imported_versions, imported_scopes = parse_dependency_management(bom_root, properties, ns)
                    managed_versions.update(imported_versions)
                    managed_scopes.update(imported_scopes)
                    logger.info(f"Imported {len(imported_versions)} managed versions from BOM {group_id}:{artifact_id}")
                else:
                    logger.warn(f"Failed to download BOM: {group_id}:{artifact_id}:{version}")

            continue  # Don't add BOM import itself to managed_versions

        if group_id and artifact_id and version:
            # Resolve property references
            if version and '${' in version:
                resolved_version = resolve_property(version, properties)
                if resolved_version and '${' not in resolved_version:
                    version = resolved_version
                else:
                    logger.debug(f"Could not resolve version {version} for {group_id}:{artifact_id}")
                    continue

            key = f"{group_id}:{artifact_id}"
            managed_versions[key] = version

            # Store managed scope if present
            if scope:
                managed_scopes[key] = scope

    logger.info(f"Parsed {len(managed_versions)} managed dependency versions from dependencyManagement")
    return managed_versions, managed_scopes


def parse_exclusions(dep_elem: ET.Element, ns: Dict[str, str]) -> Set[str]:
    """Parse <exclusions> from a dependency element."""
    exclusions = set()

    exclusions_elem = dep_elem.find('m:exclusions', ns)
    if exclusions_elem is None:
        return exclusions

    for exclusion in exclusions_elem.findall('m:exclusion', ns):
        ex_group = get_element_text(exclusion, 'groupId', ns)
        ex_artifact = get_element_text(exclusion, 'artifactId', ns)

        if ex_group and ex_artifact:
            exclusions.add(f"{ex_group}:{ex_artifact}")
            logger.debug(f"Found exclusion: {ex_group}:{ex_artifact}")

    return exclusions


def should_include_scope(dep_scope: str, scope_filter: str) -> bool:
    """Check if a dependency scope should be included based on filter."""
    if scope_filter == 'all':
        return True

    dep_scope_lower = dep_scope.lower() if dep_scope else 'compile'
    scope_filter_lower = scope_filter.lower()

    if scope_filter_lower == dep_scope_lower:
        return True

    # Runtime filter includes both compile and runtime
    if scope_filter_lower == 'runtime' and dep_scope_lower in ('compile', 'runtime'):
        return True

    return False




class FileParser:
    """Parser for various input file formats."""

    @staticmethod
    def parse_flat_file(file_path: str) -> List[Package]:
        """
        Parse a flat file with system:name:version per line.
        Supports both local files and URLs.

        Example:
            maven:org.springframework.boot:spring-boot-starter-web:3.1.0
            npm:react:18.2.0
            pypi:requests:2.28.1
        """
        packages = []
        content = _read_content(file_path)

        for line_num, line in enumerate(content.splitlines(), 1):
            line = line.strip()

            # Skip empty lines and comments
            if not line or line.startswith('#'):
                continue

            # Skip Maven warning and info lines
            import re
            if re.match(r'^\[WARNING\]', line, re.IGNORECASE):
                continue
            if re.match(r'^\[INFO\].*---.*---', line, re.IGNORECASE):  # Maven goal headers like "[INFO] --- dependency:tree ---"
                continue

            # Strip Maven tree visualization characters if present
            # Examples: "[INFO] +- ", "[INFO] |  \- ", "[INFO]    ", etc.
            maven_tree_pattern = r'^\[INFO\]\s*[\|\\+\-\s]*'
            line = re.sub(maven_tree_pattern, '', line, flags=re.IGNORECASE)

            # Skip lines that don't look like dependencies after stripping
            if not line or len(line.split(':')) < 3:
                continue

            # Parse system:name:version format
            parts = line.split(':')
            if len(parts) < 3:
                logger.debug(f"Line {line_num}: Skipping non-dependency line '{line}'")
                continue

            # Check if this is Maven dependency:tree format: groupId:artifactId:type:version:scope
            # or if it has an explicit system prefix like maven:groupId:artifactId:version
            if len(parts) >= 5 and parts[2] == 'jar':
                # Maven dependency:tree format: groupId:artifactId:jar:version:scope
                system = 'maven'
                name = f"{parts[0]}:{parts[1]}"
                version = parts[3]
                scope = parts[4] if len(parts) > 4 else 'compile'
                pkg = _create_package_with_metadata(system=system, name=name, version=version, scope=scope)
                packages.append(pkg)
                continue

            system = parts[0]
            # Handle maven groupId:artifactId format with system prefix
            if system.lower() == 'maven' and len(parts) >= 4:
                name = f"{parts[1]}:{parts[2]}"
                version = parts[3]
            else:
                name = parts[1]
                version = ':'.join(parts[2:])  # Handle versions with colons

            packages.append(_create_package_with_metadata(system=system, name=name, version=version))

        logger.info(f"Parsed {len(packages)} packages from flat file")
        return packages

    @staticmethod
    def parse_sbom_file(file_path: str) -> List[Package]:
        """Parse a CycloneDX SBOM JSON file. Supports both local files and URLs."""
        content = _read_content(file_path)
        sbom = json.loads(content)

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

        return _create_package_with_metadata(system=system, name=name, version=version)

    @staticmethod
    def _resolve_parent_properties(file_path: str) -> Dict[str, str]:
        """
        Recursively load parent POMs from local filesystem and collect properties.
        This allows resolving ${revision} and other placeholders before calling pymaven.
        """
        properties = {}
        current_path = Path(file_path).resolve()

        try:
            tree = ET.parse(current_path)
            root = tree.getroot()
            ns = {'m': 'http://maven.apache.org/POM/4.0.0'}

            # Check if this POM has a parent
            parent_elem = root.find('m:parent', ns)
            if parent_elem is not None:
                # Get relativePath (defaults to ../pom.xml)
                relative_path_elem = parent_elem.find('m:relativePath', ns)
                relative_path = relative_path_elem.text if relative_path_elem is not None else '../pom.xml'

                # Resolve parent path
                parent_path = (current_path.parent / relative_path).resolve()

                if parent_path.exists():
                    # Recursively get grandparent properties first
                    properties.update(FileParser._resolve_parent_properties(str(parent_path)))

                    # Then load this parent's properties (override grandparent)
                    parent_tree = ET.parse(parent_path)
                    parent_root = parent_tree.getroot()
                    props_elem = parent_root.find('m:properties', ns)
                    if props_elem is not None:
                        for prop in props_elem:
                            # Remove namespace from tag
                            tag = prop.tag.split('}')[-1] if '}' in prop.tag else prop.tag
                            if prop.text:
                                properties[tag] = prop.text

            # Finally load this POM's own properties (override parent)
            props_elem = root.find('m:properties', ns)
            if props_elem is not None:
                for prop in props_elem:
                    tag = prop.tag.split('}')[-1] if '}' in prop.tag else prop.tag
                    if prop.text:
                        properties[tag] = prop.text

        except Exception as e:
            logger.debug(f"Could not load parent properties: {e}")

        return properties

    @staticmethod
    def parse_pom_file(file_path: str, scope_filter: str = 'all', include_optional: bool = False) -> Tuple[List, Dict[str, str], Dict[str, Set[str]], Optional[Dict[str, str]]]:
        """
        Parse a Maven pom.xml file using pure XML parsing (no pymaven).
        Based on Java FileParser logic.

        Args:
            file_path: Path to the pom.xml file
            scope_filter: Maven scope to include (runtime, compile, provided, test, or all)
            include_optional: Whether to include optional/provided dependencies

        Returns:
            Tuple of (packages, dependency_management, exclusions, project_metadata)
            where project_metadata is a dict with group, name, version, description
        """
          # Import here to avoid circular import

        packages = []
        dependency_management = {}
        managed_scopes = {}
        exclusions_map = {}
        project_metadata = {}
        ns = {'m': 'http://maven.apache.org/POM/4.0.0'}

        try:
            tree = ET.parse(file_path)
            root = tree.getroot()

            # Extract project metadata for SBOM metadata.component
            # Use get_direct_project_element_text to avoid getting values from <parent>
            project_group = get_direct_project_element_text(root, 'groupId', ns)
            project_artifact = get_direct_project_element_text(root, 'artifactId', ns)
            project_version = get_direct_project_element_text(root, 'version', ns)
            project_name = get_direct_project_element_text(root, 'name', ns)
            project_description = get_direct_project_element_text(root, 'description', ns)
            project_packaging = get_direct_project_element_text(root, 'packaging', ns)

            # Inherit groupId/version from parent if not specified
            parent_elem = root.find('m:parent', ns)
            if parent_elem is not None:
                if not project_group:
                    project_group = get_element_text(parent_elem, 'groupId', ns)
                if not project_version:
                    project_version = get_element_text(parent_elem, 'version', ns)

            # Load parent POM data (properties and hierarchy)
            parent_properties, pom_hierarchy = parse_parent_pom_data(root, file_path, ns)

            logger.info(f"Loaded {len(parent_properties)} properties from parent POM hierarchy")

            # Parse properties from current POM (override parent)
            current_properties = parse_properties(root, ns)
            all_properties = {**parent_properties, **current_properties}
            logger.info(f"Loaded {len(all_properties)} properties total ({len(current_properties)} from current pom.xml)")

            # Parse ALL dependencyManagement sections with FINAL merged properties
            # Parse from parent hierarchy first (oldest first)
            for pom_root in pom_hierarchy:
                pom_dep_mgmt_vers, pom_dep_mgmt_scopes = parse_dependency_management(pom_root, all_properties, ns)
                dependency_management.update(pom_dep_mgmt_vers)
                managed_scopes.update(pom_dep_mgmt_scopes)

            # Parse dependency management from current POM (overrides parents)
            current_dep_mgmt_vers, current_dep_mgmt_scopes = parse_dependency_management(root, all_properties, ns)
            dependency_management.update(current_dep_mgmt_vers)
            managed_scopes.update(current_dep_mgmt_scopes)

            logger.info(f"Total {len(dependency_management)} managed dependency versions")
            logger.info(f"Total {len(managed_scopes)} managed dependency scopes")

            # NOW resolve project version using loaded properties and create metadata
            if project_version and '${' in project_version:
                resolved_version = resolve_property(project_version, all_properties)
                if resolved_version and '${' not in resolved_version:
                    project_version = resolved_version
                    logger.info(f"Resolved project version to: {project_version}")

            if project_group and project_artifact:
                project_metadata = {
                    'group': project_group,
                    'name': project_artifact,  # CycloneDX uses 'name' for artifactId
                    'version': project_version or 'unknown',
                    'type': 'application',  # Maven projects are typically applications
                    'packaging': project_packaging or 'jar'
                }

                # Add optional fields if present
                if project_name and project_name != project_artifact:
                    project_metadata['displayName'] = project_name
                if project_description:
                    project_metadata['description'] = project_description

                logger.info(f"Created project metadata: {project_group}:{project_artifact}:{project_version}")

            # Find root <dependencies> section (not from <dependencyManagement> or <build>)
            # Look for <project><dependencies> directly
            dependency_nodes = []
            for child in root:
                if child.tag.endswith('dependencies'):
                    # This is a direct child of project - it's the root dependencies
                    dependency_nodes = child.findall('m:dependency', ns)
                    logger.info(f"Found root <dependencies> section with {len(dependency_nodes)} dependencies")
                    break
    
            # If no root dependencies found, it's a parent POM
            if not dependency_nodes:
                logger.info("No root <dependencies> section found (parent POM)")
    
            # Parse dependencies
            for dep in dependency_nodes:
                # Get groupId and artifactId first (needed for scope inheritance)
                group_id = get_element_text(dep, 'groupId', ns)
                artifact_id = get_element_text(dep, 'artifactId', ns)
                key = f"{group_id}:{artifact_id}"

                # Get scope - check managed scopes before defaulting to 'compile'
                scope = get_element_text(dep, 'scope', ns)
                if not scope:
                    scope = managed_scopes.get(key)
                    if scope:
                        logger.debug(f"Inherited scope {scope} for {group_id}:{artifact_id} from dependencyManagement")
                    else:
                        scope = 'compile'  # Maven default

                logger.debug(f"Dependency {group_id}:{artifact_id} has scope: {scope}")

                # Skip provided scope unless includeOptional
                if not include_optional and scope == 'provided':
                    logger.info(f"Skipping provided scope dependency: {group_id}:{artifact_id}")
                    continue

                # Skip optional unless includeOptional
                optional = get_element_text(dep, 'optional', ns)
                if not include_optional and optional == 'true':
                    logger.info(f"Skipping optional dependency: {group_id}:{artifact_id}")
                    continue

                # Apply scope filtering
                if not should_include_scope(scope, scope_filter):
                    logger.info(f"Skipping {scope} scope dependency: {group_id}:{artifact_id} (filter: {scope_filter})")
                    continue
                version = get_element_text(dep, 'version', ns)
    
                # Parse exclusions for this dependency
                dep_exclusions = parse_exclusions(dep, ns)
    
                if group_id and artifact_id:
                    # If version not specified, get from dependency management
                    if not version:
                        version = dependency_management.get(key)
                        if version:
                            logger.info(f"Resolved version for {group_id}:{artifact_id} from dependencyManagement: {version}")
                        else:
                            logger.warn(f"Skipping dependency with no version: {group_id}:{artifact_id}")
                            continue
                    elif version and '${' in version:
                        # Resolve property placeholder
                        resolved_version = resolve_property(version, all_properties)
                        if resolved_version and '${' not in resolved_version:
                            version = resolved_version
                            logger.info(f"Resolved property version for {group_id}:{artifact_id} to {version}")
                        else:
                            logger.warn(f"Skipping dependency with unresolvable version: {group_id}:{artifact_id}:{version}")
                            continue

                    # ALWAYS check if dependency management overrides this version
                    # This matches Maven's behavior where dependency management wins
                    key = f"{group_id}:{artifact_id}"
                    managed_version = dependency_management.get(key)
                    if managed_version and managed_version != version:
                        logger.info(f"Overriding {group_id}:{artifact_id} version {version} with managed version {managed_version}")
                        version = managed_version

                    name = f"{group_id}:{artifact_id}"
                    # Use "optional" scope if optional=true, otherwise use Maven scope
                    effective_scope = "optional" if optional == 'true' else scope

                    pkg = _create_package_with_metadata(system='maven', name=name, version=version, scope=effective_scope)
                    packages.append(pkg)
                    pkg_name = f"{pkg.system}:{pkg.name}:{pkg.version}"
                    logger.info(f"Added package from pom.xml: {pkg_name} (scope: {effective_scope})")

                    # Store exclusions
                    if dep_exclusions:
                        exclusions_map[name] = dep_exclusions
                        logger.info(f"Package {name} has {len(dep_exclusions)} exclusions")
    
            logger.info(f"Parsed {len(packages)} packages from pom.xml")
    
        except Exception as e:
            logger.error(f"Error parsing pom.xml file {file_path}: {e}")
            import traceback
            traceback.print_exc()

        return packages, dependency_management, exclusions_map, project_metadata
    

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
                            packages.append(_create_package_with_metadata(system='pypi', name=name, version=version))
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
                packages.append(_create_package_with_metadata(system='maven', name=name, version=version))

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
