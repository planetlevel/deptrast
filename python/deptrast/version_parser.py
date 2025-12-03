"""Version parsing utilities for handling vendor-specific version formats."""

import re
from dataclasses import dataclass
from typing import Optional, Dict


@dataclass
class VersionInfo:
    """
    Parsed version information.

    Attributes:
        sbom_version: Version to use in SBOM (typically the patched/actual version)
        depsdev_version: Version to use for deps.dev API queries (typically the upstream version)
        original_string: The original version string as-is
        is_herodevs: Whether this is a HeroDevs NES version
        metadata: Additional metadata about the version
    """
    sbom_version: str
    depsdev_version: str
    original_string: str
    is_herodevs: bool = False
    metadata: Dict[str, str] = None

    def __post_init__(self):
        if self.metadata is None:
            self.metadata = {}


class VersionParser:
    """Parser for vendor-specific version formats."""

    # HeroDevs NES format: <original>-<artifact>-<patched>
    # Example: 5.3.39-spring-framework-5.3.47
    # The artifact name must NOT contain hyphens followed by version numbers
    HERODEVS_PATTERN = re.compile(
        r'^([0-9]+\.[0-9]+\.[0-9]+(?:[A-Za-z0-9._]*)?)'   # Original version (no trailing hyphen)
        r'-([a-z][a-z0-9_-]*[a-z0-9_])'                   # Artifact name (letters/numbers/hyphens/underscores, not ending with hyphen)
        r'-([0-9]+\.[0-9]+\.[0-9]+(?:[A-Za-z0-9._]*)?)$'  # Patched version
    )

    @classmethod
    def parse(cls, version: str) -> VersionInfo:
        """
        Parse a version string, handling special formats like HeroDevs NES.

        Args:
            version: The version string to parse

        Returns:
            VersionInfo with appropriate versions for different use cases
        """
        # Try HeroDevs NES format
        match = cls.HERODEVS_PATTERN.match(version)
        if match:
            original_version = match.group(1)
            artifact_name = match.group(2)
            patched_version = match.group(3)

            return VersionInfo(
                sbom_version=patched_version,      # Use patched version in SBOM
                depsdev_version=original_version,  # Use original for deps.dev
                original_string=version,
                is_herodevs=True,
                metadata={
                    'herodevs:nes': 'true',
                    'herodevs:upstream-version': original_version,
                    'herodevs:patched-version': patched_version,
                    'herodevs:artifact': artifact_name,
                    'supplier': 'HeroDevs'
                }
            )

        # Standard version - no special handling needed
        return VersionInfo(
            sbom_version=version,
            depsdev_version=version,
            original_string=version,
            is_herodevs=False
        )

    @classmethod
    def get_depsdev_version(cls, version: str) -> str:
        """
        Get the version to use for deps.dev API queries.

        For HeroDevs versions, returns the upstream version.
        For standard versions, returns the version as-is.

        Args:
            version: The version string to parse

        Returns:
            The version to use for deps.dev queries
        """
        version_info = cls.parse(version)
        return version_info.depsdev_version

    @classmethod
    def get_sbom_version(cls, version: str) -> str:
        """
        Get the version to use in SBOM output.

        For HeroDevs versions, returns the patched version.
        For standard versions, returns the version as-is.

        Args:
            version: The version string to parse

        Returns:
            The version to use in SBOM
        """
        version_info = cls.parse(version)
        return version_info.sbom_version
