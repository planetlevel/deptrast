"""Client for interacting with the deps.dev API."""

import logging
from typing import Optional, Dict, Any
from urllib.parse import quote

import requests

from .models import Package
from .version_parser import VersionParser

logger = logging.getLogger(__name__)


class DepsDevClient:
    """Client for fetching dependency information from deps.dev API."""

    BASE_URL = "https://api.deps.dev/v3/systems"

    def __init__(self):
        """Initialize the API client."""
        self.session = requests.Session()
        self.session.headers.update({
            "Accept": "application/json",
            "User-Agent": "deptrast/3.0.1"
        })

    def get_dependency_graph(self, package: Package) -> Optional[Dict[str, Any]]:
        """
        Get the dependency graph for a package from deps.dev API.

        For vendor-patched versions (like HeroDevs NES), this uses the upstream
        version for deps.dev queries since deps.dev only knows about the original
        Maven Central versions.

        Args:
            package: The package to fetch dependencies for

        Returns:
            JSON response containing nodes and edges, or None if request fails
        """
        # Parse version to handle vendor-specific formats (e.g., HeroDevs)
        depsdev_version = VersionParser.get_depsdev_version(package.version)

        # URL-encode the package name to handle special characters like ':'
        encoded_name = quote(package.name, safe='')
        url = (
            f"{self.BASE_URL}/{package.system}/packages/{encoded_name}"
            f"/versions/{depsdev_version}:dependencies"
        )

        logger.debug(f"Fetching dependency graph for {package.full_name}")
        if depsdev_version != package.version:
            logger.debug(f"  Original version: {package.version}")
            logger.debug(f"  deps.dev version: {depsdev_version}")
        logger.debug(f"  URL: {url}")

        try:
            response = self.session.get(url, timeout=30)
            if response.status_code == 200:
                return response.json()
            else:
                logger.info(
                    f"Failed to get dependency graph for {package.full_name}: "
                    f"HTTP {response.status_code}"
                )
                return None
        except requests.RequestException as e:
            logger.error(f"Error fetching dependencies for {package.full_name}: {e}")
            return None

    def close(self):
        """Close the session and clean up resources."""
        self.session.close()

    def __enter__(self):
        """Context manager entry."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.close()
