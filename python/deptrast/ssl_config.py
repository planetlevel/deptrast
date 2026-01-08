"""SSL configuration for corporate environments with SSL inspection (e.g., Netskope).

OpenSSL 3.x introduced strict certificate validation that rejects certificates
without proper key usage extensions. Corporate SSL inspection proxies like
Netskope often use certificates that fail this strict validation.

This module provides a configured requests session that works with such proxies.
"""

import os
import ssl
import logging
from typing import Optional

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.ssl_ import create_urllib3_context

logger = logging.getLogger(__name__)

# Known corporate SSL inspection cert bundle locations
CORPORATE_CERT_PATHS = [
    "/Library/Application Support/Netskope/STAgent/data/netskope-cert-bundle.pem",  # Netskope macOS
    "/etc/netskope/cert-bundle.pem",  # Netskope Linux
    "/etc/ssl/certs/ca-certificates.crt",  # Generic Linux
]


def get_corporate_cert_path() -> Optional[str]:
    """Find the corporate SSL certificate bundle if present."""
    for path in CORPORATE_CERT_PATHS:
        if os.path.exists(path):
            return path
    return None


class CorporateSSLAdapter(HTTPAdapter):
    """HTTP adapter that works with corporate SSL inspection proxies.

    This adapter creates an SSL context with relaxed verification flags
    to work around OpenSSL 3.x strict key usage extension requirements.
    """

    def __init__(self, cert_path: Optional[str] = None, **kwargs):
        self.cert_path = cert_path or get_corporate_cert_path()
        super().__init__(**kwargs)

    def init_poolmanager(self, *args, **kwargs):
        """Initialize pool manager with custom SSL context."""
        ctx = create_urllib3_context()

        # Load corporate cert bundle if available
        if self.cert_path and os.path.exists(self.cert_path):
            ctx.load_verify_locations(self.cert_path)
            logger.debug(f"Loaded corporate cert bundle from {self.cert_path}")

        # Relax strict key usage validation (OpenSSL 3.x)
        # This allows certificates that don't have key usage extensions
        ctx.verify_flags = ssl.VERIFY_DEFAULT

        kwargs['ssl_context'] = ctx
        return super().init_poolmanager(*args, **kwargs)


def create_session() -> requests.Session:
    """Create a requests session configured for corporate SSL environments.

    Returns:
        A requests.Session that works with corporate SSL inspection proxies.
    """
    session = requests.Session()

    # Check if we're in a corporate SSL inspection environment
    cert_path = get_corporate_cert_path()

    if cert_path:
        logger.info(f"Detected corporate SSL environment, using {cert_path}")
        adapter = CorporateSSLAdapter(cert_path=cert_path)
        session.mount('https://', adapter)

    return session


# Convenience function to get a configured session
def get_session() -> requests.Session:
    """Get a session configured for the current SSL environment."""
    return create_session()
