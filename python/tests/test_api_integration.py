"""Integration tests for API client with version parsing."""

import pytest
from unittest.mock import Mock, patch
from deptrast.api_client import DepsDevClient
from deptrast.models import Package


class TestDepsDevClientIntegration:
    """Integration tests for DepsDevClient with version parsing."""

    @patch('deptrast.api_client.requests.Session')
    def test_herodevs_version_uses_upstream_for_api(self, mock_session_class):
        """Test that HeroDevs versions use upstream version for deps.dev API calls."""
        # Setup mock
        mock_session = Mock()
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {'nodes': [], 'edges': []}
        mock_session.get.return_value = mock_response
        mock_session_class.return_value = mock_session

        # Create client and package
        client = DepsDevClient()
        package = Package(
            system="maven",
            name="org.springframework:spring-core",
            version="5.3.39-spring-framework-5.3.47"  # HeroDevs NES version
        )

        # Make API call
        result = client.get_dependency_graph(package)

        # Verify the API was called with the upstream version (5.3.39), not patched (5.3.47)
        mock_session.get.assert_called_once()
        call_args = mock_session.get.call_args
        url = call_args[0][0]

        assert "5.3.39:dependencies" in url
        assert "5.3.47" not in url
        assert result is not None

    @patch('deptrast.api_client.requests.Session')
    def test_standard_version_unchanged(self, mock_session_class):
        """Test that standard versions are used as-is for deps.dev API calls."""
        # Setup mock
        mock_session = Mock()
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {'nodes': [], 'edges': []}
        mock_session.get.return_value = mock_response
        mock_session_class.return_value = mock_session

        # Create client and package
        client = DepsDevClient()
        package = Package(
            system="maven",
            name="org.springframework:spring-core",
            version="5.3.39"  # Standard version
        )

        # Make API call
        result = client.get_dependency_graph(package)

        # Verify the API was called with the version as-is
        mock_session.get.assert_called_once()
        call_args = mock_session.get.call_args
        url = call_args[0][0]

        assert "5.3.39:dependencies" in url
        assert result is not None

    @patch('deptrast.api_client.requests.Session')
    def test_url_encoding_with_herodevs(self, mock_session_class):
        """Test that URL encoding works correctly with HeroDevs versions."""
        # Setup mock
        mock_session = Mock()
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {'nodes': [], 'edges': []}
        mock_session.get.return_value = mock_response
        mock_session_class.return_value = mock_session

        # Create client and package
        client = DepsDevClient()
        package = Package(
            system="maven",
            name="org.springframework:spring-boot",
            version="2.7.18-spring-boot-2.7.27"
        )

        # Make API call
        result = client.get_dependency_graph(package)

        # Verify URL encoding and version parsing
        mock_session.get.assert_called_once()
        call_args = mock_session.get.call_args
        url = call_args[0][0]

        # Package name should be URL-encoded (: becomes %3A)
        assert "org.springframework%3Aspring-boot" in url
        # Should use upstream version 2.7.18, not patched 2.7.27
        assert "2.7.18:dependencies" in url
        assert "2.7.27" not in url
        assert result is not None
