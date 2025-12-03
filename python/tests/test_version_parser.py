"""Tests for version parsing utilities."""

import pytest
from deptrast.version_parser import VersionParser, VersionInfo


class TestVersionParser:
    """Tests for the VersionParser class."""

    def test_parse_herodevs_spring_framework(self):
        """Test parsing HeroDevs Spring Framework version."""
        version = "5.3.39-spring-framework-5.3.47"
        info = VersionParser.parse(version)

        assert info.is_herodevs is True
        assert info.sbom_version == "5.3.47"
        assert info.depsdev_version == "5.3.39"
        assert info.original_string == version
        assert info.metadata['herodevs:nes'] == 'true'
        assert info.metadata['herodevs:upstream-version'] == '5.3.39'
        assert info.metadata['herodevs:patched-version'] == '5.3.47'
        assert info.metadata['herodevs:artifact'] == 'spring-framework'
        assert info.metadata['supplier'] == 'HeroDevs'

    def test_parse_herodevs_spring_boot(self):
        """Test parsing HeroDevs Spring Boot version."""
        version = "2.7.18-spring-boot-2.7.27"
        info = VersionParser.parse(version)

        assert info.is_herodevs is True
        assert info.sbom_version == "2.7.27"
        assert info.depsdev_version == "2.7.18"
        assert info.metadata['herodevs:artifact'] == 'spring-boot'

    def test_parse_herodevs_spring_security(self):
        """Test parsing HeroDevs Spring Security version."""
        version = "5.8.16-spring-security-5.8.22"
        info = VersionParser.parse(version)

        assert info.is_herodevs is True
        assert info.sbom_version == "5.8.22"
        assert info.depsdev_version == "5.8.16"

    def test_parse_herodevs_with_release_suffix(self):
        """Test parsing HeroDevs version with RELEASE suffix."""
        version = "2.4.4-spring-ldap-2.4.7.RELEASE"
        info = VersionParser.parse(version)

        assert info.is_herodevs is True
        assert info.sbom_version == "2.4.7.RELEASE"
        assert info.depsdev_version == "2.4.4"

    def test_parse_herodevs_spring_session(self):
        """Test parsing HeroDevs Spring Session version."""
        version = "2.7.4-spring-session-2.7.9"
        info = VersionParser.parse(version)

        assert info.is_herodevs is True
        assert info.sbom_version == "2.7.9"
        assert info.depsdev_version == "2.7.4"

    def test_parse_standard_version_simple(self):
        """Test parsing standard semantic version."""
        version = "1.2.3"
        info = VersionParser.parse(version)

        assert info.is_herodevs is False
        assert info.sbom_version == version
        assert info.depsdev_version == version
        assert info.original_string == version
        assert len(info.metadata) == 0

    def test_parse_standard_version_with_release(self):
        """Test parsing standard version with RELEASE suffix."""
        version = "5.3.39.RELEASE"
        info = VersionParser.parse(version)

        assert info.is_herodevs is False
        assert info.sbom_version == version
        assert info.depsdev_version == version

    def test_parse_standard_version_with_snapshot(self):
        """Test parsing standard version with SNAPSHOT suffix."""
        version = "1.0.0-SNAPSHOT"
        info = VersionParser.parse(version)

        assert info.is_herodevs is False
        assert info.sbom_version == version
        assert info.depsdev_version == version

    def test_parse_standard_version_with_qualifier(self):
        """Test parsing standard version with qualifier."""
        version = "3.2.1.Final"
        info = VersionParser.parse(version)

        assert info.is_herodevs is False
        assert info.sbom_version == version
        assert info.depsdev_version == version

    def test_get_depsdev_version_herodevs(self):
        """Test convenience method for getting deps.dev version."""
        version = "5.3.39-spring-framework-5.3.47"
        depsdev_version = VersionParser.get_depsdev_version(version)

        assert depsdev_version == "5.3.39"

    def test_get_depsdev_version_standard(self):
        """Test convenience method for standard version."""
        version = "1.2.3"
        depsdev_version = VersionParser.get_depsdev_version(version)

        assert depsdev_version == "1.2.3"

    def test_get_sbom_version_herodevs(self):
        """Test convenience method for getting SBOM version."""
        version = "5.3.39-spring-framework-5.3.47"
        sbom_version = VersionParser.get_sbom_version(version)

        assert sbom_version == "5.3.47"

    def test_get_sbom_version_standard(self):
        """Test convenience method for standard version."""
        version = "1.2.3"
        sbom_version = VersionParser.get_sbom_version(version)

        assert sbom_version == "1.2.3"

    def test_parse_not_herodevs_single_hyphen(self):
        """Test that versions with single hyphen are not parsed as HeroDevs."""
        version = "1.0.0-beta"
        info = VersionParser.parse(version)

        assert info.is_herodevs is False
        assert info.sbom_version == version

    def test_parse_not_herodevs_wrong_format(self):
        """Test that versions without proper version numbers don't match HeroDevs pattern."""
        version = "1.2.3-rc1"  # Only one hyphen, not HeroDevs format
        info = VersionParser.parse(version)

        assert info.is_herodevs is False
        assert info.sbom_version == version

    def test_parse_version_with_underscores(self):
        """Test parsing version with underscores in artifact name."""
        version = "1.2.3-some_artifact-1.2.4"
        info = VersionParser.parse(version)

        assert info.is_herodevs is True
        assert info.sbom_version == "1.2.4"
        assert info.depsdev_version == "1.2.3"
        assert info.metadata['herodevs:artifact'] == 'some_artifact'

    def test_version_info_defaults(self):
        """Test VersionInfo default initialization."""
        info = VersionInfo(
            sbom_version="1.0.0",
            depsdev_version="1.0.0",
            original_string="1.0.0"
        )

        assert info.is_herodevs is False
        assert info.metadata == {}
