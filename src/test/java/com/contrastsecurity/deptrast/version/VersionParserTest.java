package com.contrastsecurity.deptrast.version;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

import java.util.Map;

/**
 * Tests for the VersionParser class
 */
public class VersionParserTest {

    @Test
    public void testParseHeroDevsSpringFramework() {
        String version = "5.3.39-spring-framework-5.3.47";
        VersionInfo info = VersionParser.parse(version);

        assertTrue(info.isHeroDevs());
        assertEquals("5.3.47", info.getSbomVersion());
        assertEquals("5.3.39", info.getDepsDevVersion());
        assertEquals(version, info.getOriginalString());

        Map<String, String> metadata = info.getMetadata();
        assertEquals("true", metadata.get("herodevs:nes"));
        assertEquals("5.3.39", metadata.get("herodevs:upstream-version"));
        assertEquals("5.3.47", metadata.get("herodevs:patched-version"));
        assertEquals("spring-framework", metadata.get("herodevs:artifact"));
        assertEquals("HeroDevs", metadata.get("supplier"));
    }

    @Test
    public void testParseHeroDevsSpringBoot() {
        String version = "2.7.18-spring-boot-2.7.27";
        VersionInfo info = VersionParser.parse(version);

        assertTrue(info.isHeroDevs());
        assertEquals("2.7.27", info.getSbomVersion());
        assertEquals("2.7.18", info.getDepsDevVersion());
        assertEquals("spring-boot", info.getMetadata().get("herodevs:artifact"));
    }

    @Test
    public void testParseHeroDevsSpringSecurity() {
        String version = "5.8.16-spring-security-5.8.22";
        VersionInfo info = VersionParser.parse(version);

        assertTrue(info.isHeroDevs());
        assertEquals("5.8.22", info.getSbomVersion());
        assertEquals("5.8.16", info.getDepsDevVersion());
    }

    @Test
    public void testParseHeroDevsWithReleaseSuffix() {
        String version = "2.4.4-spring-ldap-2.4.7.RELEASE";
        VersionInfo info = VersionParser.parse(version);

        assertTrue(info.isHeroDevs());
        assertEquals("2.4.7.RELEASE", info.getSbomVersion());
        assertEquals("2.4.4", info.getDepsDevVersion());
    }

    @Test
    public void testParseHeroDevsSpringSession() {
        String version = "2.7.4-spring-session-2.7.9";
        VersionInfo info = VersionParser.parse(version);

        assertTrue(info.isHeroDevs());
        assertEquals("2.7.9", info.getSbomVersion());
        assertEquals("2.7.4", info.getDepsDevVersion());
    }

    @Test
    public void testParseStandardVersionSimple() {
        String version = "1.2.3";
        VersionInfo info = VersionParser.parse(version);

        assertFalse(info.isHeroDevs());
        assertEquals(version, info.getSbomVersion());
        assertEquals(version, info.getDepsDevVersion());
        assertEquals(version, info.getOriginalString());
        assertTrue(info.getMetadata().isEmpty());
    }

    @Test
    public void testParseStandardVersionWithRelease() {
        String version = "5.3.39.RELEASE";
        VersionInfo info = VersionParser.parse(version);

        assertFalse(info.isHeroDevs());
        assertEquals(version, info.getSbomVersion());
        assertEquals(version, info.getDepsDevVersion());
    }

    @Test
    public void testParseStandardVersionWithSnapshot() {
        String version = "1.0.0-SNAPSHOT";
        VersionInfo info = VersionParser.parse(version);

        assertFalse(info.isHeroDevs());
        assertEquals(version, info.getSbomVersion());
        assertEquals(version, info.getDepsDevVersion());
    }

    @Test
    public void testParseStandardVersionWithQualifier() {
        String version = "3.2.1.Final";
        VersionInfo info = VersionParser.parse(version);

        assertFalse(info.isHeroDevs());
        assertEquals(version, info.getSbomVersion());
        assertEquals(version, info.getDepsDevVersion());
    }

    @Test
    public void testGetDepsDevVersionHeroDevs() {
        String version = "5.3.39-spring-framework-5.3.47";
        String depsDevVersion = VersionParser.getDepsDevVersion(version);

        assertEquals("5.3.39", depsDevVersion);
    }

    @Test
    public void testGetDepsDevVersionStandard() {
        String version = "1.2.3";
        String depsDevVersion = VersionParser.getDepsDevVersion(version);

        assertEquals("1.2.3", depsDevVersion);
    }

    @Test
    public void testGetSbomVersionHeroDevs() {
        String version = "5.3.39-spring-framework-5.3.47";
        String sbomVersion = VersionParser.getSbomVersion(version);

        assertEquals("5.3.47", sbomVersion);
    }

    @Test
    public void testGetSbomVersionStandard() {
        String version = "1.2.3";
        String sbomVersion = VersionParser.getSbomVersion(version);

        assertEquals("1.2.3", sbomVersion);
    }

    @Test
    public void testParseNotHeroDevsSingleHyphen() {
        String version = "1.0.0-beta";
        VersionInfo info = VersionParser.parse(version);

        assertFalse(info.isHeroDevs());
        assertEquals(version, info.getSbomVersion());
    }

    @Test
    public void testParseNotHeroDevsWrongFormat() {
        String version = "1.2.3-rc1";
        VersionInfo info = VersionParser.parse(version);

        assertFalse(info.isHeroDevs());
        assertEquals(version, info.getSbomVersion());
    }

    @Test
    public void testParseVersionWithUnderscores() {
        String version = "1.2.3-some_artifact-1.2.4";
        VersionInfo info = VersionParser.parse(version);

        assertTrue(info.isHeroDevs());
        assertEquals("1.2.4", info.getSbomVersion());
        assertEquals("1.2.3", info.getDepsDevVersion());
        assertEquals("some_artifact", info.getMetadata().get("herodevs:artifact"));
    }

    @Test
    public void testParseNullVersion() {
        VersionInfo info = VersionParser.parse(null);

        assertFalse(info.isHeroDevs());
        assertNull(info.getSbomVersion());
        assertNull(info.getDepsDevVersion());
    }

    @Test
    public void testParseEmptyVersion() {
        String version = "";
        VersionInfo info = VersionParser.parse(version);

        assertFalse(info.isHeroDevs());
        assertEquals("", info.getSbomVersion());
        assertEquals("", info.getDepsDevVersion());
    }
}
