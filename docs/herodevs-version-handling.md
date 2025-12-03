# HeroDevs NES Version Handling

## Problem

HeroDevs Never-Ending Support (NES) uses a special version format:
```
<original-version>-<artifact-name>-<patched-version>
```

Example: `5.3.39-spring-framework-5.3.47`

This creates challenges for:
1. **deps.dev API queries** - Only knows about upstream versions (5.3.39)
2. **SBOM generation** - Should reflect the actual patched version (5.3.47)
3. **Vulnerability scanning** - Needs to know it's patched, not vulnerable

## Solution

### Python Implementation

#### 1. Version Parser (`deptrast/version_parser.py`)

Parses HeroDevs versions and provides:
- `sbom_version`: Patched version for SBOM (5.3.47)
- `depsdev_version`: Original version for deps.dev API (5.3.39)
- `metadata`: Rich metadata for SBOM properties

```python
from deptrast.version_parser import VersionParser

version = "5.3.39-spring-framework-5.3.47"
info = VersionParser.parse(version)

# For SBOM
print(info.sbom_version)  # "5.3.47"

# For deps.dev API
print(info.depsdev_version)  # "5.3.39"

# Metadata
print(info.metadata)
# {
#   'herodevs:nes': 'true',
#   'herodevs:upstream-version': '5.3.39',
#   'herodevs:patched-version': '5.3.47',
#   'herodevs:artifact': 'spring-framework',
#   'supplier': 'HeroDevs'
# }
```

#### 2. API Client Integration (`deptrast/api_client.py`)

Automatically uses upstream version for deps.dev queries:

```python
# Given package with HeroDevs version
package = Package(
    system="maven",
    name="org.springframework:spring-core",
    version="5.3.39-spring-framework-5.3.47"
)

# API client automatically uses 5.3.39 for deps.dev
graph = client.get_dependency_graph(package)
# Queries: /maven/packages/org.springframework:spring-core/versions/5.3.39:dependencies
```

#### 3. Package Model (`deptrast/models.py`)

Package now includes `version_metadata` field:

```python
package = Package(
    system="maven",
    name="org.springframework:spring-core",
    version="5.3.39-spring-framework-5.3.47",
    version_metadata={
        'herodevs:nes': 'true',
        'herodevs:upstream-version': '5.3.39',
        'herodevs:patched-version': '5.3.47',
        # ...
    }
)
```

#### 4. Graph Builder Integration (`deptrast/graph_builder.py`)

Automatically populates metadata when creating packages:

```python
# Internal method now parses versions
pkg = self._create_package("maven", "org.springframework:spring-core", "5.3.39-spring-framework-5.3.47")
# pkg.version_metadata is automatically populated
```

## Usage

### For deps.dev Queries
Always use the **upstream version** (5.3.39) - this is what deps.dev knows about from Maven Central.

### For SBOM Generation
Use the **patched version** (5.3.47) as the primary version, but include properties:

```json
{
  "group": "org.springframework",
  "name": "spring-core",
  "version": "5.3.47",
  "purl": "pkg:maven/org.springframework/spring-core@5.3.47",
  "supplier": {
    "name": "HeroDevs"
  },
  "properties": [
    {
      "name": "herodevs:nes",
      "value": "true"
    },
    {
      "name": "herodevs:upstream-version",
      "value": "5.3.39"
    },
    {
      "name": "herodevs:deps-dev-purl",
      "value": "pkg:maven/org.springframework/spring-core@5.3.39"
    }
  ]
}
```

### For Vulnerability Scanning
- Primary version (5.3.47) helps indicate it's patched
- Upstream version in properties allows correlation with CVE databases
- `herodevs:nes` property indicates patches may address CVEs

## Testing

Comprehensive test coverage in:
- `python/tests/test_version_parser.py` - Version parsing logic
- `python/tests/test_api_integration.py` - API client integration

Run tests:
```bash
python3 -m pytest python/tests/test_version_parser.py -v
python3 -m pytest python/tests/test_api_integration.py -v
```

## Java Port (TODO)

The Python implementation should be ported to Java:

1. Create `VersionParser.java` with similar logic
2. Update `DepsDevClient.java` to use upstream versions
3. Add `versionMetadata` field to `Package.java`
4. Update `DependencyGraphBuilder.java` to populate metadata
5. Add comprehensive tests

### Java Implementation Sketch

```java
public class VersionParser {
    private static final Pattern HERODEVS_PATTERN =
        Pattern.compile("^([0-9]+\\.[0-9]+\\.[0-9]+(?:[A-Za-z0-9._]*)?)" +
                       "-([a-z][a-z0-9_-]*[a-z0-9_])" +
                       "-([0-9]+\\.[0-9]+\\.[0-9]+(?:[A-Za-z0-9._]*)?)$");

    public static VersionInfo parse(String version) {
        Matcher matcher = HERODEVS_PATTERN.matcher(version);
        if (matcher.matches()) {
            return new VersionInfo(
                matcher.group(3),  // sbomVersion (patched)
                matcher.group(1),  // depsDevVersion (original)
                version,           // originalString
                true,              // isHeroDevs
                buildMetadata(matcher)
            );
        }
        return new VersionInfo(version, version, version, false, null);
    }

    public static String getDepsDevVersion(String version) {
        return parse(version).getDepsDevVersion();
    }
}
```

## References

- HeroDevs NES: https://www.herodevs.com/support/nes-documentation
- CycloneDX Pedigree: https://cyclonedx.org/use-cases/#pedigree
- deps.dev API: https://docs.deps.dev/api/v3/
