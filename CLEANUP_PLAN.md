# Deptrast Code Cleanup Plan

## Executive Summary

The codebase is functional but has accumulated technical debt. This plan prioritizes cleanup tasks by risk/impact.

## Quick Wins (Low Risk, High Value)

### 1. Remove Deprecated Methods ✓ Safe
**Files**:
- `FileParser.java:240-243` - Remove `parsePomFile()`
- `DepsDevClient.java:133-182` - Remove `getDependencies()`

**Verification**: Grep confirms neither method is called
**Risk**: None - methods are unused
**Benefit**: Reduces LOC by ~54 lines

### 2. Clean Up Comments ✓ Safe
**Files**: All files with excessive comments
**Actions**:
- Remove redundant comments that just restate code
- Keep JavaDoc and algorithm explanations
- Remove empty comment blocks

**Risk**: None
**Benefit**: Better code readability, ~100 lines reduced

### 3. Extract Constants ✓ Safe
**Create**: `com.contrastsecurity.deptrast.constants.PackageSystem`
```java
public enum PackageSystem {
    MAVEN("maven"),
    NPM("npm"),
    PYPI("pypi"),
    NUGET("nuget"),
    GO("go"),
    CARGO("cargo");

    private final String value;
    // ...
}
```

**Benefit**: Type safety, prevents typos
**Risk**: Low - simple refactor

### 4. Remove Dead Code (If confirmed unused externally)
**Files**:
- `PackageDependencyInfo.java` (entire file - 140 lines)
- `PackageCache.getDetailedDependencyInfo()` (method)

**Verification Needed**: Confirm no external tools use this API
**Risk**: Medium if used externally
**Benefit**: -140 lines, simpler codebase

## Medium Priority (Moderate Risk, High Value)

### 5. Extract SSL Configuration ✓ Reduces duplication
**Create**: `com.contrastsecurity.deptrast.util.SSLUtils`
```java
public class SSLUtils {
    /**
     * SECURITY WARNING: Creates SSL context that trusts all certificates.
     * This disables certificate validation and should only be used in
     * development/testing environments or with explicit user consent.
     *
     * @param allowInsecure If true, creates trust-all context
     * @return SSLContext configured based on allowInsecure flag
     */
    public static SSLContext createSSLContext(boolean allowInsecure) {
        if (!allowInsecure) {
            // Return default secure context
        }
        // Return trust-all context with warning log
    }
}
```

**Files to modify**:
- `FileParser.java:60-96`
- `DepsDevClient.java:51-84`

**Benefits**:
- DRY principle
- Single place to fix security issue
- Easier to add configuration flag later

**Risk**: Medium - touches network code
**Testing**: Verify deps.dev API calls still work

### 6. Add Configuration Object ✓ Cleaner API
**Create**: `com.contrastsecurity.deptrast.config.DependencyConfig`
```java
public class DependencyConfig {
    private final String inputFormat;
    private final String inputType;
    private final String outputFormat;
    private final String outputType;
    private final String projectName;
    private final boolean verbose;
    private final boolean allowInsecureSSL;
    private final Map<String, String> dependencyManagement;
    private final Map<String, Set<String>> exclusions;

    // Builder pattern
    public static class Builder { ... }
}
```

**Benefits**:
- Reduces parameter lists
- Easier to add new config options
- Better testability

**Risk**: Medium - requires refactoring many method signatures
**Benefit**: Much cleaner code

## Higher Risk (Architectural Changes)

### 7. Split FileParser (Large Refactor)
**Current**: 989 lines, handles 5+ formats
**Proposed**:
```
com.contrastsecurity.deptrast.parser/
├── FileParser (interface)
├── FlatFileParser
├── PomFileParser
├── GradleFileParser
├── PyPiRequirementsParser
└── SbomFileParser
```

**Also create**:
```
com.contrastsecurity.deptrast.http/
└── MavenCentralClient
```

**Benefits**:
- Single Responsibility Principle
- Easier testing
- Easier to add new formats

**Risk**: HIGH - major refactoring
**Effort**: 4-8 hours
**Testing**: Full regression testing needed

### 8. Split DependencyTreeGenerator (Large Refactor)
**Current**: 607 lines, multiple responsibilities
**Proposed**:
```
com.contrastsecurity.deptrast/
├── DependencyTreeGenerator (main/orchestrator)
├── cli/
│   └── CommandLineParser
├── output/
│   ├── OutputGenerator (interface)
│   ├── TreeOutputGenerator
│   ├── MavenTreeOutputGenerator
│   └── SbomOutputGenerator
└── format/
    └── InputFormatDetector
```

**Benefits**:
- Clean separation of concerns
- Easier to maintain
- Better testability

**Risk**: HIGH - major refactoring
**Effort**: 4-8 hours
**Testing**: Full regression testing needed

### 9. Replace Singleton Pattern (Moderate Refactor)
**Current**: `PackageCache.getInstance()` - global state
**Proposed**: Constructor injection
```java
public class DependencyGraphBuilder {
    private final PackageCache cache;

    public DependencyGraphBuilder(PackageCache cache) {
        this.cache = cache;
    }
}
```

**Benefits**:
- Testability
- No global state
- Thread safety

**Risk**: MEDIUM - affects multiple classes
**Effort**: 2-3 hours

## Security Issues

### CRITICAL: SSL Certificate Bypass
**Files**:
- `FileParser.java:60-96`
- `DepsDevClient.java:51-84`

**Current Code**:
```java
TrustManager[] trustAllCerts = new TrustManager[]{
    new X509TrustManager() {
        public void checkClientTrusted(...) {} // NO VALIDATION!
        public void checkServerTrusted(...) {} // NO VALIDATION!
    }
};
```

**Recommended Actions**:
1. **Immediate**: Add prominent warning in README
2. **Short-term**: Add `--allow-insecure-ssl` flag (default: false)
3. **Long-term**: Remove trust-all option entirely

**Documentation needed**:
```markdown
## Security Considerations

### SSL Certificate Validation

**WARNING**: This tool currently disables SSL certificate validation when
connecting to Maven Central and deps.dev APIs. This makes the tool vulnerable
to man-in-the-middle attacks.

**Why**: Some corporate environments use SSL-intercepting proxies with
self-signed certificates.

**Risks**:
- Compromised dependencies could be injected
- Sensitive data could be intercepted

**Recommended**: Only use on trusted networks or with proper SSL/TLS configuration.

**Future**: Version 3.0 will require proper SSL certificates by default.
```

## Recommended Execution Order

### Phase 1: Quick Wins (1-2 hours)
1. Remove deprecated methods
2. Clean up excessive comments
3. Extract constants to enum
4. Document SSL security issue

**After Phase 1**: ~200 lines removed, no functional changes

### Phase 2: Safe Refactors (2-3 hours)
5. Extract SSL configuration utility
6. Add configuration object
7. Remove dead code (if confirmed safe)

**After Phase 2**: Code quality significantly improved

### Phase 3: Architectural (8-12 hours, separate effort)
8. Split FileParser
9. Split DependencyTreeGenerator
10. Replace singleton pattern

**After Phase 3**: Professional-grade architecture

## Testing Strategy

After each phase:
1. Run full test suite: `mvn test`
2. Test manual scenarios:
   - Flat file input
   - POM file input
   - SBOM enhancement
   - All output formats
3. Performance regression check

## Files That Will Change

### Phase 1 (Low Risk):
- `FileParser.java` - Remove method, clean comments
- `DepsDevClient.java` - Remove method, clean comments
- `DependencyTreeGenerator.java` - Clean comments
- `README.md` - Add security warning
- New: `PackageSystem.java` (enum)

### Phase 2 (Medium Risk):
- `FileParser.java` - Use SSLUtils
- `DepsDevClient.java` - Use SSLUtils
- `DependencyTreeGenerator.java` - Use config object
- New: `SSLUtils.java`
- New: `DependencyConfig.java`

### Phase 3 (High Risk):
- Major restructuring - create separate plan if pursuing

## Success Metrics

- Lines of code reduced: ~300-500 (Phase 1+2)
- Cyclomatic complexity reduced
- Test coverage maintained/improved
- No performance regression
- All existing functionality preserved

## Recommendations

**For immediate cleanup**: Execute Phase 1 + Phase 2
**For long-term health**: Consider Phase 3 for v3.0

**Priority**: Phase 1 is low-hanging fruit and should be done ASAP.
