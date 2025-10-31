# Deptrast Test Suite

This directory contains comprehensive integration tests for the Deptrast dependency tree generator.

## Test Files

### DependencyTreeGeneratorTest.java
Main integration test suite covering all basic use cases of deptrast:

1. **Flat file input with SBOM output** - Tests parsing flat file format (libraries.txt)
2. **POM file input with SBOM output** - Tests parsing Maven POM files
3. **Maven tree output format** - Tests Maven dependency:tree format generation
4. **Tree output format** - Tests custom tree format generation
5. **Input type: roots** - Tests processing only root dependencies
6. **Output type: roots only** - Tests outputting only root packages
7. **Auto-detect input format** - Tests automatic format detection
8. **Verbose mode** - Tests verbose logging
9. **CDXgen comparison (POM)** - Compares results with CDXgen tool (requires CDXgen installed)
10. **CDXgen comparison (test data)** - Tests against test-data POM file
11. **Invalid input format handling** - Tests error handling
12. **Invalid output format handling** - Tests error handling
13. **Missing input file handling** - Tests graceful error handling
14. **Stdout output** - Tests output to stdout (dash as output file)
15. **Project name customization** - Tests custom project naming
16. **Dependency tree regeneration** - Tests rebuilding dependency relationships from stripped SBOM

### CDXgenHelper.java
Helper class for comparing deptrast results with CDXgen:

- Checks if CDXgen is available on the system
- Runs CDXgen on input files
- Extracts and compares component lists
- Calculates match percentage
- Identifies missing components

## Running Tests

### Run all tests:
```bash
mvn test
```

### Run specific test:
```bash
mvn test -Dtest=DependencyTreeGeneratorTest
```

### Run specific test method:
```bash
mvn test -Dtest=DependencyTreeGeneratorTest#testFlatFileInputWithSbomOutput
```

## CDXgen Comparison Tests

The test suite includes tests that compare deptrast results with CDXgen, a popular SBOM generation tool.

### Gold Standard
The test suite uses a pre-generated CDXgen SBOM as the gold standard:
- File: `test-data/spring-petclinic-cdxgen-gold.json`
- Generated from: Spring PetClinic project (../spring-petclinic)
- Generated with: `cdxgen --required-only` (excludes test dependencies)
- Total components: 149 (Maven, npm, github, nix packages)
- Maven components: 139
- Dependency relationships: 115

### Current Status
- **Deptrast finds: ~103 Maven components**
- **Match rate: 74%** (up from 66% when test deps were included)
- **Baseline threshold: 74%** (test fails if below this)
- **Target: 90%+**

### Why Not 100%?
The gap is expected due to different approaches:
- **CDXgen**: Analyzes actual JAR files, includes all transitive dependencies
- **Deptrast**: Analyzes POM files, resolves via Maven Central API

### Regenerating Gold Standard
If you want to update the gold standard:
```bash
# Install CDXgen
npm install -g @cyclonedx/cdxgen

# Generate new gold standard (excluding test dependencies)
cdxgen --required-only -o test-data/spring-petclinic-cdxgen-gold.json ../spring-petclinic
```

**Important**: Use `--required-only` flag to exclude test-scoped dependencies for a fair comparison.

### What the tests do:
1. Run both deptrast and CDXgen on the same input file
2. Parse the generated SBOMs
3. Extract component identifiers (PURLs or name:version)
4. Calculate the percentage of CDXgen components found by deptrast
5. Report any missing components for debugging

## Test Data

The tests use the following test data files:
- `test-data/libraries.txt` - Flat file with Spring PetClinic dependencies
- `test-data/petclinic-pom.xml` - Spring PetClinic POM file
- `/Users/jeffwilliams/git/spring-petclinic/pom.xml` - Real Spring PetClinic project (if available)

## Test Output

Test outputs are written to:
- `target/test-output/*.json` - SBOM outputs
- `target/test-output/*.txt` - Tree and Maven format outputs

## Architecture

### Test Organization
- Tests are ordered using `@Order` annotation to run in logical sequence
- Each test is independent and can be run separately
- Tests use JUnit 5 (Jupiter) framework

### Output Capturing
- Tests capture stdout/stderr to verify console output
- Outputs are restored after each test

### Assumptions
- Tests use `Assumptions.assumeTrue()` for conditional execution
- CDXgen tests are skipped if CDXgen is not installed
- Some tests are skipped if required input files are not available

## Extending Tests

To add new tests:

1. Add a new `@Test` method to `DependencyTreeGeneratorTest`
2. Use `@Order` annotation to specify execution order
3. Use `@DisplayName` for descriptive test names
4. Follow the existing pattern of invoking `DependencyTreeGenerator.main()`
5. Verify outputs using assertions

Example:
```java
@Test
@Order(16)
@DisplayName("Test new feature")
void testNewFeature() throws IOException {
    String inputFile = TEST_DATA_DIR + "/input.txt";
    String outputFile = TEMP_OUTPUT_DIR + "/output.json";

    DependencyTreeGenerator.main(new String[]{
        inputFile,
        outputFile,
        "--your-option"
    });

    assertTrue(Files.exists(Paths.get(outputFile)));
    // Add more assertions...
}
```

## Debugging Failed Tests

If tests fail:

1. Check test reports in `target/surefire-reports/`
2. Examine test output files in `target/test-output/`
3. Run tests with verbose output: `mvn test -X`
4. Run specific failing test to isolate issue
5. Check that all test data files exist

## Future Improvements

Potential areas for enhancement:

- Add unit tests for individual components
- Add tests for Gradle and PyPI input formats
- Add performance benchmarking tests
- Add tests for edge cases and error conditions
- Add tests for dependency exclusions and version management
- Improve CDXgen comparison to handle different naming conventions
