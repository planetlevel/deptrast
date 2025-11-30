# Integration Plan: SBOM Visualization

This document outlines how to integrate the SBOM visualization into the deptrast CLI.

## Current Status

**✅ Completed:**
- Interactive HTML visualization (`sbom-viz.html`)
- Python graph command module (`python/deptrast/commands/graph.py`)
- Documentation (`README-viz.md`)
- Test script (`scripts/visualize-sbom.sh`)

**🔲 Next Steps:**
1. Integrate into main CLI (see below)
2. Add tests
3. Update main README

## Integration Approach

### Step 1: Update `__main__.py`

Add the `graph` subcommand to `python/deptrast/__main__.py`:

```python
# In the argument parser section, add:

graph_parser = subparsers.add_parser(
    'graph',
    help='Generate interactive visualization of dependency tree'
)
graph_parser.add_argument(
    'input',
    help='SBOM file to visualize (.sbom or .json)'
)
graph_parser.add_argument(
    '--output',
    '-o',
    help='Output HTML file path (default: temp file)',
    default=None
)
graph_parser.add_argument(
    '--no-browser',
    action='store_true',
    help='Do not open browser automatically'
)

# In the command dispatch section, add:
from deptrast.commands.graph import visualize_sbom

elif args.command == 'graph':
    visualize_sbom(
        args.input,
        output_html=args.output,
        open_browser=not args.no_browser
    )
```

### Step 2: Update parsers.py (Optional Enhancement)

For the full "generate and visualize" workflow:

```python
# Add to parsers.py or create new function in graph.py

def generate_and_visualize(input_file, output_sbom=None, output_html=None):
    """
    Generate SBOM from Maven/Gradle project and immediately visualize it.

    Example:
        deptrast graph --pom pom.xml
    """
    from deptrast.parsers import parse_input
    from deptrast.commands.graph import visualize_sbom
    import tempfile

    # Generate SBOM if needed
    if output_sbom is None:
        fd, output_sbom = tempfile.mkstemp(suffix='.sbom', prefix='deptrast-')
        os.close(fd)

    # Use existing deptrast functionality
    parse_input(input_file, output_sbom, format='json')

    # Visualize
    visualize_sbom(output_sbom, output_html=output_html, open_browser=True)

    return output_html
```

Then add argument to graph parser:
```python
graph_parser.add_argument(
    '--pom',
    help='Generate SBOM from POM file, then visualize'
)
```

### Step 3: Update Entry Points

Update `setup.py` or `pyproject.toml` to expose the graph command:

```python
# In setup.py:
entry_points={
    'console_scripts': [
        'deptrast=deptrast.__main__:main',
        'deptrast-graph=deptrast.commands.graph:main',  # Optional separate command
    ],
}
```

## Usage Examples

After integration:

```bash
# Visualize existing SBOM
deptrast graph petclinic.sbom

# Generate from POM and visualize (future enhancement)
deptrast graph --pom pom.xml

# Save HTML to specific location
deptrast graph petclinic.sbom --output report.html

# Generate without opening browser (for CI/CD)
deptrast graph petclinic.sbom --no-browser
```

## Testing

### Manual Testing

```bash
# Test with petclinic SBOM
./scripts/visualize-sbom.sh src/test/resources/petclinic-deptrast-from-maven.sbom

# Or directly
python3 python/deptrast/commands/graph.py src/test/resources/petclinic-deptrast-from-maven.sbom
```

### Automated Testing

Add to `python/tests/test_graph.py`:

```python
import unittest
import json
import tempfile
from pathlib import Path
from deptrast.commands.graph import visualize_sbom

class TestGraphVisualization(unittest.TestCase):

    def setUp(self):
        # Create minimal SBOM for testing
        self.test_sbom = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "components": [
                {
                    "type": "library",
                    "group": "com.example",
                    "name": "test-lib",
                    "version": "1.0.0",
                    "purl": "pkg:maven/com.example/test-lib@1.0.0"
                }
            ],
            "dependencies": [
                {
                    "ref": "pkg:maven/com.example/test-lib@1.0.0",
                    "dependsOn": []
                }
            ]
        }

        self.sbom_file = tempfile.NamedTemporaryFile(
            mode='w',
            suffix='.json',
            delete=False
        )
        json.dump(self.test_sbom, self.sbom_file)
        self.sbom_file.close()

    def tearDown(self):
        Path(self.sbom_file.name).unlink()

    def test_visualize_creates_html(self):
        """Test that visualization creates valid HTML file"""
        output = visualize_sbom(
            self.sbom_file.name,
            open_browser=False
        )

        self.assertTrue(Path(output).exists())

        with open(output) as f:
            content = f.read()
            self.assertIn('<!DOCTYPE html>', content)
            self.assertIn('SBOM Dependency Tree', content)
            self.assertIn('test-lib', content)

        Path(output).unlink()

    def test_visualize_with_output_path(self):
        """Test visualization with custom output path"""
        output_path = tempfile.mktemp(suffix='.html')

        result = visualize_sbom(
            self.sbom_file.name,
            output_html=output_path,
            open_browser=False
        )

        self.assertEqual(result, output_path)
        self.assertTrue(Path(output_path).exists())

        Path(output_path).unlink()

if __name__ == '__main__':
    unittest.main()
```

## Documentation Updates

### Update Main README.md

Add section:

```markdown
### Visualize Dependency Tree

Generate an interactive visualization of the dependency tree:

\`\`\`bash
# Visualize existing SBOM
deptrast graph petclinic.sbom

# Save to specific file
deptrast graph petclinic.sbom --output report.html
\`\`\`

The visualization opens in your default browser with:
- Expandable/collapsible dependency tree
- Search and filtering
- Dependency statistics
- Circular dependency detection

See [README-viz.md](README-viz.md) for more details.
```

## File Checklist

- ✅ `sbom-viz.html` - Standalone visualization tool
- ✅ `python/deptrast/commands/graph.py` - Python module for graph command
- ✅ `scripts/visualize-sbom.sh` - Helper script for quick testing
- ✅ `README-viz.md` - Visualization documentation
- ✅ `INTEGRATION-PLAN.md` - This file
- 🔲 `python/tests/test_graph.py` - Unit tests
- 🔲 Updated `python/deptrast/__main__.py` - CLI integration
- 🔲 Updated `README.md` - Main documentation
- 🔲 Updated `python/deptrast.egg-info/SOURCES.txt` - Package metadata

## Next Actions

1. Review this integration plan
2. Decide on preferred integration approach:
   - **Option A**: Simple (just visualize existing SBOMs)
   - **Option B**: Full integration (generate + visualize in one command)
3. Update `__main__.py` with chosen approach
4. Add tests
5. Update main README
6. Test end-to-end workflow

## Notes

- All visualization code is self-contained (no external dependencies)
- Works with any CycloneDX SBOM (not just deptrast-generated)
- Browser opens automatically but can be disabled with `--no-browser`
- HTML files are standalone and can be shared/archived
