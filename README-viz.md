# SBOM Dependency Tree Visualization

Interactive web-based visualization for CycloneDX SBOM files showing dependency trees with expand/collapse functionality.

## Quick Start

1. Open `sbom-viz.html` in a web browser
2. Click "Load SBOM" and select a CycloneDX SBOM file (or drag & drop)
3. Interact with the tree:
   - Click arrows to expand/collapse nodes
   - Use "Expand All" / "Collapse All" for bulk operations
   - Search for specific dependencies in the search box

## Features

- **Interactive Tree View**: Expandable/collapsible dependency tree
- **Color-Coded Display**: Group (teal), artifact name (yellow), version (gray)
- **Statistics Dashboard**: Shows total components, direct dependencies, max depth, and SBOM format
- **Search**: Real-time search with highlighting
- **Circular Dependency Detection**: Marks circular dependencies to prevent infinite loops
- **Dark Theme**: Easy on the eyes for long analysis sessions

## Testing

Test with the included Petclinic SBOM:

```bash
# Just open the HTML file in your browser
open sbom-viz.html

# Then load: src/test/resources/petclinic-deptrast-from-maven.sbom
```

Or from the command line:
```bash
# macOS
open sbom-viz.html

# Linux
xdg-open sbom-viz.html

# Windows
start sbom-viz.html
```

## Integration with deptrast

### Option 1: Stand-alone Command (Recommended)

Add a new subcommand to deptrast CLI:

```bash
# Generate and visualize in one command
deptrast graph pom.xml

# Or visualize existing SBOM
deptrast graph --input petclinic.sbom
```

Implementation approach:
1. Add `graph` subcommand to `python/deptrast/commands/graph.py`
2. Generate SBOM (if needed) using existing code
3. Write HTML file to temp location with embedded SBOM data
4. Open browser automatically using Python's `webbrowser` module

### Option 2: Separate Utility

Keep as separate tool that works with any CycloneDX SBOM:

```bash
# Use the HTML file directly
open sbom-viz.html
```

### Option 3: Embedded Server

Create a Python HTTP server that serves the visualization:

```bash
# Start visualization server
deptrast serve --sbom petclinic.sbom --port 8080
```

## File Structure

```
deptrast/
├── sbom-viz.html              # Main visualization (this file)
├── README-viz.md              # This documentation
└── src/test/resources/
    └── petclinic-deptrast-from-maven.sbom  # Test data
```

## Browser Compatibility

- Chrome/Edge: ✅ Full support
- Firefox: ✅ Full support
- Safari: ✅ Full support
- Requires JavaScript enabled

## Technical Details

- Pure HTML/CSS/JS (no external dependencies)
- Parses CycloneDX 1.6 format (compatible with earlier versions)
- Handles circular dependencies gracefully
- Maintains expand/collapse state during interactions
- Efficient rendering for large SBOMs (tested with 800+ components)

## Future Enhancements

- Export tree as PNG/SVG
- Filter by scope (runtime, test, provided)
- Show vulnerability information (if present in SBOM)
- Diff view for comparing two SBOMs
- License information display
- Dependency path finder (show path from root to specific component)
