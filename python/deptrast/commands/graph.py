#!/usr/bin/env python3
"""
Graph command for deptrast - visualize SBOM dependency trees.

Usage:
    deptrast graph <input-file>          # Visualize existing SBOM
    deptrast graph --pom pom.xml         # Generate from POM and visualize
"""

import json
import tempfile
import webbrowser
import os
from pathlib import Path


# HTML template with embedded JavaScript - will be populated with SBOM data
HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SBOM Dependency Visualization - {filename}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            background: #1e1e1e;
            color: #d4d4d4;
            padding: 20px;
        }}
        .header {{
            margin-bottom: 30px;
        }}
        h1 {{
            font-size: 24px;
            font-weight: 600;
            margin-bottom: 10px;
            color: #ffffff;
        }}
        .controls {{
            display: flex;
            gap: 15px;
            margin-bottom: 20px;
        }}
        button {{
            background: #0e639c;
            color: white;
            border: none;
            padding: 8px 16px;
            border-radius: 4px;
            cursor: pointer;
            font-size: 14px;
        }}
        button:hover {{
            background: #1177bb;
        }}
        .stats {{
            background: #252526;
            padding: 15px;
            border-radius: 6px;
            margin-bottom: 20px;
            border: 1px solid #3e3e42;
        }}
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
        }}
        .stat-item {{
            display: flex;
            flex-direction: column;
        }}
        .stat-label {{
            font-size: 12px;
            color: #858585;
            margin-bottom: 4px;
        }}
        .stat-value {{
            font-size: 20px;
            font-weight: 600;
            color: #4ec9b0;
        }}
        .tree-container {{
            background: #252526;
            border-radius: 6px;
            padding: 20px;
            border: 1px solid #3e3e42;
            overflow: auto;
            max-height: calc(100vh - 300px);
        }}
        .scroll-spacer {{
            height: 50vh;
            pointer-events: none;
        }}
        .tree-node {{
            margin-left: 20px;
            position: relative;
        }}
        .tree-node.root {{
            margin-left: 0;
        }}
        .node-content {{
            display: flex;
            align-items: center;
            padding: 6px 10px;
            cursor: pointer;
            border-radius: 4px;
            transition: background 0.15s;
            user-select: none;
        }}
        .node-content:hover {{
            background: #2a2d2e;
        }}
        .expand-icon {{
            width: 16px;
            height: 16px;
            margin-right: 8px;
            display: inline-flex;
            align-items: center;
            justify-content: center;
            font-size: 12px;
            color: #858585;
        }}
        .expand-icon.expandable {{
            cursor: pointer;
        }}
        .expand-icon.expanded::before {{
            content: '▼';
        }}
        .expand-icon.collapsed::before {{
            content: '▶';
        }}
        .expand-icon.leaf::before {{
            content: '•';
            font-size: 8px;
        }}
        .expand-icon.root-leaf::before {{
            content: '||';
            font-size: 12px;
        }}
        .node-name {{
            font-family: 'Consolas', 'Monaco', 'Courier New', monospace;
            font-size: 13px;
        }}
        .node-group {{
            color: #4ec9b0;
        }}
        .node-artifact {{
            color: #dcdcaa;
        }}
        .node-version {{
            color: #858585;
            margin-left: 4px;
        }}
        .node-children {{
            margin-top: 4px;
        }}
        .node-children.collapsed {{
            display: none;
        }}
        .search-box {{
            width: 100%;
            padding: 10px;
            background: #3c3c3c;
            border: 1px solid #3e3e42;
            border-radius: 4px;
            color: #d4d4d4;
            font-size: 14px;
            margin-bottom: 15px;
        }}
        .search-box:focus {{
            outline: none;
            border-color: #0e639c;
        }}
        .highlight {{
            background: #515c6a;
        }}
        .url-loader {{
            background: #252526;
            padding: 15px;
            border-radius: 6px;
            margin-bottom: 20px;
            border: 1px solid #3e3e42;
            display: flex;
            gap: 10px;
            align-items: center;
        }}
        .url-input {{
            flex: 1;
            padding: 10px;
            background: #3c3c3c;
            border: 1px solid #3e3e42;
            border-radius: 4px;
            color: #d4d4d4;
            font-size: 14px;
        }}
        .url-input:focus {{
            outline: none;
            border-color: #0e639c;
        }}
        .load-button {{
            background: #0e639c;
            color: white;
            border: none;
            padding: 10px 20px;
            border-radius: 4px;
            cursor: pointer;
            font-size: 14px;
            white-space: nowrap;
        }}
        .load-button:hover {{
            background: #1177bb;
        }}
        .load-button:disabled {{
            background: #555;
            cursor: not-allowed;
        }}
        .error-message {{
            color: #f48771;
            font-size: 12px;
            margin-top: 5px;
        }}
    </style>
</head>
<body>
    <div class="header">
        <h1>SBOM Dependency Tree - {filename}</h1>
        <div class="controls">
            <button onclick="expandAll()">Expand All</button>
            <button onclick="collapseAll()">Collapse All</button>
        </div>
    </div>

    <div class="stats">
        <div class="stats-grid">
            <div class="stat-item">
                <div class="stat-label">Total Components</div>
                <div class="stat-value" id="totalComponents">0</div>
            </div>
            <div class="stat-item">
                <div class="stat-label">Direct Dependencies</div>
                <div class="stat-value" id="directDeps">0</div>
            </div>
            <div class="stat-item">
                <div class="stat-label">Max Depth</div>
                <div class="stat-value" id="maxDepth">0</div>
            </div>
            <div class="stat-item">
                <div class="stat-label">SBOM Format</div>
                <div class="stat-value" id="bomFormat">-</div>
            </div>
        </div>
    </div>

    <div class="url-loader">
        <input type="text" class="url-input" id="urlInput" placeholder="Load SBOM from URL (e.g., https://example.com/sbom.json)">
        <button class="load-button" onclick="loadFromUrl()">Load URL</button>
    </div>
    <div id="errorContainer"></div>

    <input type="text" class="search-box" id="searchBox" placeholder="Search dependencies...">

    <div class="tree-container" id="treeContainer"></div>

    <script>
        const sbomData = {sbom_json};
        let componentMap = new Map();
        let expandedState = new Map();
        let rootNodeSet = new Set();

        function init() {{
            // Build component map
            if (sbomData.components) {{
                sbomData.components.forEach(comp => {{
                    componentMap.set(comp.purl, comp);
                }});
            }}

            // Build dependency tree
            const dependencyMap = new Map();
            if (sbomData.dependencies) {{
                sbomData.dependencies.forEach(dep => {{
                    dependencyMap.set(dep.ref, dep.dependsOn || []);
                }});
            }}

            const rootNodes = findRootNodes(dependencyMap);
            // Track root nodes in a Set for quick lookup
            rootNodes.forEach(root => rootNodeSet.add(root));
            updateStats(sbomData, rootNodes.length);
            renderTree(rootNodes, dependencyMap);
        }}

        function findRootNodes(dependencyMap) {{
            const allDeps = new Set();
            dependencyMap.forEach((deps, ref) => {{
                deps.forEach(dep => allDeps.add(dep));
            }});

            const roots = [];
            dependencyMap.forEach((deps, ref) => {{
                if (!allDeps.has(ref)) {{
                    roots.push(ref);
                }}
            }});

            return roots.length > 0 ? roots : Array.from(dependencyMap.keys());
        }}

        function updateStats(sbom, directDeps) {{
            document.getElementById('totalComponents').textContent = sbom.components ? sbom.components.length : 0;
            document.getElementById('directDeps').textContent = directDeps;
            document.getElementById('bomFormat').textContent = `${{sbom.bomFormat}} ${{sbom.specVersion}}`;

            let maxDepth = 0;
            const dependencyMap = new Map();
            if (sbom.dependencies) {{
                sbom.dependencies.forEach(dep => {{
                    dependencyMap.set(dep.ref, dep.dependsOn || []);
                }});
            }}
            const roots = findRootNodes(dependencyMap);
            roots.forEach(root => {{
                const depth = calculateDepth(root, dependencyMap, new Set());
                maxDepth = Math.max(maxDepth, depth);
            }});
            document.getElementById('maxDepth').textContent = maxDepth;
        }}

        function calculateDepth(ref, dependencyMap, visited) {{
            if (visited.has(ref)) return 0;
            visited.add(ref);

            const deps = dependencyMap.get(ref) || [];
            if (deps.length === 0) return 1;

            let maxChildDepth = 0;
            deps.forEach(dep => {{
                const childDepth = calculateDepth(dep, dependencyMap, new Set(visited));
                maxChildDepth = Math.max(maxChildDepth, childDepth);
            }});

            return maxChildDepth + 1;
        }}

        function renderTree(roots, dependencyMap) {{
            const container = document.getElementById('treeContainer');
            container.innerHTML = '';

            // Add top spacer for scrolling
            const topSpacer = document.createElement('div');
            topSpacer.className = 'scroll-spacer';
            container.appendChild(topSpacer);

            roots.forEach(root => {{
                const nodeElement = renderNode(root, dependencyMap, new Set(), true);
                container.appendChild(nodeElement);
            }});

            // Add bottom spacer for scrolling
            const bottomSpacer = document.createElement('div');
            bottomSpacer.className = 'scroll-spacer';
            container.appendChild(bottomSpacer);
        }}

        function renderNode(purl, dependencyMap, visited, isRoot = false) {{
            const nodeDiv = document.createElement('div');
            nodeDiv.className = isRoot ? 'tree-node root' : 'tree-node';

            if (visited.has(purl)) {{
                const content = createNodeContent(purl, false, true);
                nodeDiv.appendChild(content);
                return nodeDiv;
            }}

            visited.add(purl);

            const deps = dependencyMap.get(purl) || [];
            const hasChildren = deps.length > 0;
            const isExpanded = expandedState.get(purl) !== false;

            const content = createNodeContent(purl, hasChildren, false, isExpanded);
            nodeDiv.appendChild(content);

            if (hasChildren) {{
                const childrenDiv = document.createElement('div');
                childrenDiv.className = isExpanded ? 'node-children' : 'node-children collapsed';
                childrenDiv.id = `children-${{purl}}`;

                deps.forEach(dep => {{
                    const childNode = renderNode(dep, dependencyMap, new Set(visited));
                    childrenDiv.appendChild(childNode);
                }});

                nodeDiv.appendChild(childrenDiv);
            }}

            return nodeDiv;
        }}

        function createNodeContent(purl, hasChildren, isCircular, isExpanded = true) {{
            const content = document.createElement('div');
            content.className = 'node-content';

            const icon = document.createElement('span');
            // Check if this is a root node with no children (root-leaf)
            const isRootLeaf = rootNodeSet.has(purl) && !hasChildren;

            if (isRootLeaf) {{
                icon.className = 'expand-icon root-leaf';
            }} else {{
                icon.className = hasChildren ?
                    (isExpanded ? 'expand-icon expandable expanded' : 'expand-icon expandable collapsed') :
                    'expand-icon leaf';
            }}

            if (hasChildren) {{
                icon.onclick = () => toggleNode(purl);
            }}

            const nameSpan = document.createElement('span');
            nameSpan.className = 'node-name';

            const component = componentMap.get(purl);
            if (component) {{
                const groupSpan = document.createElement('span');
                groupSpan.className = 'node-group';
                groupSpan.textContent = component.group + '/';

                const artifactSpan = document.createElement('span');
                artifactSpan.className = 'node-artifact';
                artifactSpan.textContent = component.name;

                const versionSpan = document.createElement('span');
                versionSpan.className = 'node-version';
                versionSpan.textContent = '@' + component.version;

                nameSpan.appendChild(groupSpan);
                nameSpan.appendChild(artifactSpan);
                nameSpan.appendChild(versionSpan);

                if (isCircular) {{
                    const circularSpan = document.createElement('span');
                    circularSpan.className = 'node-version';
                    circularSpan.textContent = ' (circular)';
                    nameSpan.appendChild(circularSpan);
                }}
            }} else {{
                nameSpan.textContent = purl;
            }}

            content.appendChild(icon);
            content.appendChild(nameSpan);

            return content;
        }}

        function toggleNode(purl) {{
            const childrenDiv = document.getElementById(`children-${{purl}}`);
            if (childrenDiv) {{
                const isCollapsed = childrenDiv.classList.contains('collapsed');
                childrenDiv.classList.toggle('collapsed');
                expandedState.set(purl, isCollapsed);

                const icons = document.querySelectorAll('.expand-icon');
                icons.forEach(icon => {{
                    const content = icon.parentElement;
                    const nameSpan = content.querySelector('.node-name');
                    if (nameSpan && nameSpan.textContent.includes(purl)) {{
                        icon.className = isCollapsed ?
                            'expand-icon expandable expanded' :
                            'expand-icon expandable collapsed';
                    }}
                }});
            }}
        }}

        function expandAll() {{
            document.querySelectorAll('.node-children').forEach(el => {{
                el.classList.remove('collapsed');
                const purl = el.id.replace('children-', '');
                expandedState.set(purl, true);
            }});
            document.querySelectorAll('.expand-icon.expandable').forEach(el => {{
                el.className = 'expand-icon expandable expanded';
            }});
        }}

        function collapseAll() {{
            document.querySelectorAll('.node-children').forEach(el => {{
                el.classList.add('collapsed');
                const purl = el.id.replace('children-', '');
                expandedState.set(purl, false);
            }});
            document.querySelectorAll('.expand-icon.expandable').forEach(el => {{
                el.className = 'expand-icon expandable collapsed';
            }});
        }}

        document.getElementById('searchBox').addEventListener('input', function(e) {{
            const searchTerm = e.target.value.toLowerCase();
            document.querySelectorAll('.node-content').forEach(node => {{
                const text = node.textContent.toLowerCase();
                if (searchTerm && text.includes(searchTerm)) {{
                    node.classList.add('highlight');
                }} else {{
                    node.classList.remove('highlight');
                }}
            }});
        }});

        async function loadFromUrl() {{
            const urlInput = document.getElementById('urlInput');
            const loadButton = document.querySelector('.load-button');
            const errorContainer = document.getElementById('errorContainer');
            const url = urlInput.value.trim();

            // Clear previous errors
            errorContainer.innerHTML = '';

            if (!url) {{
                errorContainer.innerHTML = '<div class="error-message">Please enter a URL</div>';
                return;
            }}

            // Validate URL format
            try {{
                new URL(url);
            }} catch (e) {{
                errorContainer.innerHTML = '<div class="error-message">Invalid URL format</div>';
                return;
            }}

            // Disable button and show loading
            loadButton.disabled = true;
            loadButton.textContent = 'Loading...';

            try {{
                const response = await fetch(url);

                if (!response.ok) {{
                    throw new Error(`HTTP error! status: ${{response.status}}`);
                }}

                const data = await response.json();

                // Validate it's a CycloneDX SBOM
                if (!data.bomFormat || !data.components) {{
                    throw new Error('Invalid SBOM format - missing required fields');
                }}

                // Replace the global sbomData and reinitialize
                Object.assign(sbomData, data);
                componentMap.clear();
                expandedState.clear();
                rootNodeSet.clear();

                // Update page title
                document.querySelector('h1').textContent = `SBOM Dependency Tree - ${{url.split('/').pop()}}`;

                // Reinitialize the visualization
                init();

                // Clear the URL input on success
                urlInput.value = '';

            }} catch (error) {{
                errorContainer.innerHTML = `<div class="error-message">Failed to load SBOM: ${{error.message}}</div>`;
            }} finally {{
                loadButton.disabled = false;
                loadButton.textContent = 'Load URL';
            }}
        }}

        // Allow Enter key to trigger load
        document.addEventListener('DOMContentLoaded', function() {{
            const urlInput = document.getElementById('urlInput');
            urlInput.addEventListener('keypress', function(e) {{
                if (e.key === 'Enter') {{
                    loadFromUrl();
                }}
            }});
        }});

        init();
    </script>
</body>
</html>
"""


def visualize_sbom(sbom_path, output_html=None, open_browser=True):
    """
    Generate an interactive HTML visualization of an SBOM file.

    Args:
        sbom_path: Path to the CycloneDX SBOM JSON file
        output_html: Optional output path for HTML file (default: temp file)
        open_browser: Whether to automatically open the visualization in a browser

    Returns:
        Path to the generated HTML file
    """
    sbom_path = Path(sbom_path)

    if not sbom_path.exists():
        raise FileNotFoundError(f"SBOM file not found: {sbom_path}")

    # Read SBOM
    with open(sbom_path, 'r') as f:
        sbom_data = json.load(f)

    # Generate HTML with embedded SBOM data
    html_content = HTML_TEMPLATE.format(
        filename=sbom_path.name,
        sbom_json=json.dumps(sbom_data)
    )

    # Write to output file
    if output_html is None:
        # Create a temp file that won't be deleted immediately
        fd, output_html = tempfile.mkstemp(suffix='.html', prefix='sbom-viz-')
        os.close(fd)  # Close the file descriptor, we'll write with regular open

    output_path = Path(output_html)
    with open(output_path, 'w') as f:
        f.write(html_content)

    print(f"Generated visualization: {output_path}")

    # Open in browser
    if open_browser:
        webbrowser.open(f'file://{output_path.absolute()}')
        print(f"Opened in browser")

    return str(output_path)


def main():
    """Main entry point for the graph command."""
    import sys

    if len(sys.argv) < 2:
        print("Usage: deptrast-graph <sbom-file>")
        print("Example: deptrast-graph petclinic.sbom")
        sys.exit(1)

    sbom_file = sys.argv[1]
    visualize_sbom(sbom_file)


if __name__ == '__main__':
    main()
