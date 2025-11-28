"""Main CLI entry point for deptrast."""

import argparse
import json
import logging
import sys
from pathlib import Path
from typing import List, Optional

from . import __version__
from .models import Package, DependencyNode
from .parsers import FileParser
from .graph_builder import DependencyGraphBuilder
from .formatters import OutputFormatter

logger = logging.getLogger(__name__)


def setup_logging(verbose: bool = False, log_level: Optional[str] = None):
    """Configure logging based on verbosity flags."""
    if log_level:
        level = getattr(logging, log_level.upper(), logging.WARNING)
    elif verbose:
        level = logging.INFO
    else:
        level = logging.WARNING

    logging.basicConfig(
        level=level,
        format='%(levelname)s: %(message)s'
    )


def handle_create(args):
    """Handle the 'create' subcommand."""
    input_file = args.input
    output_file = args.output

    # Setup logging
    setup_logging(args.verbose, args.loglevel)

    # Detect input format
    detected_format = FileParser.detect_format(input_file)
    logger.info(f"Detected input format: {detected_format}")

    # Determine input type (smart defaults)
    input_type = args.input_type
    if input_type == 'smart':
        if detected_format in ('pom', 'gradle', 'pypi'):
            input_type = 'roots'
        else:
            input_type = 'all'

    logger.info(f"Input: {input_file} (format={detected_format}, type={input_type})")
    logger.info(f"Output: {output_file} (format={args.output_format})")

    # Parse input file
    packages: List[Package] = []
    dependency_management = {}
    exclusions = {}
    original_sbom_content = None

    try:
        if detected_format == 'flat':
            packages = FileParser.parse_flat_file(input_file)
        elif detected_format == 'sbom':
            packages = FileParser.parse_sbom_file(input_file)
            # Read original SBOM content for enhancement
            if Path(input_file).exists():
                with open(input_file, 'r') as f:
                    original_sbom_content = f.read()
        elif detected_format == 'pom':
            packages, dependency_management, exclusions = FileParser.parse_pom_file(input_file)
            logger.info(
                f"Parsed {len(packages)} packages with {len(dependency_management)} "
                f"managed versions and {len(exclusions)} exclusions from pom.xml"
            )
        elif detected_format == 'pypi':
            packages = FileParser.parse_requirements_file(input_file)
        elif detected_format == 'gradle':
            packages = FileParser.parse_gradle_file(input_file)
        else:
            print(f"Unknown input format: {detected_format}", file=sys.stderr)
            return 1
    except Exception as e:
        logger.error(f"Error parsing input file: {e}")
        print(f"Error parsing input file: {e}", file=sys.stderr)
        return 1

    if not packages:
        logger.error("No valid packages found in the input file")
        print("No valid packages found in the input file. Check format and try again.")
        return 1

    logger.info(f"Loaded {len(packages)} packages from the input file")

    # Check if we should use existing dependencies or rebuild
    use_existing_deps = args.use_existing_deps
    dependency_trees: List[DependencyNode]
    all_tracked_packages: List[Package]

    if use_existing_deps and detected_format == 'sbom' and original_sbom_content:
        logger.info("Using existing dependency graph from SBOM (fast mode)")
        # Parse existing dependency graph
        dependency_trees = parse_dependency_graph_from_sbom(original_sbom_content, packages)
        all_tracked_packages = packages
        logger.info(f"Using existing dependency graph with {len(dependency_trees)} root packages")
    else:
        # Build dependency trees from scratch
        logger.info(f"Analyzing dependencies for {len(packages)} packages...")

        with DependencyGraphBuilder() as graph_builder:
            # Apply dependency management if available
            if dependency_management:
                graph_builder.set_dependency_management(dependency_management)
                logger.info(f"Applied {len(dependency_management)} managed dependency versions")

            # Apply exclusions if available
            if exclusions:
                graph_builder.set_exclusions(exclusions)
                logger.info(f"Applied {len(exclusions)} exclusion rules")

            dependency_trees = graph_builder.build_dependency_trees(packages)
            all_tracked_packages = list(graph_builder.get_all_reconciled_packages())

        logger.info(f"Identified {len(dependency_trees)} root packages")
        logger.info(f"Using {len(all_tracked_packages)} reconciled packages for output")

    # Generate output based on format
    try:
        if args.output_format == 'list':
            output = OutputFormatter.format_as_list(all_tracked_packages)
        elif args.output_format == 'roots':
            # SBOM with only root packages
            root_packages = [node.package for node in dependency_trees]
            output = OutputFormatter.format_as_sbom(root_packages, dependency_trees)
        elif args.output_format == 'tree':
            if args.tree_format == 'maven':
                output = OutputFormatter.format_as_maven_tree(args.project_name, dependency_trees)
            else:
                output = OutputFormatter.format_as_tree(dependency_trees, all_tracked_packages, args.project_name)
        else:  # sbom (default)
            if original_sbom_content:
                output = OutputFormatter.enhance_sbom_with_dependencies(
                    original_sbom_content, all_tracked_packages, dependency_trees
                )
            else:
                output = OutputFormatter.format_as_sbom(all_tracked_packages, dependency_trees)
    except Exception as e:
        logger.error(f"Error generating output: {e}")
        print(f"Error generating output: {e}", file=sys.stderr)
        return 1

    # Write output
    try:
        if output_file == '-':
            print(output, end='')
        else:
            with open(output_file, 'w') as f:
                f.write(output)
            logger.info(f"Output written to: {output_file}")
            print(f"Output written to: {output_file}")
    except Exception as e:
        logger.error(f"Error writing output: {e}")
        print(f"Error writing output: {e}", file=sys.stderr)
        return 1

    logger.info("Dependency tree generation completed successfully")
    return 0


def handle_enrich(args):
    """Handle the 'enrich' subcommand."""
    # Delegate to create with SBOM input/output
    create_args = argparse.Namespace(
        input=args.input,
        output=args.output,
        input_type='smart',
        output_format='sbom',
        tree_format='tree',
        project_name='project',
        verbose=args.verbose if hasattr(args, 'verbose') else False,
        loglevel=args.loglevel if hasattr(args, 'loglevel') else None,
        use_existing_deps=False  # Always rebuild for enrich
    )
    return handle_create(create_args)


def handle_print(args):
    """Handle the 'print' subcommand."""
    # Delegate to create with stdout output
    create_args = argparse.Namespace(
        input=args.input,
        output='-',
        input_type='smart',
        output_format=args.output_format,
        tree_format=args.tree_format,
        project_name=args.project_name,
        verbose=args.verbose,
        loglevel=args.loglevel,
        use_existing_deps=args.use_existing_deps
    )
    return handle_create(create_args)


def parse_dependency_graph_from_sbom(sbom_content: str, packages: List[Package]) -> List[DependencyNode]:
    """Parse existing dependency graph from SBOM."""
    try:
        sbom = json.loads(sbom_content)

        # Build purl -> Package map
        purl_to_package = {}
        for pkg in packages:
            purl = OutputFormatter._build_purl(pkg)
            # Normalize purl (remove qualifiers)
            purl = purl.split('?')[0]
            purl_to_package[purl] = pkg

        # Build bom-ref -> Package map
        bomref_to_package = {}
        components = sbom.get('components', [])
        for component in components:
            bomref = component.get('bom-ref')
            purl = component.get('purl')
            if bomref and purl:
                purl = purl.split('?')[0]
                pkg = purl_to_package.get(purl)
                if pkg:
                    bomref_to_package[bomref] = pkg

        # Parse dependencies array
        dep_graph = {}
        dependencies = sbom.get('dependencies', [])
        for dep in dependencies:
            ref = dep.get('ref')
            if ref:
                depends_on = dep.get('dependsOn', [])
                dep_graph[ref] = depends_on

        # Build DependencyNode tree structure
        # Find root nodes
        all_refs = set(dep_graph.keys())
        non_root_refs = set()
        for deps in dep_graph.values():
            non_root_refs.update(deps)
        root_refs = all_refs - non_root_refs

        # Build trees
        trees = []
        ref_to_node = {}

        for root_ref in root_refs:
            pkg = bomref_to_package.get(root_ref)
            if pkg:
                root_node = build_dependency_node(root_ref, dep_graph, bomref_to_package, ref_to_node, 0)
                if root_node:
                    trees.append(root_node)
            else:
                # Root ref not in components (likely project/metadata)
                # Use its dependencies as roots
                logger.debug(f"Root ref not in components: {root_ref}. Using its dependencies as roots.")
                child_refs = dep_graph.get(root_ref, [])
                for child_ref in child_refs:
                    child_pkg = bomref_to_package.get(child_ref)
                    if child_pkg:
                        child_node = build_dependency_node(child_ref, dep_graph, bomref_to_package, ref_to_node, 0)
                        if child_node:
                            trees.append(child_node)

        return trees

    except Exception as e:
        logger.error(f"Error parsing dependency graph from SBOM: {e}")
        return []


def build_dependency_node(ref, dep_graph, bomref_to_package, ref_to_node, depth):
    """Recursively build DependencyNode from SBOM dependency graph."""
    # Check if already built (handle cycles)
    if ref in ref_to_node:
        return ref_to_node[ref]

    pkg = bomref_to_package.get(ref)
    if not pkg:
        return None

    node = DependencyNode(package=pkg, depth=depth)
    ref_to_node[ref] = node

    # Add children
    child_refs = dep_graph.get(ref, [])
    for child_ref in child_refs:
        child_node = build_dependency_node(child_ref, dep_graph, bomref_to_package, ref_to_node, depth + 1)
        if child_node:
            node.add_child(child_node)

    return node


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        prog='deptrast',
        description='The ultimate dependency tree converter, enhancer, and streamliner'
    )
    parser.add_argument('--version', action='version', version=f'%(prog)s {__version__}')

    subparsers = parser.add_subparsers(dest='command', help='Subcommands')

    # Create command
    create_parser = subparsers.add_parser('create', help='Create SBOM or other formats from source files')
    create_parser.add_argument('input', help='Input file path')
    create_parser.add_argument('output', help='Output file path (use - for stdout)')
    create_parser.add_argument('--input', dest='input_type', default='smart',
                               choices=['roots', 'list', 'smart'],
                               help='Input type (default: auto-detected)')
    create_parser.add_argument('--output', dest='output_format', default='sbom',
                               choices=['sbom', 'roots', 'tree', 'list'],
                               help='Output format (default: sbom)')
    create_parser.add_argument('--format', dest='tree_format', default='tree',
                               choices=['tree', 'maven'],
                               help='Tree visualization format (default: tree)')
    create_parser.add_argument('--project-name', default='project',
                               help='Project name for tree output')
    create_parser.add_argument('--use-existing-deps', action='store_true',
                               help='Use existing dependency graph from SBOM (fast mode)')
    create_parser.add_argument('--rebuild-deps', action='store_false', dest='use_existing_deps',
                               help='Rebuild dependency graph from scratch (default)')
    create_parser.add_argument('-v', '--verbose', action='store_true',
                               help='Verbose logging')
    create_parser.add_argument('--loglevel',
                               choices=['TRACE', 'DEBUG', 'INFO', 'WARN', 'ERROR'],
                               help='Set log level')
    create_parser.set_defaults(func=handle_create, use_existing_deps=False)

    # Enrich command
    enrich_parser = subparsers.add_parser('enrich', help='Add dependency graph to existing SBOM')
    enrich_parser.add_argument('input', help='Input SBOM file')
    enrich_parser.add_argument('output', help='Output SBOM file')
    enrich_parser.add_argument('-v', '--verbose', action='store_true', help='Verbose logging')
    enrich_parser.add_argument('--loglevel', choices=['TRACE', 'DEBUG', 'INFO', 'WARN', 'ERROR'])
    enrich_parser.set_defaults(func=handle_enrich)

    # Print command
    print_parser = subparsers.add_parser('print', help='Display SBOM in different formats')
    print_parser.add_argument('input', help='Input SBOM file')
    print_parser.add_argument('--output', dest='output_format', default='tree',
                              choices=['tree', 'list', 'roots'],
                              help='Output format (default: tree)')
    print_parser.add_argument('--format', dest='tree_format', default='tree',
                              choices=['tree', 'maven'],
                              help='Tree visualization format (default: tree)')
    print_parser.add_argument('--project-name', default='project',
                              help='Project name for tree output')
    print_parser.add_argument('--use-existing-deps', action='store_true', default=True,
                              help='Use existing dependency graph (default, fast)')
    print_parser.add_argument('--rebuild-deps', action='store_false', dest='use_existing_deps',
                              help='Rebuild dependency graph from scratch')
    print_parser.add_argument('-v', '--verbose', action='store_true', help='Verbose logging')
    print_parser.add_argument('--loglevel', choices=['TRACE', 'DEBUG', 'INFO', 'WARN', 'ERROR'])
    print_parser.set_defaults(func=handle_print)

    # Parse arguments
    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return 1

    # Execute command
    try:
        return args.func(args)
    except Exception as e:
        logger.exception(f"Unexpected error: {e}")
        print(f"Error: {e}", file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
