"""Core data models for deptrast."""

from dataclasses import dataclass, field
from typing import List, Optional, Dict


@dataclass
class Package:
    """Represents a software package with system, name, and version."""

    system: str  # maven, npm, pypi
    name: str
    version: str
    scope: str = "compile"  # Maven scope: compile, runtime, test, provided, system, optional, excluded
    original_maven_scope: Optional[str] = None  # Original Maven scope before any transformations (immutable)
    scope_reason: Optional[str] = None  # Reason for scope assignment (e.g., "conflict-resolution", "not-observed-at-runtime")
    winning_version: Optional[str] = None  # If this is a losing version, what version won?
    scope_strategy: Optional[str] = None  # Conflict resolution strategy used: "maven" or "highest"
    defeated_versions: List[str] = field(default_factory=list)  # If this is a winner, list of versions it defeated
    is_override_winner: bool = False  # True if this won via dependency management override
    version_metadata: Optional[Dict[str, str]] = None  # Metadata about version (e.g., HeroDevs info)

    def __post_init__(self):
        """Normalize system to lowercase."""
        self.system = self.system.lower()
        # Default to compile if scope is None or empty
        if not self.scope:
            self.scope = "compile"
        # Capture original scope if not already set
        if self.original_maven_scope is None:
            self.original_maven_scope = self.scope

    @property
    def full_name(self) -> str:
        """Return the full package name in system:name:version format."""
        return f"{self.system}:{self.name}:{self.version}"

    def __str__(self) -> str:
        return self.full_name

    def __hash__(self) -> int:
        return hash(self.full_name)

    def __eq__(self, other) -> bool:
        if not isinstance(other, Package):
            return False
        return self.full_name == other.full_name


@dataclass
class DependencyNode:
    """Represents a node in a dependency graph (not a tree - nodes can be shared)."""

    package: Package
    is_root: bool = False
    children: List['DependencyNode'] = field(default_factory=list, compare=False, hash=False)

    def __eq__(self, other) -> bool:
        """Equality based on object identity for graph node sharing."""
        return self is other

    def __hash__(self) -> int:
        """Hash based on object identity for graph node sharing."""
        return id(self)

    def add_child(self, child: 'DependencyNode') -> None:
        """Add a child dependency to this node."""
        # DEBUG: Track commons-io additions to commons-compress
        if "commons-compress@1.27.1" in self.package.full_name and "commons-io@2.19.0" in child.package.full_name:
            import traceback
            import logging
            logger = logging.getLogger(__name__)
            logger.warning(f"DEBUG: add_child() - Adding commons-io@2.19.0 to commons-compress@1.27.1")
            logger.warning(f"DEBUG: Stack trace:\n{''.join(traceback.format_stack())}")
        if child not in self.children:  # Avoid duplicates
            self.children.append(child)

    def mark_as_root(self) -> None:
        """Mark this node as a root dependency."""
        self.is_root = True

    def get_tree_representation(self, prefix: str = "", is_last: bool = True, depth: int = 0, visited: set = None) -> str:
        """Generate a tree visualization string (depth computed on-the-fly)."""
        if visited is None:
            visited = set()

        lines = []

        # Check for cycles
        node_id = self.package.full_name
        if node_id in visited:
            # Root indicator
            root_marker = "🔴 " if self.is_root else ""

            # Show cycle marker
            connector = "└── " if is_last else "├── "
            if depth == 0:
                lines.append(f"{root_marker}{node_id} (cycle)")
            else:
                lines.append(f"{prefix}{connector}{root_marker}{node_id} (cycle)")
            return "\n".join(lines)

        visited.add(node_id)

        # Root indicator
        root_marker = "🔴 " if self.is_root else ""

        # Current node
        connector = "└── " if is_last else "├── "
        if depth == 0:
            lines.append(f"{root_marker}{self.package.full_name}")
        else:
            lines.append(f"{prefix}{connector}{root_marker}{self.package.full_name}")

        # Children
        for i, child in enumerate(self.children):
            is_last_child = (i == len(self.children) - 1)
            if depth == 0:
                child_prefix = ""
            else:
                child_prefix = prefix + ("    " if is_last else "│   ")
            lines.append(child.get_tree_representation(child_prefix, is_last_child, depth + 1, visited))

        return "\n".join(lines)

    def collect_all_packages(self) -> List[Package]:
        """Recursively collect all packages in this tree."""
        packages = [self.package]
        for child in self.children:
            packages.extend(child.collect_all_packages())
        return packages
