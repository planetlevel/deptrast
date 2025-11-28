"""Core data models for deptrast."""

from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class Package:
    """Represents a software package with system, name, and version."""

    system: str  # maven, npm, pypi
    name: str
    version: str

    def __post_init__(self):
        """Normalize system to lowercase."""
        self.system = self.system.lower()

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
    """Represents a node in a dependency tree."""

    package: Package
    depth: int = 0
    is_root: bool = False
    children: List['DependencyNode'] = field(default_factory=list)

    def add_child(self, child: 'DependencyNode') -> None:
        """Add a child dependency to this node."""
        self.children.append(child)

    def mark_as_root(self) -> None:
        """Mark this node as a root dependency."""
        self.is_root = True

    def get_tree_representation(self, prefix: str = "", is_last: bool = True) -> str:
        """Generate a tree visualization string."""
        lines = []

        # Root indicator
        root_marker = "🔴 " if self.is_root else ""

        # Current node
        connector = "└── " if is_last else "├── "
        if self.depth == 0:
            lines.append(f"{root_marker}{self.package.full_name}")
        else:
            lines.append(f"{prefix}{connector}{root_marker}{self.package.full_name}")

        # Children
        for i, child in enumerate(self.children):
            is_last_child = (i == len(self.children) - 1)
            if self.depth == 0:
                child_prefix = ""
            else:
                child_prefix = prefix + ("    " if is_last else "│   ")
            lines.append(child.get_tree_representation(child_prefix, is_last_child))

        return "\n".join(lines)

    def collect_all_packages(self) -> List[Package]:
        """Recursively collect all packages in this tree."""
        packages = [self.package]
        for child in self.children:
            packages.extend(child.collect_all_packages())
        return packages
