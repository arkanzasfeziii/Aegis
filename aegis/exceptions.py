"""Custom exception hierarchy for Aegis."""

from __future__ import annotations


class AegisError(Exception):
    """Base exception for all Aegis errors."""


class ModuleError(AegisError):
    """Raised when a module encounters a runtime error."""


class ConnectionError(AegisError):
    """Raised when connection to target fails."""


class DependencyError(AegisError):
    """Raised when a required dependency is missing."""

    def __init__(self, package: str) -> None:
        super().__init__(f"Missing: {package}. Install with: pip install {package}")
        self.package = package
