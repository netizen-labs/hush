"""hush — a zero-dependency, git-aware secret scanner.

Public API:

    >>> from hush import Scanner
    >>> scanner = Scanner()
    >>> findings = scanner.scan_text('token = "ghp_" + "x"*36', source="demo")

See :mod:`hush.cli` for the command-line entry point.
"""

from __future__ import annotations

from .baseline import Baseline
from .entropy import is_high_entropy, shannon_entropy
from .rules import DEFAULT_RULES, Rule
from .scanner import Finding, Scanner, sort_findings

__version__ = "0.1.0"

__all__ = [
    "Scanner",
    "Finding",
    "Rule",
    "Baseline",
    "DEFAULT_RULES",
    "shannon_entropy",
    "is_high_entropy",
    "sort_findings",
    "__version__",
]
