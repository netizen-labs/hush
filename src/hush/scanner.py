"""Core scanning engine: turn text and files into :class:`Finding` objects."""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Iterator, Sequence

from .entropy import is_high_entropy, shannon_entropy
from .rules import DEFAULT_RULES, SEVERITY_ORDER, Rule

# Directories that never contain source worth scanning and would only slow us
# down (or produce noise). Matched by exact name at any depth.
DEFAULT_SKIP_DIRS = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        "node_modules",
        "venv",
        ".venv",
        "env",
        "__pycache__",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        "dist",
        "build",
        ".idea",
        ".vscode",
        "vendor",
        "target",
    }
)

# The rule id used when a finding comes purely from the entropy detector.
ENTROPY_RULE_ID = "high-entropy-string"

# Read files in bounded chunks; anything larger is almost certainly a data blob,
# not source, and scanning it wastes time.
MAX_FILE_BYTES = 5 * 1024 * 1024


@dataclass(frozen=True)
class Finding:
    """A single potential secret located in some source.

    ``source`` is a file path or a synthetic label (e.g. a git ref). ``secret``
    holds the raw matched value; use :meth:`redacted` for anything user-facing.
    """

    rule_id: str
    description: str
    severity: str
    source: str
    line: int
    secret: str
    entropy: float

    @property
    def fingerprint(self) -> str:
        """Stable id for baselining: survives line moves, not value changes.

        Deliberately excludes the line number so that inserting code above a
        known/accepted secret does not invalidate its baseline entry.
        """
        digest = hashlib.sha256(
            f"{self.rule_id}\0{self.source}\0{self.secret}".encode("utf-8")
        ).hexdigest()
        return digest[:16]

    def redacted(self) -> str:
        """Return the secret with its middle masked, keeping a few edge chars."""
        secret = self.secret
        if len(secret) <= 8:
            return secret[0] + "*" * (len(secret) - 1) if secret else ""
        keep = 4
        return f"{secret[:keep]}{'*' * (len(secret) - 2 * keep)}{secret[-keep:]}"

    def to_dict(self, *, reveal: bool = False) -> dict:
        """Serialise for JSON output. Redacts the secret unless ``reveal``."""
        return {
            "rule_id": self.rule_id,
            "description": self.description,
            "severity": self.severity,
            "source": self.source,
            "line": self.line,
            "secret": self.secret if reveal else self.redacted(),
            "entropy": round(self.entropy, 3),
            "fingerprint": self.fingerprint,
        }


class Scanner:
    """Applies rules and entropy analysis to lines of text.

    Args:
        rules: Detection rules to apply. Defaults to :data:`DEFAULT_RULES`.
        use_entropy: Also flag high-entropy tokens that no rule matched.
        min_severity: Drop findings below this severity (``low`` keeps all).
        skip_dirs: Directory names to prune during directory walks.
    """

    def __init__(
        self,
        rules: Sequence[Rule] | None = None,
        *,
        use_entropy: bool = True,
        min_severity: str = "low",
        skip_dirs: Iterable[str] = DEFAULT_SKIP_DIRS,
    ) -> None:
        self.rules = tuple(rules if rules is not None else DEFAULT_RULES)
        self.use_entropy = use_entropy
        if min_severity not in SEVERITY_ORDER:
            raise ValueError(f"unknown severity: {min_severity!r}")
        self.min_severity = min_severity
        self.skip_dirs = frozenset(skip_dirs)

    # -- text ---------------------------------------------------------------

    def scan_line(self, line: str, *, source: str, line_no: int) -> Iterator[Finding]:
        """Yield findings for a single line of text."""
        threshold = SEVERITY_ORDER[self.min_severity]
        lower = line.lower()
        seen_spans: list[tuple[int, int]] = []

        for rule in self.rules:
            if SEVERITY_ORDER[rule.severity] < threshold:
                continue
            if rule.keywords and not any(kw in lower for kw in rule.keywords):
                continue
            for match in rule.regex.finditer(line):
                secret = rule.secret_from(match)
                # The generic assignment rule is only trustworthy when the value
                # is actually random; a plain word like "password123" is noise.
                if rule.id == "generic-assignment" and not is_high_entropy(
                    secret, min_length=12, base64_threshold=3.0, hex_threshold=2.0
                ):
                    continue
                seen_spans.append(match.span())
                yield Finding(
                    rule_id=rule.id,
                    description=rule.description,
                    severity=rule.severity,
                    source=source,
                    line=line_no,
                    secret=secret,
                    entropy=shannon_entropy(secret),
                )

        if self.use_entropy and threshold <= SEVERITY_ORDER["medium"]:
            yield from self._entropy_findings(line, source, line_no, seen_spans)

    def _entropy_findings(
        self,
        line: str,
        source: str,
        line_no: int,
        seen_spans: list[tuple[int, int]],
    ) -> Iterator[Finding]:
        """Flag standalone high-entropy tokens not already covered by a rule."""
        offset = 0
        for token in line.split():
            start = line.find(token, offset)
            offset = start + len(token)
            cleaned = token.strip("\"'`,;:()[]{}<>")
            if not is_high_entropy(cleaned):
                continue
            # Skip tokens already reported by a regex rule on this line.
            if any(s <= start < e for s, e in seen_spans):
                continue
            yield Finding(
                rule_id=ENTROPY_RULE_ID,
                description="High-entropy string",
                severity="medium",
                source=source,
                line=line_no,
                secret=cleaned,
                entropy=shannon_entropy(cleaned),
            )

    def scan_text(self, text: str, *, source: str) -> list[Finding]:
        """Scan a whole blob of text, returning findings in document order."""
        findings: list[Finding] = []
        for i, line in enumerate(text.splitlines(), start=1):
            findings.extend(self.scan_line(line, source=source, line_no=i))
        return findings

    # -- files --------------------------------------------------------------

    def scan_file(self, path: str | os.PathLike[str]) -> list[Finding]:
        """Scan one file. Silently skips binary/oversized/unreadable files."""
        p = Path(path)
        try:
            if p.stat().st_size > MAX_FILE_BYTES:
                return []
            raw = p.read_bytes()
        except (OSError, ValueError):
            return []
        if b"\x00" in raw:  # crude but effective binary sniff
            return []
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            text = raw.decode("latin-1", errors="replace")
        return self.scan_text(text, source=str(p))

    def scan_path(self, root: str | os.PathLike[str]) -> list[Finding]:
        """Scan a file or recurse a directory, pruning :attr:`skip_dirs`."""
        root_path = Path(root)
        if root_path.is_file():
            return self.scan_file(root_path)

        findings: list[Finding] = []
        for dirpath, dirnames, filenames in os.walk(root_path):
            # In-place filter prunes os.walk's descent into skipped dirs.
            dirnames[:] = [d for d in dirnames if d not in self.skip_dirs]
            for name in filenames:
                findings.extend(self.scan_file(Path(dirpath) / name))
        return findings


def sort_findings(findings: Sequence[Finding]) -> list[Finding]:
    """Return findings ordered by severity (desc), then source and line."""
    return sorted(
        findings,
        key=lambda f: (-SEVERITY_ORDER[f.severity], f.source, f.line),
    )
