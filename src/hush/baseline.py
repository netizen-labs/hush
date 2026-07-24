"""Baseline (allowlist) support.

A baseline records the fingerprints of findings you have reviewed and chosen to
accept — test fixtures, example values, documented dummy keys. On subsequent
scans those findings are suppressed, so ``hush`` only ever reports *new* leaks.
This is what makes it usable in CI on an existing codebase.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Sequence

from .scanner import Finding

BASELINE_VERSION = 1


@dataclass
class Baseline:
    """A set of accepted finding fingerprints, persisted as JSON."""

    fingerprints: set[str] = field(default_factory=set)

    def contains(self, finding: Finding) -> bool:
        return finding.fingerprint in self.fingerprints

    def filter(self, findings: Iterable[Finding]) -> list[Finding]:
        """Return only findings *not* present in the baseline."""
        return [f for f in findings if f.fingerprint not in self.fingerprints]

    # -- persistence --------------------------------------------------------

    @classmethod
    def from_findings(cls, findings: Sequence[Finding]) -> "Baseline":
        return cls(fingerprints={f.fingerprint for f in findings})

    @classmethod
    def load(cls, path: str | Path) -> "Baseline":
        """Load a baseline from ``path``; empty baseline if it doesn't exist."""
        p = Path(path)
        if not p.exists():
            return cls()
        data = json.loads(p.read_text(encoding="utf-8"))
        entries = data.get("findings", [])
        return cls(fingerprints={e["fingerprint"] for e in entries})

    def to_json(self, findings: Sequence[Finding] | None = None) -> str:
        """Serialise to JSON. If ``findings`` given, include redacted context.

        Storing a little context (rule, source, redacted secret) makes the
        baseline file reviewable in a pull request instead of an opaque hash
        list — you can see *what* was accepted, never the raw secret.
        """
        if findings is not None:
            entries = [
                {
                    "fingerprint": f.fingerprint,
                    "rule_id": f.rule_id,
                    "source": f.source,
                    "line": f.line,
                    "secret": f.redacted(),
                }
                for f in findings
            ]
        else:
            entries = [{"fingerprint": fp} for fp in sorted(self.fingerprints)]
        payload = {"version": BASELINE_VERSION, "findings": entries}
        return json.dumps(payload, indent=2, sort_keys=False) + "\n"

    def save(self, path: str | Path, findings: Sequence[Finding] | None = None) -> None:
        Path(path).write_text(self.to_json(findings), encoding="utf-8")
