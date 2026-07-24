"""Thin wrappers over the ``git`` CLI for staged-file and history scanning.

We shell out to ``git`` rather than depend on a library: it keeps hush
zero-dependency and always matches the user's real git behaviour (config,
attributes, submodules). All functions degrade gracefully when git is absent or
the cwd is not a repository.
"""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Sequence

from .scanner import Finding, Scanner


class GitError(RuntimeError):
    """Raised when a git invocation fails or git is unavailable."""


def _git(args: Sequence[str], *, cwd: str | Path = ".") -> str:
    """Run a git command, returning stdout. Raises :class:`GitError` on failure."""
    try:
        result = subprocess.run(
            ["git", *args],
            cwd=str(cwd),
            capture_output=True,
            text=True,
            check=True,
        )
    except FileNotFoundError as exc:  # git not installed
        raise GitError("git executable not found on PATH") from exc
    except subprocess.CalledProcessError as exc:
        raise GitError(exc.stderr.strip() or f"git {' '.join(args)} failed") from exc
    return result.stdout


def is_git_repo(cwd: str | Path = ".") -> bool:
    try:
        out = _git(["rev-parse", "--is-inside-work-tree"], cwd=cwd)
    except GitError:
        return False
    return out.strip() == "true"


def staged_files(cwd: str | Path = ".") -> list[str]:
    """Return paths of files staged for commit (added/copied/modified/renamed)."""
    out = _git(
        ["diff", "--cached", "--name-only", "--diff-filter=ACMR"], cwd=cwd
    )
    return [line for line in out.splitlines() if line.strip()]


def staged_blob(path: str, cwd: str | Path = ".") -> str:
    """Return the *staged* (index) content of ``path``.

    This reads the version that will actually be committed, which may differ
    from the working-tree file — the correct thing to scan in a pre-commit hook.
    """
    try:
        return _git(["show", f":{path}"], cwd=cwd)
    except GitError:
        return ""


def scan_staged(scanner: Scanner, cwd: str | Path = ".") -> list[Finding]:
    """Scan every staged file's index content with ``scanner``."""
    findings: list[Finding] = []
    for path in staged_files(cwd=cwd):
        content = staged_blob(path, cwd=cwd)
        if content:
            findings.extend(scanner.scan_text(content, source=path))
    return findings


def _rev_list(max_count: int | None, cwd: str | Path) -> list[str]:
    args = ["rev-list", "HEAD"]
    if max_count is not None:
        args += ["--max-count", str(max_count)]
    return [line for line in _git(args, cwd=cwd).splitlines() if line.strip()]


def scan_history(
    scanner: Scanner,
    *,
    max_commits: int | None = None,
    cwd: str | Path = ".",
) -> list[Finding]:
    """Scan the added lines of each commit's diff for secrets.

    A leak that was committed and later "removed" still lives in history and is
    still compromised. Scanning ``git log -p`` added lines surfaces those. The
    finding ``source`` is labelled ``<short-sha>:<path>``.
    """
    findings: list[Finding] = []
    for sha in _rev_list(max_commits, cwd):
        short = sha[:10]
        diff = _git(
            ["show", "--no-color", "--format=", "--unified=0", sha], cwd=cwd
        )
        current_file = "?"
        line_no = 0
        for line in diff.splitlines():
            if line.startswith("+++ b/"):
                current_file = line[6:]
            elif line.startswith("@@"):
                # @@ -a,b +c,d @@  -> capture the new-file start line c
                try:
                    plus = line.split("+", 1)[1]
                    line_no = int(plus.split(",", 1)[0].split(" ", 1)[0])
                except (IndexError, ValueError):
                    line_no = 0
            elif line.startswith("+") and not line.startswith("+++"):
                added = line[1:]
                for f in scanner.scan_line(
                    added, source=f"{short}:{current_file}", line_no=line_no
                ):
                    findings.append(f)
                line_no += 1
    return findings
