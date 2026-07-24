"""Command-line interface for hush.

Subcommands:
    scan       Scan files/directories, staged files, or git history.
    baseline   Generate a baseline (allowlist) from current findings.

Exit codes are CI-friendly: ``0`` = clean, ``1`` = secrets found,
``2`` = usage/runtime error.
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Sequence

from . import __version__
from .baseline import Baseline
from .gitutils import GitError, is_git_repo, scan_history, scan_staged
from .rules import SEVERITY_ORDER
from .scanner import Finding, Scanner, sort_findings

EXIT_CLEAN = 0
EXIT_FOUND = 1
EXIT_ERROR = 2

# ANSI colours, disabled when not writing to a TTY or when NO_COLOR is set.
_SEVERITY_COLOR = {
    "critical": "\033[1;31m",
    "high": "\033[31m",
    "medium": "\033[33m",
    "low": "\033[36m",
}
_RESET = "\033[0m"


def _use_color(stream) -> bool:
    import os

    if os.environ.get("NO_COLOR"):
        return False
    return hasattr(stream, "isatty") and stream.isatty()


def _make_utf8_safe(stream) -> None:
    """Best-effort: never crash on a non-UTF-8 console (e.g. Windows cp1252).

    Reconfigures the stream to UTF-8 and replaces any characters it still can't
    encode, so emoji/redaction output degrades to ``?`` instead of raising
    ``UnicodeEncodeError``. No-op on streams that don't support reconfigure.
    """
    try:
        stream.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError):  # already detached / not reconfigurable
        pass


def _color(text: str, severity: str, enabled: bool) -> str:
    if not enabled:
        return text
    return f"{_SEVERITY_COLOR.get(severity, '')}{text}{_RESET}"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="hush",
        description="Zero-dependency secret scanner. Keep your keys hushed.",
    )
    parser.add_argument(
        "--version", action="version", version=f"%(prog)s {__version__}"
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # -- shared scan options ---------------------------------------------
    def add_scan_opts(p: argparse.ArgumentParser) -> None:
        p.add_argument(
            "--no-entropy",
            action="store_true",
            help="disable the high-entropy string detector",
        )
        p.add_argument(
            "--min-severity",
            choices=list(SEVERITY_ORDER),
            default="low",
            help="ignore findings below this severity (default: low)",
        )
        p.add_argument(
            "--baseline",
            metavar="FILE",
            help="suppress findings listed in this baseline file",
        )
        p.add_argument(
            "--format",
            choices=("text", "json"),
            default="text",
            help="output format (default: text)",
        )
        p.add_argument(
            "--reveal",
            action="store_true",
            help="show full secrets instead of redacting them",
        )

    scan = sub.add_parser("scan", help="scan files, staged changes, or history")
    scan.add_argument(
        "paths",
        nargs="*",
        default=["."],
        help="files or directories to scan (default: current directory)",
    )
    scan.add_argument(
        "--staged",
        action="store_true",
        help="scan git staged files instead of paths (for pre-commit)",
    )
    scan.add_argument(
        "--history",
        action="store_true",
        help="scan git commit history for secrets",
    )
    scan.add_argument(
        "--max-commits",
        type=int,
        default=None,
        help="limit history scan to the most recent N commits",
    )
    add_scan_opts(scan)

    base = sub.add_parser("baseline", help="write a baseline from current findings")
    base.add_argument(
        "paths",
        nargs="*",
        default=["."],
        help="files or directories to scan (default: current directory)",
    )
    base.add_argument(
        "-o",
        "--output",
        default=".hush-baseline.json",
        help="baseline file to write (default: .hush-baseline.json)",
    )
    base.add_argument(
        "--no-entropy", action="store_true", help="disable entropy detector"
    )

    return parser


def _make_scanner(args: argparse.Namespace) -> Scanner:
    return Scanner(
        use_entropy=not args.no_entropy,
        min_severity=getattr(args, "min_severity", "low"),
    )


def _collect(args: argparse.Namespace, scanner: Scanner) -> list[Finding]:
    if getattr(args, "staged", False):
        if not is_git_repo():
            raise GitError("not inside a git repository")
        return scan_staged(scanner)
    if getattr(args, "history", False):
        if not is_git_repo():
            raise GitError("not inside a git repository")
        return scan_history(scanner, max_commits=args.max_commits)
    findings: list[Finding] = []
    for path in args.paths:
        findings.extend(scanner.scan_path(path))
    return findings


def _report_text(findings: Sequence[Finding], *, reveal: bool, stream) -> None:
    color = _use_color(stream)
    if not findings:
        print("No secrets found. 🤫", file=stream)
        return
    by_sev: dict[str, int] = {}
    for f in findings:
        by_sev[f.severity] = by_sev.get(f.severity, 0) + 1
    for f in findings:
        secret = f.secret if reveal else f.redacted()
        tag = _color(f.severity.upper().ljust(8), f.severity, color)
        print(f"{tag} {f.source}:{f.line}", file=stream)
        print(f"         {f.description} [{f.rule_id}]", file=stream)
        print(f"         {secret}  (entropy {f.entropy:.2f})", file=stream)
        print(file=stream)
    summary = ", ".join(
        f"{by_sev[s]} {s}" for s in SEVERITY_ORDER if s in by_sev
    )
    print(f"Found {len(findings)} potential secret(s): {summary}", file=stream)


def _report_json(findings: Sequence[Finding], *, reveal: bool, stream) -> None:
    payload = {
        "count": len(findings),
        "findings": [f.to_dict(reveal=reveal) for f in findings],
    }
    json.dump(payload, stream, indent=2)
    stream.write("\n")


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    _make_utf8_safe(sys.stdout)
    _make_utf8_safe(sys.stderr)

    try:
        if args.command == "baseline":
            scanner = _make_scanner(args)
            findings = []
            for path in args.paths:
                findings.extend(scanner.scan_path(path))
            findings = sort_findings(findings)
            Baseline.from_findings(findings).save(args.output, findings)
            print(
                f"Wrote {len(findings)} finding(s) to {args.output}",
                file=sys.stderr,
            )
            return EXIT_CLEAN

        scanner = _make_scanner(args)
        findings = sort_findings(_collect(args, scanner))

        if args.baseline:
            findings = Baseline.load(args.baseline).filter(findings)

    except GitError as exc:
        print(f"hush: {exc}", file=sys.stderr)
        return EXIT_ERROR

    if args.format == "json":
        _report_json(findings, reveal=args.reveal, stream=sys.stdout)
    else:
        _report_text(findings, reveal=args.reveal, stream=sys.stdout)

    return EXIT_FOUND if findings else EXIT_CLEAN


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
