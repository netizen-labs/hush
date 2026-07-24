# hush 🤫

**A zero-dependency, git-aware secret scanner. Keep your keys hushed.**

`hush` finds leaked credentials — API keys, tokens, private keys — in your code,
your **staged changes**, and your **git history**, before they end up in a public
repo. It's a single pure-Python package with **no runtime dependencies**: nothing
to compile, no supply chain to trust, `pip install` and go.

```text
CRITICAL src/config.py:12
         AWS Access Key ID [aws-access-key-id]
         AKIA****************  (entropy 3.68)

CRITICAL src/config.py:13
         GitHub Personal Access / OAuth / App Token [github-token]
         ghp_****************************aaaa  (entropy 4.90)

Found 2 potential secret(s): 2 critical
```

---

## Why another secret scanner?

There are great tools out there (gitleaks, trufflehog, detect-secrets). `hush`
makes a few deliberate trade-offs:

- **Zero dependencies.** Pure Python standard library. The whole tool is a few
  hundred readable lines — audit it in an afternoon, extend it in a minute.
- **Two detectors, not one.** Curated regex rules catch *known* secret shapes
  (AWS, GitHub, Stripe, Slack, …); a Shannon-**entropy** detector catches the
  random blobs no vendor pattern knows about. They de-duplicate against each
  other so you never get the same leak reported twice.
- **Baselines that are reviewable.** Accept existing/false-positive findings into
  a `.hush-baseline.json` that stores **redacted** context — you can see *what*
  was accepted in code review, and hush only ever reports what's **new**.
- **Git-native.** Scan the index (`--staged`) for a pre-commit gate, or sweep
  the whole history (`--history`) to find secrets that were "removed" but are
  still sitting in old commits (and therefore still compromised).
- **CI-friendly exit codes.** `0` clean, `1` secrets found, `2` error.

## Install

From PyPI (once published):

```bash
pip install hush-scan
```

From source:

```bash
git clone https://github.com/netizen-labs/hush
cd hush
pip install -e .
```

Requires **Python 3.9+**. No other runtime dependencies.

## Usage

### Scan files or directories

```bash
hush scan                 # scan the current directory
hush scan src/ config/    # scan specific paths
hush scan --format json   # machine-readable output
```

Secrets are **redacted** by default. Pass `--reveal` if you really want the raw
values (e.g. to rotate them).

### Pre-commit gate (scan staged changes)

```bash
hush scan --staged
```

This reads the **index** version of each staged file — exactly what's about to be
committed — not your working tree. Wire it up automatically with
[pre-commit](https://pre-commit.com):

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/netizen-labs/hush
    rev: v0.1.0
    hooks:
      - id: hush
```

### Scan git history

```bash
hush scan --history                  # every commit
hush scan --history --max-commits 50 # last 50 commits
```

Findings are labelled `<short-sha>:<path>` so you can trace the leak.

### Baselines (accept known findings)

On an existing codebase you'll have test fixtures and example values. Snapshot
them once:

```bash
hush baseline src/ tests/ -o .hush-baseline.json
```

Then every future scan only surfaces **new** secrets:

```bash
hush scan --baseline .hush-baseline.json
```

Commit `.hush-baseline.json` to your repo. It contains fingerprints and
**redacted** context only — never a raw secret.

### Useful flags

| Flag | Description |
| --- | --- |
| `--no-entropy` | Disable the high-entropy detector (regex rules only). |
| `--min-severity {low,medium,high,critical}` | Ignore findings below this level. |
| `--baseline FILE` | Suppress findings listed in a baseline. |
| `--format {text,json}` | Output format. |
| `--reveal` | Show full secrets instead of redacting. |
| `--staged` | Scan git staged files. |
| `--history [--max-commits N]` | Scan git commit history. |

## Use as a library

```python
from hush import Scanner

scanner = Scanner(use_entropy=True, min_severity="medium")
findings = scanner.scan_path("src/")

for f in findings:
    print(f.severity, f.source, f.line, f.redacted())
```

Add your own rule without forking:

```python
import re
from hush import Scanner, Rule
from hush.rules import DEFAULT_RULES

acme = Rule(
    id="acme-token",
    description="ACME internal token",
    regex=re.compile(r"(?P<secret>acme_[A-Za-z0-9]{32})"),
    severity="high",
    keywords=("acme_",),
)

scanner = Scanner(rules=[*DEFAULT_RULES, acme])
```

## What it detects

Built-in rules cover AWS keys, GitHub/GitLab tokens, Slack tokens and webhooks,
Stripe keys, Google API keys and OAuth IDs, OpenAI/Anthropic keys, JWTs, PEM
private-key blocks, Twilio, SendGrid, npm tokens, and generic high-entropy
`secret = "..."` assignments — plus the entropy detector for everything else.

> **Note:** `hush` is a safety net, not a vault. A clean scan is not a guarantee.
> If a secret has ever been committed, **rotate it** — deletion doesn't un-leak it.

## GitHub Actions

```yaml
name: secret-scan
on: [push, pull_request]
jobs:
  hush:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: { python-version: "3.12" }
      - run: pip install hush-scan
      - run: hush scan --baseline .hush-baseline.json
```

## Development

```bash
pip install -e ".[dev]"
pytest                 # run the suite
pytest --cov=hush      # with coverage
```

## License

MIT © Lucas Gabriel Ramos Aguiar. See [LICENSE](LICENSE).
