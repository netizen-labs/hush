# Contributing to hush

Thanks for helping keep secrets hushed. Contributions are welcome.

## Setup

```bash
git clone https://github.com/netizen-labs/hush
cd hush
pip install -e ".[dev]"
pytest
```

## Guidelines

- **Keep runtime dependencies at zero.** This is the core promise of the
  project. Standard library only in `src/hush/`. Dev/test tooling is fine.
- **Every new rule needs a test.** Add the `Rule` to `src/hush/rules.py` and a
  detection test to `tests/test_rules.py`. Build fixture secrets at runtime
  (e.g. `"ghp_" + "a" * 36`) so hush's own dogfood scan stays clean.
- **Favour precision over recall.** A noisy rule that fires on real code erodes
  trust in every report. If a pattern is inherently loose, gate it behind the
  entropy check like `generic-assignment` does.
- Run `pytest --cov=hush` before opening a PR. Keep coverage from regressing.

## Adding a detection rule

```python
Rule(
    id="acme-token",                 # stable, kebab-case, unique
    description="ACME internal token",
    regex=re.compile(r"(?P<secret>acme_[A-Za-z0-9]{32})"),
    severity="high",                 # low | medium | high | critical
    keywords=("acme_",),             # cheap pre-filter; lowercase
)
```

The `secret` named group is what gets reported and redacted. If you omit it, the
whole match is treated as the secret.

## Reporting security issues

If you find a vulnerability in hush itself, please open a private security
advisory on GitHub rather than a public issue.
