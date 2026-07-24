# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-07-23

### Added
- Regex rules for AWS, GitHub, GitLab, Slack, Stripe, Google, OpenAI,
  Anthropic, Twilio, SendGrid, npm, JWTs, and PEM private keys.
- Shannon-entropy detector for unknown high-randomness secrets, de-duplicated
  against regex matches.
- `hush scan` for files and directories, with directory pruning and binary
  detection.
- `hush scan --staged` to scan the git index (pre-commit gate).
- `hush scan --history [--max-commits N]` to scan commit history.
- `hush baseline` and `--baseline` to accept known findings; baseline files
  store fingerprints and redacted context only.
- Text and JSON output, severity filtering, secret redaction, `--reveal`.
- CI-friendly exit codes (0 clean / 1 found / 2 error).
- pre-commit hook definition and GitHub Actions CI (Linux/macOS/Windows,
  Python 3.9–3.13).
