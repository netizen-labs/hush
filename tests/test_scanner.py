from pathlib import Path

import pytest

from hush.scanner import ENTROPY_RULE_ID, Finding, Scanner, sort_findings


@pytest.fixture
def scanner():
    return Scanner()


def test_finding_fingerprint_is_stable_across_lines():
    a = Finding("r", "d", "high", "f.py", 10, "SECRET", 3.0)
    b = Finding("r", "d", "high", "f.py", 99, "SECRET", 3.0)
    assert a.fingerprint == b.fingerprint


def test_finding_fingerprint_changes_with_secret():
    a = Finding("r", "d", "high", "f.py", 1, "SECRET-A", 3.0)
    b = Finding("r", "d", "high", "f.py", 1, "SECRET-B", 3.0)
    assert a.fingerprint != b.fingerprint


def test_redaction_masks_the_middle():
    f = Finding("r", "d", "high", "f", 1, "ABCDEFGHIJKL", 3.0)
    red = f.redacted()
    assert red.startswith("ABCD")
    assert red.endswith("IJKL")
    assert "*" in red
    assert len(red) == len("ABCDEFGHIJKL")


def test_redaction_of_short_secret_does_not_leak():
    f = Finding("r", "d", "high", "f", 1, "abcd", 3.0)
    assert f.redacted() == "a***"


def test_to_dict_redacts_by_default():
    f = Finding("r", "d", "high", "f", 1, "ABCDEFGHIJKL", 3.0)
    assert f.to_dict()["secret"] != "ABCDEFGHIJKL"
    assert f.to_dict(reveal=True)["secret"] == "ABCDEFGHIJKL"


def test_entropy_detector_flags_unknown_random_token(scanner):
    line = 'config.set("Xk9Lm2Qp7Vz4Rb8Nw1Tc6Yd0Ff3Gh")'
    ids = {f.rule_id for f in scanner.scan_text(line, source="t")}
    assert ENTROPY_RULE_ID in ids


def test_entropy_and_rule_do_not_double_report(scanner):
    # A GitHub token is high entropy AND matches a rule; it must be reported
    # once, by the rule, not twice.
    token = "ghp_" + "aB3xK9mP2qL7vN4wR8tY6zC1dF5gH0jS2kL9"
    findings = scanner.scan_text(token, source="t")
    assert len(findings) == 1
    assert findings[0].rule_id == "github-token"


def test_scan_file_skips_binary(tmp_path: Path):
    p = tmp_path / "blob.bin"
    p.write_bytes(b"\x00\x01ghp_" + b"a" * 36)
    assert Scanner().scan_file(p) == []


def test_scan_path_recurses_and_prunes(tmp_path: Path):
    (tmp_path / "src").mkdir()
    (tmp_path / "node_modules").mkdir()
    good = tmp_path / "src" / "app.py"
    good.write_text('token = "ghp_' + "a" * 36 + '"')
    # This one lives in a pruned dir and must be ignored.
    (tmp_path / "node_modules" / "leak.py").write_text('key = "ghp_' + "b" * 36 + '"')

    findings = Scanner().scan_path(tmp_path)
    sources = {f.source for f in findings}
    assert any("app.py" in s for s in sources)
    assert not any("node_modules" in s for s in sources)


def test_scan_missing_file_is_silent():
    assert Scanner().scan_file("does-not-exist-xyz.py") == []


def test_scan_path_skips_baseline_file(tmp_path: Path):
    # Regression: on macOS the temp dir carries a high-entropy random segment
    # (/var/folders/xx/<random>/T/...). A baseline stores that path in its
    # "source" field, so re-scanning the baseline flagged it as a secret,
    # breaking baseline suppression. The baseline file must never be scanned.
    (tmp_path / ".hush-baseline.json").write_text(
        '{"version": 1, "findings": [{"fingerprint": "a1b2c3d4e5f6a7b8",'
        ' "source": "/var/folders/q8/n5kd0f9s2h4j1kL9pQ7xZ/T/x/config.py"}]}'
    )
    (tmp_path / "app.py").write_text("print('hello')\n")
    assert Scanner().scan_path(tmp_path) == []


def test_sort_findings_orders_by_severity():
    low = Finding("r", "d", "low", "a", 1, "x", 1.0)
    crit = Finding("r", "d", "critical", "a", 2, "y", 1.0)
    med = Finding("r", "d", "medium", "a", 3, "z", 1.0)
    ordered = sort_findings([low, crit, med])
    assert [f.severity for f in ordered] == ["critical", "medium", "low"]


def test_invalid_min_severity_raises():
    with pytest.raises(ValueError):
        Scanner(min_severity="bogus")
