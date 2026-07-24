import json
from pathlib import Path

from hush.baseline import Baseline
from hush.scanner import Finding


def _finding(secret="ghpSECRETVALUE0000", source="f.py"):
    return Finding("github-token", "GitHub", "critical", source, 1, secret, 4.0)


def test_from_findings_collects_fingerprints():
    f = _finding()
    b = Baseline.from_findings([f])
    assert b.contains(f)


def test_filter_removes_baselined_findings():
    keep = _finding(secret="NEW-SECRET-VALUE-XYZ")
    accepted = _finding(secret="OLD-ACCEPTED-VALUE")
    baseline = Baseline.from_findings([accepted])
    result = baseline.filter([keep, accepted])
    assert result == [keep]


def test_roundtrip_save_and_load(tmp_path: Path):
    findings = [_finding(secret="AAAA1111BBBB2222"), _finding(secret="CCCC3333DDDD4444")]
    path = tmp_path / ".hush-baseline.json"
    Baseline.from_findings(findings).save(path, findings)

    loaded = Baseline.load(path)
    for f in findings:
        assert loaded.contains(f)


def test_saved_baseline_never_contains_raw_secret(tmp_path: Path):
    secret = "SUPERSECRETVALUE12345"
    f = _finding(secret=secret)
    path = tmp_path / "b.json"
    Baseline.from_findings([f]).save(path, [f])
    text = path.read_text(encoding="utf-8")
    assert secret not in text  # redacted context only
    data = json.loads(text)
    assert data["version"] == 1
    assert data["findings"][0]["fingerprint"] == f.fingerprint


def test_load_missing_file_returns_empty_baseline(tmp_path: Path):
    b = Baseline.load(tmp_path / "nope.json")
    assert b.fingerprints == set()
