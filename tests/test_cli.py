import json
from pathlib import Path

import pytest

from hush.cli import EXIT_CLEAN, EXIT_FOUND, main


def _write_leak(tmp_path: Path) -> Path:
    p = tmp_path / "config.py"
    p.write_text('GITHUB_TOKEN = "ghp_' + "a" * 36 + '"\n')
    return p


def test_scan_clean_dir_exits_zero(tmp_path, capsys):
    (tmp_path / "ok.py").write_text("print('hello')\n")
    rc = main(["scan", str(tmp_path)])
    assert rc == EXIT_CLEAN
    assert "No secrets found" in capsys.readouterr().out


def test_scan_leaky_dir_exits_one(tmp_path, capsys):
    _write_leak(tmp_path)
    rc = main(["scan", str(tmp_path)])
    out = capsys.readouterr().out
    assert rc == EXIT_FOUND
    assert "github-token" in out


def test_json_output_is_valid_and_redacted(tmp_path, capsys):
    _write_leak(tmp_path)
    rc = main(["scan", str(tmp_path), "--format", "json"])
    out = capsys.readouterr().out
    assert rc == EXIT_FOUND
    payload = json.loads(out)
    assert payload["count"] >= 1
    secret_field = payload["findings"][0]["secret"]
    assert "*" in secret_field  # redacted by default


def test_reveal_shows_full_secret(tmp_path, capsys):
    _write_leak(tmp_path)
    main(["scan", str(tmp_path), "--format", "json", "--reveal"])
    payload = json.loads(capsys.readouterr().out)
    assert "*" not in payload["findings"][0]["secret"]


def test_baseline_then_scan_suppresses(tmp_path, capsys):
    _write_leak(tmp_path)
    baseline = tmp_path / ".hush-baseline.json"

    rc = main(["baseline", str(tmp_path), "-o", str(baseline)])
    assert rc == EXIT_CLEAN
    assert baseline.exists()
    capsys.readouterr()  # drain

    rc = main(["scan", str(tmp_path), "--baseline", str(baseline)])
    assert rc == EXIT_CLEAN
    assert "No secrets found" in capsys.readouterr().out


def test_min_severity_filters_output(tmp_path, capsys):
    # A JWT is 'medium'; require 'critical' and it should vanish.
    (tmp_path / "t.py").write_text(
        'x = "eyJ' + "a" * 12 + ".eyJ" + "b" * 12 + "." + "c" * 12 + '"\n'
    )
    rc = main(["scan", str(tmp_path), "--min-severity", "critical"])
    assert rc == EXIT_CLEAN


def test_staged_without_repo_errors(tmp_path, capsys, monkeypatch):
    monkeypatch.chdir(tmp_path)
    rc = main(["scan", "--staged"])
    assert rc == 2
    assert "hush:" in capsys.readouterr().err


def test_version_flag(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0
