"""Integration tests that drive a real temporary git repository.

Skipped automatically when git is not installed, so the suite still passes in
minimal environments.
"""

import shutil
import subprocess

import pytest

from hush.gitutils import (
    GitError,
    is_git_repo,
    scan_history,
    scan_staged,
    staged_files,
)
from hush.scanner import Scanner

pytestmark = pytest.mark.skipif(
    shutil.which("git") is None, reason="git not available"
)

LEAK = 'TOKEN = "ghp_' + "a" * 36 + '"\n'


def _run(args, cwd):
    subprocess.run(args, cwd=cwd, check=True, capture_output=True, text=True)


@pytest.fixture
def repo(tmp_path):
    _run(["git", "init", "-q"], tmp_path)
    _run(["git", "config", "user.email", "t@t.dev"], tmp_path)
    _run(["git", "config", "user.name", "Test"], tmp_path)
    _run(["git", "config", "commit.gpgsign", "false"], tmp_path)
    return tmp_path


def test_is_git_repo_true_inside(repo):
    assert is_git_repo(repo)


def test_is_git_repo_false_outside(tmp_path):
    assert not is_git_repo(tmp_path)


def test_staged_files_lists_added(repo):
    (repo / "config.py").write_text(LEAK)
    _run(["git", "add", "config.py"], repo)
    assert "config.py" in staged_files(cwd=repo)


def test_scan_staged_finds_secret_in_index(repo):
    (repo / "config.py").write_text(LEAK)
    _run(["git", "add", "config.py"], repo)
    findings = scan_staged(Scanner(), cwd=repo)
    assert any(f.rule_id == "github-token" for f in findings)


def test_scan_staged_reads_index_not_worktree(repo):
    # Stage a clean file, then dirty the working tree with a leak. The staged
    # scan must see the clean *index* version, i.e. find nothing.
    f = repo / "config.py"
    f.write_text("clean = 1\n")
    _run(["git", "add", "config.py"], repo)
    f.write_text(LEAK)  # worktree now leaks, index does not
    findings = scan_staged(Scanner(), cwd=repo)
    assert findings == []


def test_scan_history_finds_deleted_secret(repo):
    # Commit a leak, then "remove" it in a later commit. History still has it.
    f = repo / "config.py"
    f.write_text(LEAK)
    _run(["git", "add", "-A"], repo)
    _run(["git", "commit", "-q", "-m", "add config"], repo)
    f.write_text("clean = 1\n")
    _run(["git", "add", "-A"], repo)
    _run(["git", "commit", "-q", "-m", "remove secret"], repo)

    findings = scan_history(Scanner(), cwd=repo)
    assert any(f.rule_id == "github-token" for f in findings)


def test_git_error_on_bad_command(tmp_path):
    with pytest.raises(GitError):
        staged_files(cwd=tmp_path)  # not a repo -> git fails
