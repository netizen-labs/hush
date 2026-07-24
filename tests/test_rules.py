"""Rule-level detection tests.

The credentials below are synthetic, non-functional fixtures built at runtime so
this file itself stays clean under hush's own scan.
"""

import pytest

from hush.scanner import Scanner


@pytest.fixture
def scanner():
    # Disable entropy here so each assertion isolates a single regex rule.
    return Scanner(use_entropy=False)


def _rule_ids(scanner, text):
    return {f.rule_id for f in scanner.scan_text(text, source="t")}


def test_detects_aws_access_key_id(scanner):
    line = "AKIA" + "IOSFODNN7EXAMPLE"
    assert "aws-access-key-id" in _rule_ids(scanner, line)


def test_detects_github_token(scanner):
    token = "ghp_" + "a" * 36
    assert "github-token" in _rule_ids(scanner, token)


def test_detects_stripe_secret_key(scanner):
    key = "sk_live_" + "0123456789abcdefABCD"
    assert "stripe-secret-key" in _rule_ids(scanner, key)


def test_detects_slack_token(scanner):
    token = "xoxb-" + "1234567890-abcdefghij"
    assert "slack-token" in _rule_ids(scanner, token)


def test_detects_google_api_key(scanner):
    key = "AIza" + "b" * 35
    assert "google-api-key" in _rule_ids(scanner, key)


def test_detects_private_key_block(scanner):
    assert "private-key-block" in _rule_ids(
        scanner, "-----BEGIN RSA PRIVATE KEY-----"
    )


def test_detects_jwt(scanner):
    jwt = "eyJ" + "a" * 12 + ".eyJ" + "b" * 12 + "." + "c" * 12
    assert "jwt" in _rule_ids(scanner, jwt)


def test_generic_assignment_requires_entropy():
    scanner = Scanner(use_entropy=False)
    # A low-entropy value must NOT trip the generic rule...
    assert "generic-assignment" not in _rule_ids(scanner, 'password = "aaaaaaaaaaaa"')
    # ...but a random-looking one must.
    ids = _rule_ids(scanner, 'api_key = "Xk9Lm2Qp7Vz4Rb8Nw1Tc6Yd"')
    assert "generic-assignment" in ids


def test_clean_code_yields_nothing(scanner):
    clean = "def add(a, b):\n    return a + b\n"
    assert scanner.scan_text(clean, source="t") == []


def test_severity_filter_drops_low(scanner):
    high_only = Scanner(use_entropy=False, min_severity="critical")
    jwt = "eyJ" + "a" * 12 + ".eyJ" + "b" * 12 + "." + "c" * 12
    # jwt is 'medium', below 'critical', so it is filtered out.
    assert high_only.scan_text(jwt, source="t") == []
