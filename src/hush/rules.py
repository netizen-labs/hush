"""Built-in detection rules for well-known credential formats.

Each :class:`Rule` pairs a compiled regex with metadata. Rules are intentionally
data, not code: adding coverage for a new provider is a one-line append, and
users can extend :data:`DEFAULT_RULES` at runtime without touching the scanner.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Pattern

# Severity levels, ordered. Used for filtering (``--min-severity``) and sorting.
SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}


@dataclass(frozen=True)
class Rule:
    """A single named detector.

    Attributes:
        id: Stable machine identifier (used in baselines and JSON output).
        description: Human-readable name shown in reports.
        regex: Compiled pattern. The captured secret is group ``"secret"`` if the
            pattern defines it, otherwise the whole match.
        severity: One of ``low``, ``medium``, ``high``, ``critical``.
        keywords: Optional lowercase hints; if set, a line must contain at least
            one before the (more expensive) regex is tried. A cheap pre-filter.
    """

    id: str
    description: str
    regex: Pattern[str]
    severity: str = "high"
    keywords: tuple[str, ...] = field(default_factory=tuple)

    def secret_from(self, match: re.Match[str]) -> str:
        """Extract the sensitive substring from a successful match."""
        if "secret" in match.re.groupindex:
            return match.group("secret")
        return match.group(0)


def _c(pattern: str) -> Pattern[str]:
    return re.compile(pattern)


# NOTE: patterns favour precision over exhaustive coverage. A missed variant is a
# follow-up rule; a noisy rule erodes trust in every report. The example secrets
# in tests are non-functional fixtures, not real credentials.
DEFAULT_RULES: tuple[Rule, ...] = (
    Rule(
        id="aws-access-key-id",
        description="AWS Access Key ID",
        regex=_c(r"(?P<secret>(?:AKIA|ASIA|AGPA|AIDA|AROA)[0-9A-Z]{16})"),
        severity="critical",
        keywords=("akia", "asia", "agpa", "aida", "aroa"),
    ),
    Rule(
        id="aws-secret-access-key",
        description="AWS Secret Access Key",
        regex=_c(
            r"(?i)aws.{0,20}?(?:secret|access).{0,20}?['\"]"
            r"(?P<secret>[A-Za-z0-9/+=]{40})['\"]"
        ),
        severity="critical",
        keywords=("aws",),
    ),
    Rule(
        id="github-token",
        description="GitHub Personal Access / OAuth / App Token",
        regex=_c(r"(?P<secret>gh[pousr]_[A-Za-z0-9]{36,255})"),
        severity="critical",
        keywords=("ghp_", "gho_", "ghu_", "ghs_", "ghr_"),
    ),
    Rule(
        id="gitlab-pat",
        description="GitLab Personal Access Token",
        regex=_c(r"(?P<secret>glpat-[A-Za-z0-9_-]{20})"),
        severity="critical",
        keywords=("glpat-",),
    ),
    Rule(
        id="slack-token",
        description="Slack Token",
        regex=_c(r"(?P<secret>xox[baprs]-[A-Za-z0-9-]{10,48})"),
        severity="high",
        keywords=("xox",),
    ),
    Rule(
        id="slack-webhook",
        description="Slack Incoming Webhook URL",
        regex=_c(
            r"(?P<secret>https://hooks\.slack\.com/services/"
            r"T[A-Za-z0-9_]+/B[A-Za-z0-9_]+/[A-Za-z0-9_]+)"
        ),
        severity="medium",
        keywords=("hooks.slack.com",),
    ),
    Rule(
        id="stripe-secret-key",
        description="Stripe Secret Key",
        regex=_c(r"(?P<secret>(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,64})"),
        severity="critical",
        keywords=("sk_live", "sk_test", "rk_live", "rk_test"),
    ),
    Rule(
        id="google-api-key",
        description="Google API Key",
        regex=_c(r"(?P<secret>AIza[0-9A-Za-z_-]{35})"),
        severity="high",
        keywords=("aiza",),
    ),
    Rule(
        id="google-oauth-id",
        description="Google OAuth Client ID",
        regex=_c(r"(?P<secret>[0-9]+-[0-9a-z]{32}\.apps\.googleusercontent\.com)"),
        severity="low",
        keywords=("googleusercontent.com",),
    ),
    Rule(
        id="openai-api-key",
        description="OpenAI API Key",
        regex=_c(r"(?P<secret>sk-(?:proj-)?[A-Za-z0-9_-]{20,120})"),
        severity="high",
        keywords=("sk-",),
    ),
    Rule(
        id="anthropic-api-key",
        description="Anthropic API Key",
        regex=_c(r"(?P<secret>sk-ant-[A-Za-z0-9_-]{20,120})"),
        severity="high",
        keywords=("sk-ant-",),
    ),
    Rule(
        id="jwt",
        description="JSON Web Token",
        regex=_c(
            r"(?P<secret>eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}"
            r"\.[A-Za-z0-9_-]{10,})"
        ),
        severity="medium",
        keywords=("eyj",),
    ),
    Rule(
        id="private-key-block",
        description="Private Key Block (PEM)",
        regex=_c(r"(?P<secret>-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----)"),
        severity="critical",
        keywords=("private key",),
    ),
    Rule(
        id="twilio-api-key",
        description="Twilio API Key",
        regex=_c(r"(?P<secret>SK[0-9a-fA-F]{32})"),
        severity="high",
        keywords=("sk",),
    ),
    Rule(
        id="sendgrid-api-key",
        description="SendGrid API Key",
        regex=_c(r"(?P<secret>SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43})"),
        severity="high",
        keywords=("sg.",),
    ),
    Rule(
        id="npm-token",
        description="npm Access Token",
        regex=_c(r"(?P<secret>npm_[A-Za-z0-9]{36})"),
        severity="high",
        keywords=("npm_",),
    ),
    Rule(
        id="generic-assignment",
        description="Generic high-entropy secret assignment",
        # Matches `password = "..."`, `api_key: '...'`, `TOKEN="..."` etc. The
        # entropy gate in the scanner decides whether the value is real.
        regex=_c(
            r"(?i)(?:password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|"
            r"auth|credential)s?\s*[:=]\s*['\"](?P<secret>[^'\"\s]{12,120})['\"]"
        ),
        severity="medium",
        keywords=(
            "password",
            "passwd",
            "pwd",
            "secret",
            "token",
            "key",
            "auth",
            "credential",
        ),
    ),
)
