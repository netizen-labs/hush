"""Shannon-entropy helpers used to catch high-randomness secrets.

Regex rules catch *known* secret shapes (an AWS key, a GitHub token). Entropy
catches the rest: a random 40-char blob assigned to ``API_KEY = "..."`` that no
vendor-specific pattern would ever match. The two approaches are complementary,
so :mod:`hush.scanner` runs both.
"""

from __future__ import annotations

import math
from collections import Counter

# Character alphabets we score independently. A base64 blob and a hex blob have
# very different "expected" entropy ceilings, so comparing each against its own
# threshold gives far fewer false positives than a single global cutoff.
BASE64_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=-_"
HEX_CHARS = "1234567890abcdefABCDEF"


def shannon_entropy(data: str) -> float:
    """Return the Shannon entropy of ``data`` in bits per character.

    A perfectly uniform string over N distinct symbols scores ``log2(N)``; a
    string of one repeated character scores ``0.0``.

    >>> shannon_entropy("") == 0.0
    True
    >>> shannon_entropy("aaaa") == 0.0
    True
    >>> round(shannon_entropy("ab"), 4)
    1.0
    """
    if not data:
        return 0.0
    length = len(data)
    counts = Counter(data)
    return -sum(
        (count / length) * math.log2(count / length) for count in counts.values()
    )


def _entropy_within(data: str, alphabet: str) -> float:
    """Entropy of ``data`` restricted to characters drawn from ``alphabet``.

    Characters outside the alphabet are dropped before scoring so that, e.g.,
    surrounding quotes or punctuation do not dilute the measured randomness.
    """
    filtered = "".join(ch for ch in data if ch in alphabet)
    return shannon_entropy(filtered)


def is_high_entropy(
    token: str,
    *,
    min_length: int = 20,
    base64_threshold: float = 4.5,
    hex_threshold: float = 3.0,
) -> bool:
    """Heuristic: does ``token`` look like a randomly generated secret?

    The token must clear ``min_length`` and then exceed the entropy threshold
    for *either* the base64 or hex alphabet. Thresholds default to values that,
    in practice, separate real credentials from ordinary identifiers and prose.

    >>> is_high_entropy("hello_world_this_is_a_variable")
    False
    >>> is_high_entropy("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")
    True
    """
    token = token.strip().strip("\"'")
    if len(token) < min_length:
        return False
    if _entropy_within(token, BASE64_CHARS) >= base64_threshold:
        return True
    if _entropy_within(token, HEX_CHARS) >= hex_threshold:
        return True
    return False
