"""
Secret-detection pattern library.

Each `Pattern` carries a compiled regex, a human name, a severity, and an
optional set of substrings/regexes that mark a match as a known placeholder
(e.g. AWS documentation example keys) so the scanner can skip it before it
ever reaches the allowlist stage.

This is intentionally a *library of signatures* rather than a single giant
regex: each pattern is independently testable and independently tunable.
"""

from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import dataclass, field
from enum import Enum


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass(frozen=True)
class Pattern:
    """A single secret-detection signature."""

    name: str
    regex: "re.Pattern[str]"
    severity: Severity
    description: str = ""
    # Group index (within `regex`) that contains the actual secret value,
    # used for hashing/allowlisting. 0 means "the whole match".
    secret_group: int = 0

    def finditer(self, text: str):
        return self.regex.finditer(text)


# ---------------------------------------------------------------------------
# Known-placeholder detection
# ---------------------------------------------------------------------------
# Values that are famous "this is not a real secret" examples, used widely in
# documentation, tests, and tutorials. We hard-exclude these regardless of
# allowlist configuration, because false-positiving on them is extremely
# common and extremely unhelpful.
KNOWN_PLACEHOLDER_VALUES = {
    "AKIAIOSFODNN7EXAMPLE",  # official AWS docs example access key id
    "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",  # official AWS docs example secret key
}

# Generic placeholder heuristics: strings that are clearly not real secrets
# because they're made of a repeated character, sequential characters, or
# common "fill this in" wording.
_PLACEHOLDER_WORDS_RE = re.compile(
    r"(?i)("
    r"your[-_]?api[-_]?key([-_]?here)?"
    r"|your[-_]?secret([-_]?here)?"
    r"|your[-_]?token([-_]?here)?"
    r"|insert[-_]?key[-_]?here"
    r"|replace[-_]?me"
    r"|change[-_]?me"
    r"|\bexample\b"
    r"|placeholder"
    r"|dummy"
    r"|\bfake\b"
    r"|\bsample\b"
    r"|test[-_]?key"
    r"|<[a-z_-]+>"
    r"|\{\{.*\}\}"
    r"|\$\{.*\}"
    r")"
)


def is_placeholder_value(value: str) -> bool:
    """Heuristically decide whether a matched secret value is an obvious
    placeholder/example/fixture value rather than a real credential."""
    if value in KNOWN_PLACEHOLDER_VALUES:
        return True

    stripped = value.strip("'\"")

    if _PLACEHOLDER_WORDS_RE.search(stripped):
        return True

    # All-same-character (e.g. "xxxxxxxxxxxxxxxx") or trivially repetitive.
    core = re.sub(r"[^A-Za-z0-9]", "", stripped)
    if core and len(set(core.lower())) <= 2:
        return True

    # Sequential digits/letters, possibly concatenated (e.g. "0123456789",
    # "abcdefgh", or "abc...xyz0123456789"): flag when a single run of
    # consecutive-ordinal characters covers most of the string.
    if len(core) >= 6:
        ordinals = [ord(c) for c in core.lower()]
        longest_run = 1
        current_run = 1
        for a, b in zip(ordinals, ordinals[1:]):
            if b - a == 1:
                current_run += 1
                longest_run = max(longest_run, current_run)
            else:
                current_run = 1
        if longest_run >= 6 and longest_run / len(core) >= 0.5:
            return True

    return False


# ---------------------------------------------------------------------------
# Shannon entropy helper (used by the generic high-entropy fallback pattern)
# ---------------------------------------------------------------------------
def shannon_entropy(data: str) -> float:
    """Real Shannon entropy, in bits per character, of `data`.

    H = -sum(p_i * log2(p_i)) over the character frequency distribution.
    An empty string has zero entropy by convention.
    """
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    entropy = 0.0
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


# Candidate token shapes the entropy detector considers: long runs of
# base64/hex-ish characters that look like they could be a key/token, found
# inside common assignment contexts OR as bare standalone tokens.
_ENTROPY_CANDIDATE_RE = re.compile(r"[A-Za-z0-9+/_=\-]{20,}")

# Thresholds tuned empirically: real API keys/tokens/base64 secrets commonly
# sit at 4.0-6.0 bits/char for length >= 20; English words / repeated
# characters / hex-lowercase-only UUIDs sit lower.
DEFAULT_ENTROPY_THRESHOLD = 4.3
DEFAULT_ENTROPY_MIN_LENGTH = 20


def find_high_entropy_strings(
    text: str,
    threshold: float = DEFAULT_ENTROPY_THRESHOLD,
    min_length: int = DEFAULT_ENTROPY_MIN_LENGTH,
):
    """Yield (match_object_like, entropy) for candidate substrings of `text`
    whose Shannon entropy exceeds `threshold`.

    Returns tuples of (start, end, value, entropy) rather than re.Match
    since the value's bounds do not necessarily correspond to a single
    regex group.
    """
    for m in _ENTROPY_CANDIDATE_RE.finditer(text):
        value = m.group(0)
        if len(value) < min_length:
            continue
        entropy = shannon_entropy(value)
        if entropy >= threshold:
            yield m.start(), m.end(), value, entropy


# ---------------------------------------------------------------------------
# Signature patterns
# ---------------------------------------------------------------------------
def _p(name, pattern, severity, description="", flags=0, secret_group=0):
    return Pattern(
        name=name,
        regex=re.compile(pattern, flags),
        severity=severity,
        description=description,
        secret_group=secret_group,
    )


PATTERNS: list[Pattern] = [
    _p(
        "aws_access_key_id",
        r"\b(AKIA|ASIA)[0-9A-Z]{16}\b",
        Severity.CRITICAL,
        "AWS Access Key ID",
    ),
    _p(
        "aws_secret_access_key",
        r"(?i)(aws_secret_access_key|aws_secret_key|secret_access_key)\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?",
        Severity.CRITICAL,
        "AWS Secret Access Key (contextual, 40-char base64-ish value)",
        secret_group=2,
    ),
    _p(
        "github_pat",
        r"\b(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,255}\b",
        Severity.CRITICAL,
        "GitHub personal/OAuth/app/refresh token",
    ),
    _p(
        "github_fine_grained_pat",
        r"\bgithub_pat_[A-Za-z0-9_]{22,255}\b",
        Severity.CRITICAL,
        "GitHub fine-grained personal access token",
    ),
    _p(
        "slack_token",
        r"\bxox[baprs]-[0-9A-Za-z-]{10,72}\b",
        Severity.HIGH,
        "Slack API token (bot/user/app/refresh/legacy)",
    ),
    _p(
        "slack_webhook",
        r"https://hooks\.slack\.com/services/T[0-9A-Za-z]{5,}/B[0-9A-Za-z]{5,}/[0-9A-Za-z]{20,}",
        Severity.HIGH,
        "Slack incoming webhook URL",
    ),
    _p(
        "google_api_key",
        r"\bAIza[0-9A-Za-z_-]{35}\b",
        Severity.HIGH,
        "Google API key",
    ),
    _p(
        "stripe_live_secret_key",
        r"\bsk_live_[0-9A-Za-z]{16,99}\b",
        Severity.CRITICAL,
        "Stripe live secret key",
    ),
    _p(
        "stripe_live_publishable_key",
        r"\bpk_live_[0-9A-Za-z]{16,99}\b",
        Severity.LOW,
        "Stripe live publishable key (not secret, but flags live-mode use)",
    ),
    _p(
        "stripe_restricted_key",
        r"\brk_live_[0-9A-Za-z]{16,99}\b",
        Severity.CRITICAL,
        "Stripe live restricted key",
    ),
    _p(
        "private_key_header",
        r"-----BEGIN (RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----",
        Severity.CRITICAL,
        "PEM-encoded private key header",
    ),
    _p(
        "jwt",
        r"\bey[A-Za-z0-9_-]{10,}\.ey[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b",
        Severity.MEDIUM,
        "JSON Web Token (header.payload.signature shape)",
    ),
    _p(
        "generic_api_key_assignment",
        r"(?i)\b(api[_-]?key|apikey|api[_-]?secret|access[_-]?token|auth[_-]?token|client[_-]?secret)\s*[:=]\s*['\"]([A-Za-z0-9_\-/+=.]{16,})['\"]",
        Severity.MEDIUM,
        "Generic API key/secret/token assignment",
        secret_group=2,
    ),
    _p(
        "generic_password_assignment",
        r"(?i)\b(password|passwd|pwd)\s*[:=]\s*['\"]([^'\"\s]{8,})['\"]",
        Severity.MEDIUM,
        "Generic password assignment",
        secret_group=2,
    ),
    _p(
        "npm_token",
        r"\bnpm_[A-Za-z0-9]{36}\b",
        Severity.HIGH,
        "npm access token",
    ),
    _p(
        "twilio_api_key",
        r"\bSK[0-9a-fA-F]{32}\b",
        Severity.HIGH,
        "Twilio API key",
    ),
    _p(
        "sendgrid_api_key",
        r"\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b",
        Severity.HIGH,
        "SendGrid API key",
    ),
    _p(
        "heroku_api_key",
        r"(?i)heroku[a-z_]*['\"]?\s*[:=]\s*['\"]?[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}['\"]?",
        Severity.MEDIUM,
        "Heroku API key (contextual UUID)",
    ),
    _p(
        "database_url_with_credentials",
        r"\b(postgres|postgresql|mysql|mongodb(?:\+srv)?|redis|amqp)://[^:\s]+:[^@\s]+@[^\s'\"]+",
        Severity.HIGH,
        "Database/connection URL containing embedded credentials",
    ),
]

# Fast lookup by name, useful for tests / CLI filtering.
PATTERNS_BY_NAME: dict[str, Pattern] = {p.name: p for p in PATTERNS}
