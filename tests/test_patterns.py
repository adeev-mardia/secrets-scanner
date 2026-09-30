"""Per-pattern detection tests: each signature must fire on the positive
fixture and must NOT fire (false-positive) on the clean fixture."""

from pathlib import Path

import pytest

from secrets_scanner.patterns import shannon_entropy, is_placeholder_value
from secrets_scanner.scanner import ScanOptions, scan_text

FIXTURES = Path(__file__).parent / "fixtures"

# `positive_text` (static fixture + reassembled AWS/Slack/Stripe secrets)
# comes from conftest.py as a session-scoped fixture.


@pytest.fixture(scope="module")
def clean_text():
    return (FIXTURES / "secrets_clean.txt").read_text()


@pytest.mark.parametrize(
    "rule_name",
    [
        "aws_access_key_id",
        "aws_secret_access_key",
        "github_pat",
        "github_fine_grained_pat",
        "slack_token",
        "slack_webhook",
        "google_api_key",
        "stripe_live_secret_key",
        "stripe_restricted_key",
        "private_key_header",
        "jwt",
        "generic_api_key_assignment",
        "generic_password_assignment",
        "npm_token",
        "twilio_api_key",
        "sendgrid_api_key",
        "database_url_with_credentials",
    ],
)
def test_pattern_detects_on_positive_fixture(positive_text, rule_name):
    findings = scan_text(positive_text, "secrets_positive.txt")
    rules_hit = {f.rule for f in findings}
    assert rule_name in rules_hit, f"{rule_name} did not fire on positive fixture"


def test_no_findings_on_clean_fixture(clean_text):
    findings = scan_text(clean_text, "secrets_clean.txt")
    # The clean fixture is built entirely from known-example / placeholder
    # values and ordinary code; nothing should be reported.
    assert findings == [], f"unexpected findings on clean fixture: {findings}"


def test_positive_fixture_has_no_unexpected_noise(positive_text):
    """Sanity check: the positive fixture should yield a reasonable number
    of findings (one per secret), not wildly more (regex over-matching) or
    fewer (regex under-matching)."""
    findings = scan_text(positive_text, "secrets_positive.txt")
    assert 12 <= len(findings) <= 30


class TestEntropy:
    def test_high_entropy_string_has_high_entropy(self):
        # Random-looking base62 string: no repetition
        value = "Zk4mP9xQ2vT7bR1nW8yL3cJ6hD0sA5gF4uE9oI2k"
        assert shannon_entropy(value) > 4.3

    def test_low_entropy_string_has_low_entropy(self):
        value = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        assert shannon_entropy(value) < 1.0

    def test_english_word_has_lower_entropy_than_random_token(self):
        english = "thequickbrownfoxjumpsoverthelazydog"
        random_token = "Zk4mP9xQ2vT7bR1nW8yL3cJ6hD0sA5gF4uE9oI2k"
        assert shannon_entropy(random_token) > shannon_entropy(english)

    def test_empty_string_has_zero_entropy(self):
        assert shannon_entropy("") == 0.0

    def test_entropy_fallback_catches_unrecognized_secret_shape(self):
        text = 'auth_blob = "Zk4mP9xQ2vT7bR1nW8yL3cJ6hD0sA5gF4uE9oI2k"\n'
        findings = scan_text(text, "sample.py", ScanOptions(patterns=[]))
        assert any(f.rule == "generic_high_entropy" for f in findings)

    def test_entropy_fallback_can_be_disabled(self):
        text = 'auth_blob = "Zk4mP9xQ2vT7bR1nW8yL3cJ6hD0sA5gF4uE9oI2k"\n'
        options = ScanOptions(patterns=[], enable_entropy=False)
        findings = scan_text(text, "sample.py", options)
        assert findings == []


class TestPlaceholderDetection:
    @pytest.mark.parametrize(
        "value",
        [
            "AKIAIOSFODNN7EXAMPLE",
            "your-api-key-here",
            "REPLACE_ME",
            "xxxxxxxxxxxxxxxxxxxxxxxx",
            "0000000000000000",
            "abcdefghijklmnopqrstuvwx",
        ],
    )
    def test_recognizes_placeholder(self, value):
        assert is_placeholder_value(value) is True

    def test_real_looking_secret_is_not_a_placeholder(self):
        assert is_placeholder_value("Zk4mP9xQ2vT7bR1nW8yL3cJ6hD0sA5gF4uE9oI2k") is False


def test_line_and_column_are_correct():
    text = "line one\nline two api_key = \"Q9xR2mK7pL4vN8sT3wY6c\"\nline three\n"
    findings = scan_text(text, "sample.py")
    assert findings, "expected the generic api key pattern to fire"
    f = findings[0]
    assert f.line == 2
    assert text.splitlines()[f.line - 1] == findings[0].context
    # column should point at (or before) the value within line 2
    assert 1 <= f.column <= len(text.splitlines()[1])
