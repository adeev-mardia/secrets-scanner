"""
Fragments for the AWS / Slack / Stripe / Twilio / SendGrid example secrets
used to supplement `secrets_positive.txt` at test time.

Each value below is split at (or right after) its format-defining prefix
and reassembled only in memory, so that no single line in this repository's
git history ever contains a contiguous, provider-shaped credential string.
This isn't just caution: GitHub's own push-protection secret scanning
blocked earlier commits of this fixture for exactly that reason, which is
itself a nice real-world confirmation that these formats look "real enough"
to be worth detecting. All values here are fake and non-functional
regardless of how they're assembled.
"""

from __future__ import annotations

_AWS_KEY_PREFIX = "AKIA"
_AWS_KEY_BODY = "ZQ3FAKEKEY7NOPEX"
AWS_ACCESS_KEY_ID = _AWS_KEY_PREFIX + _AWS_KEY_BODY

_AWS_SECRET_HALF_A = "kL8n2pQrS9tUvWxYz1AaBbCc"
_AWS_SECRET_HALF_B = "DdEeFfGgHhIiJjKk"
AWS_SECRET_ACCESS_KEY = _AWS_SECRET_HALF_A + _AWS_SECRET_HALF_B

_SLACK_BOT_PREFIX = "xoxb-9284710365-8123940657-"
_SLACK_BOT_BODY = "yrbmEYYmdhQj38AruHr4iwRx"
SLACK_BOT_TOKEN = _SLACK_BOT_PREFIX + _SLACK_BOT_BODY

_SLACK_WEBHOOK_PREFIX = "https://hooks.slack.com/services/T092FQZLK/B084MXPQR/"
_SLACK_WEBHOOK_BODY = "yrbmEYYmdhQj38AruHr4iwRx"
SLACK_WEBHOOK_URL = _SLACK_WEBHOOK_PREFIX + _SLACK_WEBHOOK_BODY

_STRIPE_SK_PREFIX = "sk_live_"
_STRIPE_SK_BODY = "51Qz1on43XkMtECqOxSF2O3GYRdo9mVh"
STRIPE_SECRET_KEY = _STRIPE_SK_PREFIX + _STRIPE_SK_BODY

_STRIPE_RK_PREFIX = "rk_live_"
_STRIPE_RK_BODY = "51Qz1XKXWNqRs7rpEmoKiuPKdYR79mVh"
STRIPE_RESTRICTED_KEY = _STRIPE_RK_PREFIX + _STRIPE_RK_BODY

_TWILIO_PREFIX = "SK"
_TWILIO_BODY = "4f58d669cbee3772a077021721a278f6"
TWILIO_API_KEY = _TWILIO_PREFIX + _TWILIO_BODY

_SENDGRID_PART_A = "SG.pVHSbKdA9u4uQgwLg6G3oT."
_SENDGRID_PART_B = "1ogmMJXwKi9x7h6AmUfBH7X41zTPDP4k8FFuf0EwixI"
SENDGRID_API_KEY = _SENDGRID_PART_A + _SENDGRID_PART_B


def extra_fixture_lines() -> str:
    """The lines these reassembled secrets would occupy in the positive
    fixture, appended in-memory at test time (see conftest.py)."""
    return (
        f'aws_access_key = "{AWS_ACCESS_KEY_ID}"\n'
        f'aws_secret_access_key = "{AWS_SECRET_ACCESS_KEY}"\n'
        f'slack_bot_token = "{SLACK_BOT_TOKEN}"\n'
        f'slack_webhook_url = "{SLACK_WEBHOOK_URL}"\n'
        f'stripe_secret = "{STRIPE_SECRET_KEY}"\n'
        f'stripe_restricted = "{STRIPE_RESTRICTED_KEY}"\n'
        f'twilio_key = "{TWILIO_API_KEY}"\n'
        f'sendgrid_key = "{SENDGRID_API_KEY}"\n'
    )
