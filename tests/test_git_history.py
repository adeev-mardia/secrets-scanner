"""End-to-end test of git-history scanning against a real, throwaway git
repository fixture (see conftest.py) where a secret is committed and later
removed. A plain working-tree scan must NOT find it; a history scan MUST."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "fixtures"))
import secret_fragments  # noqa: E402

from secrets_scanner.scanner import ScanOptions, scan_git_history, scan_path

# Same fake AWS key config.py in the throwaway repo fixture is built with
# (see conftest.py) — assembled from a fragment, not stored contiguously.
_FAKE_AWS_KEY = secret_fragments._AWS_KEY_PREFIX + "QWERTYUIOPASDFGH"


def test_working_tree_scan_does_not_find_removed_secret(git_repo_with_removed_secret):
    findings = scan_path(git_repo_with_removed_secret)
    assert findings == [], "secret was removed from HEAD; working-tree scan should be clean"


def test_git_history_scan_finds_secret_committed_and_later_removed(git_repo_with_removed_secret):
    findings = scan_git_history(git_repo_with_removed_secret)
    assert findings, "expected the history scan to find the secret that was committed and later removed"

    aws_findings = [f for f in findings if f.rule == "aws_access_key_id"]
    assert aws_findings, f"expected an aws_access_key_id finding, got rules: {[f.rule for f in findings]}"

    hit = aws_findings[0]
    assert hit.file == "config.py"
    assert hit.commit is not None and len(hit.commit) == 40
    assert _FAKE_AWS_KEY in hit.match or hit.match.startswith("AKIA")


def test_git_history_scan_reports_the_introducing_commit_not_head(git_repo_with_removed_secret):
    findings = scan_git_history(git_repo_with_removed_secret)
    aws_findings = [f for f in findings if f.rule == "aws_access_key_id"]
    assert aws_findings

    # The commit that introduced the secret should NOT be the current HEAD
    # (HEAD is the "remove secret" commit, which has no added AWS key line).
    import subprocess

    head = subprocess.run(
        ["git", "-C", str(git_repo_with_removed_secret), "rev-parse", "HEAD"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()

    assert aws_findings[0].commit != head


def test_git_history_scan_respects_allowlist(git_repo_with_removed_secret):
    from secrets_scanner.scanner import Allowlist

    allowlist = Allowlist(literals={_FAKE_AWS_KEY})
    options = ScanOptions(allowlist=allowlist)
    findings = scan_git_history(git_repo_with_removed_secret, options)
    assert not any(f.rule == "aws_access_key_id" for f in findings)
