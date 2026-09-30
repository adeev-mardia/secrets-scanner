import os
import subprocess
import sys
from pathlib import Path

import pytest

FIXTURES_DIR = Path(__file__).parent / "fixtures"

sys.path.insert(0, str(FIXTURES_DIR))
import secret_fragments  # noqa: E402


@pytest.fixture(scope="session")
def positive_text() -> str:
    """The full positive-fixture text: the static file on disk plus the
    AWS/Slack/Stripe secrets reassembled in-memory from secret_fragments.py
    (see that module's docstring for why they aren't stored contiguously)."""
    static = (FIXTURES_DIR / "secrets_positive.txt").read_text()
    return static + "\n" + secret_fragments.extra_fixture_lines()


@pytest.fixture
def positive_fixture_file(tmp_path: Path, positive_text: str) -> Path:
    """Materializes the full positive fixture (static + reassembled
    AWS/Slack/Stripe secrets) as a real file on disk, for tests that need
    to scan an actual path (CLI / scan_path) rather than in-memory text."""
    path = tmp_path / "secrets_positive_full.txt"
    path.write_text(positive_text)
    return path


def _git(repo: Path, *args: str) -> str:
    env = dict(os.environ)
    env.update(
        {
            "GIT_AUTHOR_NAME": "Test Author",
            "GIT_AUTHOR_EMAIL": "test@example.com",
            "GIT_COMMITTER_NAME": "Test Author",
            "GIT_COMMITTER_EMAIL": "test@example.com",
        }
    )
    result = subprocess.run(
        ["git", "-C", str(repo)] + list(args),
        capture_output=True,
        text=True,
        check=True,
        env=env,
    )
    return result.stdout


@pytest.fixture
def git_repo_with_removed_secret(tmp_path: Path) -> Path:
    """Create a real, throwaway git repository:

    commit 1: add README.md (no secret)
    commit 2: add config.py containing a real-looking AWS key
    commit 3: remove the secret from config.py (rotate it out)

    This lets tests genuinely exercise git-history scanning: a plain
    working-tree scan of HEAD finds nothing, but history scanning must
    still catch the secret introduced (and later removed) in commit 2.
    """
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-q", "-b", "main")
    _git(repo, "config", "user.email", "test@example.com")
    _git(repo, "config", "user.name", "Test Author")

    (repo / "README.md").write_text("# Demo repo\n\nNothing to see here.\n")
    _git(repo, "add", "README.md")
    _git(repo, "commit", "-q", "-m", "Initial commit")

    # Split so this repo's own git history never contains the contiguous
    # AWS-key-shaped string (see secret_fragments.py's docstring) — the
    # commit below still writes the reassembled, fully-formed value into
    # the THROWAWAY repo under tmp_path, which is exactly what the test
    # needs and never touches this repository's own history.
    fake_aws_key = secret_fragments._AWS_KEY_PREFIX + "QWERTYUIOPASDFGH"
    config_path = repo / "config.py"
    config_path.write_text(
        f'AWS_ACCESS_KEY_ID = "{fake_aws_key}"\n'
        'DEBUG = True\n'
    )
    _git(repo, "add", "config.py")
    _git(repo, "commit", "-q", "-m", "Add AWS credentials to config (oops)")

    config_path.write_text(
        "AWS_ACCESS_KEY_ID = os.environ['AWS_ACCESS_KEY_ID']\n"
        "DEBUG = True\n"
    )
    _git(repo, "add", "config.py")
    _git(repo, "commit", "-q", "-m", "Remove hardcoded AWS credentials")

    return repo
