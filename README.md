# secrets-scanner

A real, dependency-light secrets scanner for source trees and git history, plus a genuinely functional GitHub Action wrapper. No external service, no SaaS API key, no network calls — everything runs locally with the Python standard library.

It detects hardcoded credentials via:

- **Signature regexes** for widely-used real-world secret formats (AWS, GitHub, Slack, Google, Stripe, private key PEM headers, JWTs, npm, Twilio, SendGrid, database connection strings, and generic `api_key = "..."` / `password = "..."` assignments).
- A **real Shannon-entropy calculator** as a fallback for high-entropy strings that don't match any known format.
- **Full git history scanning** — it walks every reachable commit with real `git diff-tree`/`git diff` subprocess calls, so it catches secrets that were committed and later "removed" (they're still sitting in history).

## Install

```bash
pip install -e ".[dev]"     # from a clone, with test dependencies
# or, once published:
pip install secrets-scanner
```

This installs the `secrets-scanner` CLI.

## CLI usage

```
secrets-scanner scan <path>                      # scan a file or directory tree
secrets-scanner scan --git-history <repo-path>    # scan the FULL reachable git history
secrets-scanner scan <repo-path> --diff BASE..HEAD  # scan only lines added between BASE and HEAD
```

Common flags:

| Flag | Purpose |
|---|---|
| `--format {table,json}` | Output format (default `table`) |
| `--allowlist FILE` | JSON allowlist/baseline file (see below) |
| `--secretsignore FILE` | `.secretsignore` file (default: `<path>/.secretsignore`) |
| `--no-entropy` | Disable the generic high-entropy fallback detector |
| `--entropy-threshold FLOAT` | Shannon entropy (bits/char) threshold (default `4.3`) |
| `--min-severity {critical,high,medium,low}` | Only report findings at/above this severity |
| `--github-annotations` | Also print `::error file=...,line=...::...` annotations to stderr |

**Exit code is `1` when any finding is reported, `0` otherwise** — this is what makes it useful as a CI gate.

### Real example output

Running against this repo's own positive test fixture — `tests/fixtures/secrets_positive.txt` plus the AWS/Slack/Stripe/Twilio/SendGrid values from `tests/fixtures/secret_fragments.py` (see that file's docstring: those are split into fragments and reassembled only in memory, because GitHub's own push-protection secret scanning correctly blocks committing them as one contiguous string — a nice real-world confirmation that the formats this tool looks for are worth looking for):

```
$ secrets-scanner scan combined_positive.txt
SEVERITY  RULE                           FILE                   LINE  MATCH      COMMIT
--------  -----------------------------  ---------------------  ----  ---------  ------
CRITICAL  github_pat                     combined_positive.txt  13    ghp_…gA9x
CRITICAL  github_fine_grained_pat        combined_positive.txt  14    gith…HJoK
CRITICAL  private_key_header             combined_positive.txt  19    ----…----
CRITICAL  aws_access_key_id              combined_positive.txt  36    AKIA…OPEX
CRITICAL  aws_secret_access_key          combined_positive.txt  37    kL8n…JjKk
CRITICAL  stripe_live_secret_key         combined_positive.txt  40    sk_l…9mVh
CRITICAL  stripe_restricted_key          combined_positive.txt  41    rk_l…9mVh
HIGH      google_api_key                 combined_positive.txt  16    AIza…psia
HIGH      npm_token                      combined_positive.txt  30    npm_…YFjS
HIGH      database_url_with_credentials  combined_positive.txt  32    post…prod
HIGH      slack_token                    combined_positive.txt  38    xoxb…iwRx
HIGH      slack_webhook                  combined_positive.txt  39    http…iwRx
HIGH      twilio_api_key                 combined_positive.txt  42    SK4f…78f6
HIGH      sendgrid_api_key               combined_positive.txt  43    SG.p…wixI
MEDIUM    jwt                            combined_positive.txt  25    eyJh…PYaU
MEDIUM    generic_api_key_assignment     combined_positive.txt  27    Q9xR…zA9x
MEDIUM    generic_password_assignment    combined_positive.txt  28    tR0u…Long
LOW       generic_high_entropy           combined_positive.txt  20    MIIE…r2Wq
LOW       generic_high_entropy           combined_positive.txt  21    FpDD…mvbC
LOW       generic_high_entropy           combined_positive.txt  34    Zk4m…oI2k

20 finding(s).
$ echo $?
1
```

And against a clean fixture (only known documentation-example keys and obvious placeholders — `AKIAIOSFODNN7EXAMPLE`, `your-api-key-here`, `xxxxxxxxxxxxxxxxxxxxxxxx`, etc.):

```
$ secrets-scanner scan tests/fixtures/secrets_clean.txt
No secrets found.
$ echo $?
0
```

`--format json` produces machine-readable output for tooling; the `match` field is always redacted (`AKIA…OPEX`) — the raw secret value is never printed, only used internally to compute the match location and the suppression fingerprint.

### Git history scanning

```bash
secrets-scanner scan --git-history /path/to/repo
```

For every commit reachable from `HEAD` (and any ref/reflog entry), this runs `git diff-tree -p -r --root <sha>` and scans only the **added** lines of each commit's diff. That means a secret that was committed in commit `abc123` and deleted in a later commit still shows up, tagged with the commit (`abc123`) that introduced it — because it genuinely happened in your repo's history and is still recoverable by anyone with clone access, even though it's gone from the working tree.

This is verified end-to-end in `tests/test_git_history.py` against a real, throwaway git repository built in a pytest fixture (`tests/conftest.py`): it inits a repo, commits a file containing an AWS key, commits again removing it, then asserts that a plain working-tree scan finds nothing while a history scan finds the key and correctly attributes it to the introducing commit (not `HEAD`).

### PR-diff-only scanning

```bash
secrets-scanner scan <repo-path> --diff origin/main..HEAD
```

Scans only the lines *added* between two refs — the fast, low-noise mode you want on every PR, as opposed to `--git-history` (slow, exhaustive, good for a periodic/scheduled job).

## False-positive suppression

Real secrets scanners generate false positives; this one is honest about that and gives you three independent ways to suppress them:

1. **Automatic placeholder detection.** Known documentation example keys (e.g. AWS's official `AKIAIOSFODNN7EXAMPLE`), and values that are obviously placeholders (`your-api-key-here`, `REPLACE_ME`, `xxxxxxxxxxxxxxxxxxxxxxxx`, all-same-character strings, and long sequential runs like `abcdefghijklmnop...` or `0123456789`) are filtered out automatically, before allowlist matching even runs. See `secrets_scanner/patterns.py::is_placeholder_value`.

2. **`.secretsignore`** — a gitignore-style file of path globs to skip entirely (test fixtures, vendored code, generated files):

   ```
   # .secretsignore
   tests/fixtures/
   vendor/
   *.min.js
   ```

3. **Allowlist / baseline file** (`--allowlist FILE`, JSON) — suppress specific known values by **literal string**, **regex**, or by **fingerprint hash** (a stable SHA-256-derived hash of `rule + file + value`, independent of line number, so it survives unrelated edits — the same mechanism tools like `detect-secrets` and `gitleaks` use for baselines):

   ```json
   {
     "literals": ["AKIAIOSFODNN7EXAMPLE"],
     "regexes": ["^testonly-"],
     "fingerprints": ["168260e127db710f"]
   }
   ```

   A flat `{"<fingerprint>": true, ...}` shape is also accepted, for simple diffable baselines.

## Using the GitHub Action

This repo *is* a GitHub Action (`action.yml` at the root is a composite action). A consuming repository uses it like:

```yaml
# .github/workflows/secrets-scan.yml
name: Secrets scan
on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0   # required for --diff / --git-history

      - uses: adeev-mardia/secrets-scanner@main
        with:
          mode: diff        # diff | path | history
```

The action installs the scanner, runs it in the chosen mode, and — when secrets are found — prints one real `::error file=<file>,line=<line>,col=<col>::<message>` [GitHub Actions workflow command](https://docs.github.com/en/actions/using-workflows/workflow-commands-for-github-actions) per finding, so each one shows up as an inline annotation on the PR diff or the Checks tab, then fails the step (`exit 1`) so the workflow run goes red. A full working example, including a slower scheduled/periodic full-history job, is at [`.github/workflows/example-usage.yml`](.github/workflows/example-usage.yml).

Action inputs: `mode` (`diff`/`path`/`history`), `path`, `base-ref`, `head-ref`, `allowlist`, `secretsignore`, `min-severity`, `fail-on-findings`.

## Architecture

```
secrets_scanner/
  patterns.py   # Pattern/Severity dataclasses, the signature list, placeholder
                # heuristics, and the real Shannon-entropy implementation.
  scanner.py    # scan_text / scan_path / scan_git_history / scan_diff,
                # Allowlist, SecretsIgnore, Finding, and output formatters
                # (table / JSON / GitHub annotations).
  cli.py        # argparse-based CLI wrapping the above.
action.yml      # Composite GitHub Action that installs + runs the CLI and
                # turns findings into real ::error annotations.
tests/
  fixtures/               # positive (has secrets) and clean (placeholders
                           # only) text fixtures used by the pattern tests.
  conftest.py              # builds a real throwaway git repo per test run.
  test_patterns.py         # one test per signature + entropy + placeholder logic.
  test_scanner.py          # allowlist / .secretsignore / output formatting.
  test_git_history.py      # end-to-end test against the real git repo fixture.
  test_cli.py               # exit codes and JSON output via subprocess.
```

Git history scanning parses unified diffs directly with `git diff-tree`/`git diff` rather than checking out every commit, which keeps a full-history scan of a repo with thousands of commits reasonably fast — it's O(commits), not O(commits × files-in-tree).

## Limitations (read this before you trust it in production)

This is a regex + entropy based scanner, like most open-source secrets scanners (gitleaks, trufflehog, detect-secrets) at their core. That inherently means:

- **False negatives are possible.** A secret in a format not covered by `patterns.py`, or one deliberately obfuscated (base64-wrapped, split across lines, built at runtime via string concatenation), will not be caught by the signature patterns. The entropy fallback catches *some* of these, but entropy alone can't distinguish a real secret from any other random-looking string (a hash, a UUID, a session ID).
- **False positives are possible**, especially from the generic high-entropy fallback and the generic `api_key = "..."` / `password = "..."` patterns — any sufficiently random-looking string, or any variable literally named `api_key`, can trigger a finding. The placeholder heuristics and allowlist mechanism exist precisely because this is unavoidable with a signature-based approach; tune `--entropy-threshold` and use `.secretsignore`/allowlists for your codebase.
- **Git history scanning finds what's reachable.** It walks `git log --reflog --all`-reachable commits; a secret that only ever existed in a rewritten/dropped commit not reachable from any ref or the reflog (e.g. after `git gc` expired it) won't be found — which is also, generally, no longer recoverable by an attacker either.
- **This is a detection aid, not a guarantee.** Treat a clean scan as "no *known-shaped* secret found," not "this codebase has no secrets." Rotate any credential this tool (or a human) finds in history, regardless of whether it's still in the working tree — history scanning finding it means it was, at some point, pushed to whatever remotes the repo was pushed to.
- **Binary files and files matching `DEFAULT_BINARY_EXTENSIONS` are skipped**, as are files under directories like `.git/`, `node_modules/`, `venv/` (see `DEFAULT_EXCLUDED_DIRS` in `scanner.py`) — a secret embedded in, say, a compiled binary won't be found.

## License

MIT — see [LICENSE](LICENSE).
