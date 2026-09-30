"""
Core scanning engine: text/file scanning, git-history scanning, diff scanning,
allowlist/.secretsignore handling, and baseline suppression.
"""

from __future__ import annotations

import fnmatch
import hashlib
import json
import os
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from .patterns import (
    PATTERNS,
    Pattern,
    Severity,
    find_high_entropy_strings,
    is_placeholder_value,
)

# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

DEFAULT_BINARY_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".pdf", ".zip", ".gz",
    ".tar", ".7z", ".exe", ".dll", ".so", ".dylib", ".class", ".jar",
    ".woff", ".woff2", ".ttf", ".eot", ".mp3", ".mp4", ".mov", ".avi",
    ".pyc", ".o", ".a", ".bin",
}

# Directories that are essentially never worth scanning and commonly huge.
DEFAULT_EXCLUDED_DIRS = {
    ".git", "node_modules", "__pycache__", ".venv", "venv", "dist", "build",
    ".mypy_cache", ".pytest_cache", ".tox", "vendor",
}


@dataclass
class Finding:
    rule: str
    severity: str
    file: str
    line: int
    column: int
    match: str  # the raw matched secret text (may be redacted for display)
    context: str = ""  # the full line, for human output
    commit: str | None = None  # set when found via git-history scan
    fingerprint: str = ""  # stable hash used for allowlisting/baseline

    def __post_init__(self):
        if not self.fingerprint:
            self.fingerprint = compute_fingerprint(self.rule, self.file, self.match)

    def redacted(self) -> str:
        v = self.match
        if len(v) <= 8:
            return "*" * len(v)
        return v[:4] + "…" + v[-4:]

    def to_dict(self) -> dict:
        d = {
            "rule": self.rule,
            "severity": self.severity,
            "file": self.file,
            "line": self.line,
            "column": self.column,
            "match": self.redacted(),
            "context": self.context.strip(),
            "fingerprint": self.fingerprint,
        }
        if self.commit:
            d["commit"] = self.commit
        return d


def compute_fingerprint(rule: str, file: str, value: str) -> str:
    """Stable hash identifying a specific finding, independent of line
    number, so it survives unrelated edits to the surrounding file — the
    same mechanism real scanners (e.g. detect-secrets, gitleaks) use for
    baseline/allowlist-by-hash.
    """
    h = hashlib.sha256()
    h.update(rule.encode("utf-8"))
    h.update(b"\x00")
    h.update(file.encode("utf-8"))
    h.update(b"\x00")
    h.update(value.encode("utf-8"))
    return h.hexdigest()[:16]


# ---------------------------------------------------------------------------
# Ignore / allowlist handling
# ---------------------------------------------------------------------------


class SecretsIgnore:
    """.secretsignore: gitignore-style path-glob exclusion list.

    One glob per line. Blank lines and lines starting with `#` are ignored.
    Matching is done against the path relative to the ignore file's
    directory, using fnmatch semantics plus a "starts with" match for
    directory-style entries (trailing slash or no wildcard).
    """

    def __init__(self, patterns: list[str] | None = None):
        self.patterns = patterns or []

    @classmethod
    def load(cls, path: str | Path) -> "SecretsIgnore":
        path = Path(path)
        if not path.exists():
            return cls([])
        patterns = []
        for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            patterns.append(line)
        return cls(patterns)

    def is_ignored(self, rel_path: str) -> bool:
        rel_path = rel_path.replace(os.sep, "/")
        for pat in self.patterns:
            pat = pat.rstrip("/")
            if fnmatch.fnmatch(rel_path, pat):
                return True
            if fnmatch.fnmatch(rel_path, pat + "/*"):
                return True
            if fnmatch.fnmatch(rel_path, "*/" + pat):
                return True
            if fnmatch.fnmatch(rel_path, "*/" + pat + "/*"):
                return True
            # plain substring/dir-prefix convenience, e.g. "fixtures"
            if "/" not in pat and "*" not in pat:
                parts = rel_path.split("/")
                if pat in parts:
                    return True
        return False


class Allowlist:
    """Suppresses findings by:
    - exact literal string match
    - regex match against the raw secret value
    - fingerprint hash match (baseline file style)
    """

    def __init__(
        self,
        literals: set[str] | None = None,
        regexes: list[re.Pattern] | None = None,
        fingerprints: set[str] | None = None,
    ):
        self.literals = literals or set()
        self.regexes = regexes or []
        self.fingerprints = fingerprints or set()

    @classmethod
    def load(cls, path: str | Path) -> "Allowlist":
        """Load from a JSON file shaped like:

        {
          "literals": ["exact-string-to-ignore"],
          "regexes": ["^test-.*$"],
          "fingerprints": ["abc123..."]
        }

        Also accepts a flat baseline shape `{"<fingerprint>": true, ...}`
        for compatibility with simple baseline-hash-only files.
        """
        path = Path(path)
        if not path.exists():
            return cls()
        data = json.loads(path.read_text(encoding="utf-8"))
        if "literals" in data or "regexes" in data or "fingerprints" in data:
            return cls(
                literals=set(data.get("literals", [])),
                regexes=[re.compile(p) for p in data.get("regexes", [])],
                fingerprints=set(data.get("fingerprints", [])),
            )
        # Flat baseline: {fingerprint: true, ...}
        return cls(fingerprints={k for k, v in data.items() if v})

    def allows(self, value: str, fingerprint: str) -> bool:
        if fingerprint in self.fingerprints:
            return True
        if value in self.literals:
            return True
        for rx in self.regexes:
            if rx.search(value):
                return True
        return False

    def save(self, path: str | Path) -> None:
        path = Path(path)
        path.write_text(
            json.dumps(
                {
                    "literals": sorted(self.literals),
                    "regexes": [r.pattern for r in self.regexes],
                    "fingerprints": sorted(self.fingerprints),
                },
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )

    def add_fingerprint(self, fp: str) -> None:
        self.fingerprints.add(fp)


# ---------------------------------------------------------------------------
# Core scan functions
# ---------------------------------------------------------------------------


@dataclass
class ScanOptions:
    patterns: list[Pattern] = field(default_factory=lambda: list(PATTERNS))
    allowlist: Allowlist = field(default_factory=Allowlist)
    secretsignore: SecretsIgnore = field(default_factory=SecretsIgnore)
    enable_entropy: bool = True
    entropy_threshold: float = 4.3
    entropy_min_length: int = 20
    min_severity: Severity | None = None


_SEVERITY_ORDER = {
    Severity.LOW: 0,
    Severity.MEDIUM: 1,
    Severity.HIGH: 2,
    Severity.CRITICAL: 3,
}


def _line_col(text: str, offset: int) -> tuple[int, int]:
    """Convert a character offset into 1-based (line, column)."""
    line = text.count("\n", 0, offset) + 1
    last_nl = text.rfind("\n", 0, offset)
    col = offset - last_nl  # 1-based column
    return line, col


def scan_text(
    text: str,
    file_label: str,
    options: ScanOptions | None = None,
    commit: str | None = None,
) -> list[Finding]:
    """Scan a chunk of text against all configured patterns plus the
    entropy fallback, returning Finding objects with real line/column
    positions."""
    options = options or ScanOptions()
    findings: list[Finding] = []
    seen_spans: list[tuple[int, int]] = []

    lines = text.splitlines()

    for pattern in options.patterns:
        for m in pattern.finditer(text):
            group = pattern.secret_group
            try:
                value = m.group(group)
                start = m.start(group)
                end = m.end(group)
            except IndexError:  # pragma: no cover - defensive
                value = None
                start, end = m.start(), m.end()
            if value is None:
                value = m.group(0)
                start, end = m.start(), m.end()

            if is_placeholder_value(value):
                continue

            fingerprint = compute_fingerprint(pattern.name, file_label, value)
            if options.allowlist.allows(value, fingerprint):
                continue

            if options.min_severity is not None:
                if _SEVERITY_ORDER[Severity(pattern.severity)] < _SEVERITY_ORDER[options.min_severity]:
                    continue

            line_no, col_no = _line_col(text, start)
            context = lines[line_no - 1] if 0 < line_no <= len(lines) else ""

            findings.append(
                Finding(
                    rule=pattern.name,
                    severity=pattern.severity.value,
                    file=file_label,
                    line=line_no,
                    column=col_no,
                    match=value,
                    context=context,
                    commit=commit,
                    fingerprint=fingerprint,
                )
            )
            seen_spans.append((start, end))

    if options.enable_entropy:
        for start, end, value, entropy in find_high_entropy_strings(
            text, options.entropy_threshold, options.entropy_min_length
        ):
            # Skip if this span overlaps a signature match already reported
            # (avoid double-reporting the same secret under two rules).
            if any(start < s_end and end > s_start for s_start, s_end in seen_spans):
                continue
            if is_placeholder_value(value):
                continue

            fingerprint = compute_fingerprint("generic_high_entropy", file_label, value)
            if options.allowlist.allows(value, fingerprint):
                continue

            severity = Severity.LOW
            if options.min_severity is not None:
                if _SEVERITY_ORDER[severity] < _SEVERITY_ORDER[options.min_severity]:
                    continue

            line_no, col_no = _line_col(text, start)
            context = lines[line_no - 1] if 0 < line_no <= len(lines) else ""

            findings.append(
                Finding(
                    rule="generic_high_entropy",
                    severity=severity.value,
                    file=file_label,
                    line=line_no,
                    column=col_no,
                    match=value,
                    context=f"{context}  # entropy={entropy:.2f}",
                    commit=commit,
                    fingerprint=fingerprint,
                )
            )

    return findings


def _is_binary_path(path: Path) -> bool:
    return path.suffix.lower() in DEFAULT_BINARY_EXTENSIONS


def _looks_binary(sample: bytes) -> bool:
    return b"\x00" in sample


def iter_scannable_files(root: str | Path, secretsignore: SecretsIgnore):
    root = Path(root)
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in DEFAULT_EXCLUDED_DIRS]
        for fname in filenames:
            fpath = Path(dirpath) / fname
            rel = str(fpath.relative_to(root))
            if secretsignore.is_ignored(rel):
                continue
            if _is_binary_path(fpath):
                continue
            yield fpath, rel


def scan_path(path: str | Path, options: ScanOptions | None = None) -> list[Finding]:
    """Scan a single file or a directory tree of files on disk."""
    options = options or ScanOptions()
    path = Path(path)
    findings: list[Finding] = []

    if path.is_file():
        files = [(path, path.name)]
    else:
        files = list(iter_scannable_files(path, options.secretsignore))

    for fpath, rel in files:
        try:
            raw = fpath.read_bytes()
        except OSError:
            continue
        if _looks_binary(raw[:8192]):
            continue
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            text = raw.decode("utf-8", errors="replace")
        findings.extend(scan_text(text, rel, options))

    return findings


# ---------------------------------------------------------------------------
# Git integration (real subprocess calls against a real repo)
# ---------------------------------------------------------------------------


def _run_git(repo_path: str | Path, args: list[str]) -> str:
    result = subprocess.run(
        ["git", "-C", str(repo_path)] + args,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"git {' '.join(args)} failed (exit {result.returncode}): {result.stderr.strip()}"
        )
    return result.stdout


def list_commits(repo_path: str | Path) -> list[str]:
    """Return all commit hashes reachable from HEAD, oldest first."""
    out = _run_git(repo_path, ["log", "--reflog", "--all", "--pretty=%H", "--reverse"])
    return [line.strip() for line in out.splitlines() if line.strip()]


def scan_git_history(
    repo_path: str | Path, options: ScanOptions | None = None
) -> list[Finding]:
    """Scan every commit's *diff* (the lines it added) across the entire
    reachable history of a real git repository. This catches secrets that
    were committed and later removed, because a removed secret still shows
    up as an added line in the commit that introduced it.

    Implementation: for each commit, run `git show <sha>` (or, for the
    root commit, a diff against the empty tree) and scan only the added
    lines (`+...`) of the unified diff, which keeps line numbers meaningful
    within each commit's version of the file and avoids re-scanning
    unchanged context lines repeatedly across every commit.
    """
    options = options or ScanOptions()
    repo_path = Path(repo_path)
    findings: list[Finding] = []

    commits = list_commits(repo_path)
    for sha in commits:
        try:
            diff = _run_git(
                repo_path,
                ["diff-tree", "--no-color", "-p", "-r", "--root", "-M", sha],
            )
        except RuntimeError:
            continue

        findings.extend(_scan_unified_diff(diff, sha, options))

    return findings


def _scan_unified_diff(diff_text: str, commit: str, options: ScanOptions) -> list[Finding]:
    """Parse a unified diff, extracting only added lines per file, and scan
    that reconstructed "added text" per file (preserving relative line
    order so line numbers are meaningful within the diff hunk)."""
    findings: list[Finding] = []
    current_file = None
    added_lines: list[str] = []
    new_line_no = 0

    def flush():
        nonlocal added_lines
        if current_file and added_lines:
            joined = "\n".join(added_lines)
            fs = scan_text(joined, current_file, options, commit=commit)
            findings.extend(fs)
        added_lines = []

    for line in diff_text.splitlines():
        if line.startswith("diff --git "):
            flush()
            current_file = None
        elif line.startswith("+++ "):
            path = line[4:].strip()
            if path == "/dev/null":
                current_file = None
            else:
                current_file = re.sub(r"^b/", "", path)
        elif line.startswith("@@"):
            m = re.match(r"^@@ -\d+(?:,\d+)? \+(\d+)", line)
            if m:
                new_line_no = int(m.group(1))
        elif line.startswith("+") and not line.startswith("+++"):
            added_lines.append(line[1:])
            new_line_no += 1
        elif line.startswith("-") and not line.startswith("---"):
            continue
        else:
            continue
    flush()
    return findings


def scan_diff(repo_path: str | Path, base: str, head: str, options: ScanOptions | None = None) -> list[Finding]:
    """Scan only the lines added between `base` and `head` (e.g. for
    PR-diff-only CI scanning): `git diff base..head`."""
    options = options or ScanOptions()
    diff = _run_git(repo_path, ["diff", "--no-color", f"{base}..{head}"])
    return _scan_unified_diff(diff, commit=f"{base}..{head}", options=options)


# ---------------------------------------------------------------------------
# Output formatting
# ---------------------------------------------------------------------------


def findings_to_json(findings: list[Finding]) -> str:
    return json.dumps([f.to_dict() for f in findings], indent=2)


def findings_to_table(findings: list[Finding]) -> str:
    if not findings:
        return "No secrets found."

    headers = ["SEVERITY", "RULE", "FILE", "LINE", "MATCH", "COMMIT"]
    rows = []
    for f in sorted(findings, key=lambda x: (-_SEVERITY_ORDER[Severity(x.severity)], x.file, x.line)):
        rows.append(
            [
                f.severity.upper(),
                f.rule,
                f.file,
                str(f.line),
                f.redacted(),
                (f.commit or "")[:10],
            ]
        )

    widths = [max(len(h), *(len(r[i]) for r in rows)) for i, h in enumerate(headers)]
    lines = []
    lines.append("  ".join(h.ljust(w) for h, w in zip(headers, widths)))
    lines.append("  ".join("-" * w for w in widths))
    for r in rows:
        lines.append("  ".join(c.ljust(w) for c, w in zip(r, widths)))
    lines.append("")
    lines.append(f"{len(findings)} finding(s).")
    return "\n".join(lines)


def findings_to_github_annotations(findings: list[Finding]) -> str:
    """Format findings as GitHub Actions `::error` workflow-command
    annotations so they surface as inline PR/checks annotations."""
    lines = []
    for f in findings:
        message = f"[{f.severity.upper()}] {f.rule}: possible secret detected ({f.redacted()})"
        message = message.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
        lines.append(f"::error file={f.file},line={f.line},col={f.column}::{message}")
    return "\n".join(lines)
