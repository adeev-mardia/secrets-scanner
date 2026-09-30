"""Command-line interface for secrets-scanner."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .patterns import Severity
from .scanner import (
    Allowlist,
    ScanOptions,
    SecretsIgnore,
    findings_to_github_annotations,
    findings_to_json,
    findings_to_table,
    scan_diff,
    scan_git_history,
    scan_path,
)


def _build_options(args) -> ScanOptions:
    allowlist = Allowlist.load(args.allowlist) if args.allowlist else Allowlist()
    secretsignore = (
        SecretsIgnore.load(args.secretsignore)
        if args.secretsignore
        else SecretsIgnore.load(Path(args.path or ".") / ".secretsignore")
    )
    min_severity = Severity(args.min_severity) if args.min_severity else None
    return ScanOptions(
        allowlist=allowlist,
        secretsignore=secretsignore,
        enable_entropy=not args.no_entropy,
        entropy_threshold=args.entropy_threshold,
        min_severity=min_severity,
    )


def cmd_scan(args) -> int:
    options = _build_options(args)

    if args.git_history:
        findings = scan_git_history(args.git_history, options)
    elif args.diff:
        try:
            base, head = args.diff.split("..", 1)
        except ValueError:
            print("error: --diff expects BASE..HEAD", file=sys.stderr)
            return 2
        repo = args.path or "."
        findings = scan_diff(repo, base, head, options)
    else:
        target = args.path or "."
        findings = scan_path(target, options)

    if args.format == "json":
        print(findings_to_json(findings))
    else:
        print(findings_to_table(findings))

    if args.github_annotations and findings:
        annotations = findings_to_github_annotations(findings)
        if annotations:
            print(annotations, file=sys.stderr)

    return 1 if findings else 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="secrets-scanner",
        description="Scan files, directories, or git history for leaked secrets.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    scan_p = sub.add_parser("scan", help="Scan a path, git history, or a diff range.")
    scan_p.add_argument("path", nargs="?", default=".", help="File or directory to scan (default: .)")
    scan_p.add_argument("--git-history", metavar="REPO_PATH", help="Scan full git history of REPO_PATH for secrets ever committed.")
    scan_p.add_argument("--diff", metavar="BASE..HEAD", help="Scan only lines added between BASE and HEAD (uses --path/positional path as repo).")
    scan_p.add_argument("--allowlist", metavar="FILE", help="JSON allowlist/baseline file for suppressing known false positives.")
    scan_p.add_argument("--secretsignore", metavar="FILE", help="Path to a .secretsignore file (default: <path>/.secretsignore).")
    scan_p.add_argument("--format", choices=["table", "json"], default="table", help="Output format.")
    scan_p.add_argument("--no-entropy", action="store_true", help="Disable the generic high-entropy fallback detector.")
    scan_p.add_argument("--entropy-threshold", type=float, default=4.3, help="Shannon entropy (bits/char) threshold for the fallback detector.")
    scan_p.add_argument("--min-severity", choices=[s.value for s in Severity], help="Only report findings at or above this severity.")
    scan_p.add_argument("--github-annotations", action="store_true", help="Also print GitHub Actions ::error annotations to stderr.")
    scan_p.set_defaults(func=cmd_scan)

    return parser


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
