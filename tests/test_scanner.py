"""Tests for scan_path, allowlist/.secretsignore suppression, and output
formatting."""

import json
from pathlib import Path

import pytest

from secrets_scanner.scanner import (
    Allowlist,
    ScanOptions,
    SecretsIgnore,
    compute_fingerprint,
    findings_to_github_annotations,
    findings_to_json,
    findings_to_table,
    scan_path,
    scan_text,
)

FIXTURES = Path(__file__).parent / "fixtures"


def test_scan_path_directory_finds_secrets_in_positive_fixture_only():
    findings = scan_path(FIXTURES)
    files_with_findings = {f.file for f in findings}
    assert any(f.endswith("secrets_positive.txt") for f in files_with_findings)
    assert not any(f.endswith("secrets_clean.txt") for f in files_with_findings)


def test_scan_path_single_file():
    findings = scan_path(FIXTURES / "secrets_positive.txt")
    assert len(findings) > 0


class TestAllowlist:
    def test_literal_suppression(self):
        text = 'api_key = "sup3rDup3rS3cr3tApiK3yValue12345"\n'
        baseline = scan_text(text, "f.py")
        assert baseline, "expected a baseline finding before allowlisting"
        value = baseline[0].match

        allowlist = Allowlist(literals={value})
        options = ScanOptions(allowlist=allowlist)
        findings = scan_text(text, "f.py", options)
        assert findings == []

    def test_regex_suppression(self):
        text = 'api_key = "testonly-1234567890abcdef"\n'
        allowlist = Allowlist(regexes=[__import__("re").compile(r"^testonly-")])
        options = ScanOptions(allowlist=allowlist)
        findings = scan_text(text, "f.py", options)
        assert findings == []

    def test_fingerprint_suppression(self):
        text = 'api_key = "sup3rDup3rS3cr3tApiK3yValue12345"\n'
        baseline = scan_text(text, "f.py")
        assert baseline
        fp = baseline[0].fingerprint

        allowlist = Allowlist(fingerprints={fp})
        options = ScanOptions(allowlist=allowlist)
        findings = scan_text(text, "f.py", options)
        assert findings == []

    def test_fingerprint_is_stable_across_repeated_scans(self):
        text = 'api_key = "sup3rDup3rS3cr3tApiK3yValue12345"\n'
        a = scan_text(text, "f.py")
        b = scan_text(text, "f.py")
        assert a[0].fingerprint == b[0].fingerprint

    def test_allowlist_save_and_load_round_trip(self, tmp_path):
        allowlist = Allowlist(
            literals={"foo"},
            regexes=[__import__("re").compile(r"^bar")],
            fingerprints={"deadbeef12345678"},
        )
        path = tmp_path / "allowlist.json"
        allowlist.save(path)

        loaded = Allowlist.load(path)
        assert loaded.literals == {"foo"}
        assert loaded.fingerprints == {"deadbeef12345678"}
        assert any(r.pattern == "^bar" for r in loaded.regexes)

    def test_flat_baseline_format_loads_as_fingerprints(self, tmp_path):
        path = tmp_path / "baseline.json"
        path.write_text(json.dumps({"abc123deadbeef01": True, "ignored": False}))
        loaded = Allowlist.load(path)
        assert loaded.fingerprints == {"abc123deadbeef01"}


class TestSecretsIgnore:
    def test_ignores_matching_directory(self, tmp_path):
        (tmp_path / "vendor").mkdir()
        (tmp_path / "vendor" / "secret.txt").write_text(
            'api_key = "sup3rDup3rS3cr3tApiK3yValue12345"\n'
        )
        (tmp_path / "app.py").write_text(
            'api_key = "sup3rDup3rS3cr3tApiK3yValue12345"\n'
        )
        (tmp_path / ".secretsignore").write_text("vendor/\n")

        ignore = SecretsIgnore.load(tmp_path / ".secretsignore")
        options = ScanOptions(secretsignore=ignore)
        findings = scan_path(tmp_path, options)

        files_hit = {f.file for f in findings}
        assert "app.py" in files_hit
        assert not any("vendor" in f for f in files_hit)

    def test_ignores_glob_pattern(self, tmp_path):
        (tmp_path / "test_fixture.py").write_text(
            'api_key = "sup3rDup3rS3cr3tApiK3yValue12345"\n'
        )
        ignore = SecretsIgnore(["test_*.py"])
        options = ScanOptions(secretsignore=ignore)
        findings = scan_path(tmp_path, options)
        assert findings == []

    def test_empty_ignore_file_ignores_nothing(self, tmp_path):
        ignore = SecretsIgnore.load(tmp_path / "does_not_exist")
        assert ignore.is_ignored("anything.py") is False


class TestOutputFormatting:
    def test_json_output_is_valid_json_and_redacts_value(self):
        findings = scan_path(FIXTURES / "secrets_positive.txt")
        out = findings_to_json(findings)
        parsed = json.loads(out)
        assert isinstance(parsed, list)
        assert len(parsed) == len(findings)
        for entry in parsed:
            assert "…" in entry["match"] or set(entry["match"]) == {"*"}

    def test_table_output_reports_no_secrets_found(self):
        assert findings_to_table([]) == "No secrets found."

    def test_table_output_contains_headers_and_count(self):
        findings = scan_path(FIXTURES / "secrets_positive.txt")
        table = findings_to_table(findings)
        assert "SEVERITY" in table
        assert f"{len(findings)} finding(s)." in table

    def test_github_annotations_format(self):
        findings = scan_text('api_key = "sup3rDup3rS3cr3tApiK3yValue12345"\n', "app.py")
        annotations = findings_to_github_annotations(findings)
        assert annotations.startswith("::error file=app.py,line=1,col=")
        assert "::" in annotations


def test_compute_fingerprint_differs_by_file_and_rule():
    fp1 = compute_fingerprint("rule_a", "file_a.py", "secretvalue")
    fp2 = compute_fingerprint("rule_b", "file_a.py", "secretvalue")
    fp3 = compute_fingerprint("rule_a", "file_b.py", "secretvalue")
    assert len({fp1, fp2, fp3}) == 3
