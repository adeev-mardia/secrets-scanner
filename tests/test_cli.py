import json
import subprocess
import sys
from pathlib import Path

FIXTURES = Path(__file__).parent / "fixtures"


def run_cli(*args):
    return subprocess.run(
        [sys.executable, "-m", "secrets_scanner.cli", *args],
        capture_output=True,
        text=True,
    )


def test_cli_exits_1_on_findings():
    result = run_cli("scan", str(FIXTURES / "secrets_positive.txt"))
    assert result.returncode == 1
    assert "finding(s)" in result.stdout


def test_cli_exits_0_on_clean_file():
    result = run_cli("scan", str(FIXTURES / "secrets_clean.txt"))
    assert result.returncode == 0
    assert "No secrets found." in result.stdout


def test_cli_json_output_is_parseable():
    result = run_cli("scan", str(FIXTURES / "secrets_positive.txt"), "--format", "json")
    assert result.returncode == 1
    data = json.loads(result.stdout)
    assert isinstance(data, list)
    assert len(data) > 0


def test_cli_min_severity_filters_findings():
    all_result = run_cli("scan", str(FIXTURES / "secrets_positive.txt"), "--format", "json")
    all_findings = json.loads(all_result.stdout)

    critical_result = run_cli(
        "scan", str(FIXTURES / "secrets_positive.txt"), "--format", "json", "--min-severity", "critical"
    )
    critical_findings = json.loads(critical_result.stdout)

    assert len(critical_findings) <= len(all_findings)
    assert all(f["severity"] == "critical" for f in critical_findings)
