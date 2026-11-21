"""CLI integration tests for Compose Scout."""

import os
import json
from compose_scout.cli import main, run_audit


def test_cli_audit_insecure_file():
    insecure_path = os.path.join(os.path.dirname(__file__), "..", "fixtures", "insecure_compose.yaml")
    report = run_audit(insecure_path)
    assert report.services_scanned == 2
    assert len(report.findings) > 0
    assert report.has_errors is True


def test_cli_strict_exit_code():
    insecure_path = os.path.join(os.path.dirname(__file__), "..", "fixtures", "insecure_compose.yaml")
    # Strict mode should exit with code 1 due to Critical/High findings
    code = main(["audit", insecure_path, "--strict", "--format", "json"])
    assert code == 1


def test_cli_json_export_format(capsys):
    hardened_path = os.path.join(os.path.dirname(__file__), "..", "fixtures", "hardened_compose.yaml")
    code = main(["audit", hardened_path, "--format", "json"])
    assert code == 0
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert "file_path" in data
    assert "findings" in data
