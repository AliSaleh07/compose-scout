"""Formatting and export utilities for Compose Scout audit reports."""

import json
from datetime import datetime, timezone
from typing import Dict, Any
from compose_scout.models import AuditReport, Severity

# ANSI Colors
COLOR_RED = "\033[91m"
COLOR_YELLOW = "\033[93m"
COLOR_BLUE = "\033[94m"
COLOR_CYAN = "\033[96m"
COLOR_GRAY = "\033[90m"
COLOR_GREEN = "\033[92m"
COLOR_BOLD = "\033[1m"
COLOR_RESET = "\033[0m"

SEVERITY_COLORS = {
    Severity.CRITICAL: COLOR_RED,
    Severity.HIGH: COLOR_RED,
    Severity.MEDIUM: COLOR_YELLOW,
    Severity.LOW: COLOR_BLUE,
    Severity.INFO: COLOR_CYAN,
}


def format_terminal(report: AuditReport, use_color: bool = True) -> str:
    lines = []
    c_bold = COLOR_BOLD if use_color else ""
    c_reset = COLOR_RESET if use_color else ""
    c_green = COLOR_GREEN if use_color else ""
    c_gray = COLOR_GRAY if use_color else ""

    lines.append(f"{c_bold}Compose Scout Security Audit Report{c_reset}")
    lines.append(f"{c_gray}Target:{c_reset} {report.file_path}")
    lines.append(f"{c_gray}Services Scanned:{c_reset} {report.services_scanned}")
    lines.append(f"{c_gray}Timestamp:{c_reset} {report.scan_timestamp}\n")

    if not report.findings:
        lines.append(f"{c_green}[✓] No security misconfigurations identified! Clean configuration.{c_reset}\n")
        return "\n".join(lines)

    lines.append(f"{c_bold}Identified Findings ({len(report.findings)} total):{c_reset}")
    lines.append("-" * 75)

    for i, finding in enumerate(report.findings, 1):
        color = SEVERITY_COLORS.get(finding.severity, "") if use_color else ""
        lines.append(
            f"{i}. [{color}{finding.severity.value}{c_reset}] {c_bold}{finding.rule_id}: {finding.title}{c_reset}"
        )
        lines.append(f"   Service:     {finding.service_name}")
        lines.append(f"   Description: {finding.description}")
        lines.append(f"   Remediation: {finding.remediation}")
        lines.append("")

    counts = report.count_by_severity
    lines.append("-" * 75)
    lines.append(f"{c_bold}Summary:{c_reset} " + " | ".join(f"{k}: {v}" for k, v in counts.items()))
    lines.append("")
    return "\n".join(lines)


def format_json(report: AuditReport) -> str:
    data = {
        "file_path": report.file_path,
        "services_scanned": report.services_scanned,
        "scan_timestamp": report.scan_timestamp,
        "total_findings": len(report.findings),
        "summary": report.count_by_severity,
        "findings": [
            {
                "rule_id": f.rule_id,
                "service": f.service_name,
                "title": f.title,
                "description": f.description,
                "severity": f.severity.value,
                "remediation": f.remediation,
            }
            for f in report.findings
        ],
    }
    return json.dumps(data, indent=2)


def format_markdown(report: AuditReport) -> str:
    lines = [
        f"# Compose Scout Security Audit",
        f"- **File:** `{report.file_path}`",
        f"- **Services Audited:** {report.services_scanned}",
        f"- **Findings:** {len(report.findings)}",
        f"- **Scan Date:** {report.scan_timestamp}",
        "",
        "## Severity Breakdown",
        "| Severity | Count |",
        "|---|---|",
    ]
    for sev, count in report.count_by_severity.items():
        lines.append(f"| {sev} | {count} |")

    lines.append("")
    if not report.findings:
        lines.append("✅ **No security misconfigurations found!**")
        return "\n".join(lines)

    lines.append("## Detailed Findings")
    lines.append("| ID | Severity | Service | Issue | Remediation |")
    lines.append("|---|---|---|---|---|")
    for f in report.findings:
        lines.append(f"| {f.rule_id} | `{f.severity.value}` | `{f.service_name}` | {f.title} | {f.remediation} |")

    return "\n".join(lines)
