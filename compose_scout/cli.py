"""Command-line interface entrypoint for Compose Scout."""

import argparse
import sys
from datetime import datetime, timezone
import os

from compose_scout.models import AuditReport
from compose_scout.parser import load_compose_file, ParseError
from compose_scout.rules import audit_services
from compose_scout.reporter import format_terminal, format_json, format_markdown


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="scout",
        description="Compose Scout: Docker Compose Auditing and Security Hardening CLI.",
    )
    subparsers = parser.add_subparsers(dest="command", help="Available subcommands")

    audit_cmd = subparsers.add_parser("audit", help="Audit a Docker Compose file for security vulnerabilities")
    audit_cmd.add_argument("file", help="Path to Docker Compose YAML file (e.g. docker-compose.yml)")
    audit_cmd.add_argument(
        "--format",
        choices=["text", "json", "markdown"],
        default="text",
        help="Output report format (default: text)",
    )
    audit_cmd.add_argument(
        "--strict",
        action="store_true",
        help="Exit with non-zero status code (1) if any CRITICAL or HIGH findings exist",
    )
    audit_cmd.add_argument(
        "--output",
        "-o",
        help="Write report output to specified file path instead of stdout",
    )
    audit_cmd.add_argument(
        "--no-color",
        action="store_true",
        help="Disable ANSI colors in terminal output",
    )
    return parser


def run_audit(file_path: str) -> AuditReport:
    data, raw_content = load_compose_file(file_path)
    services = data.get("services", {})
    findings = audit_services(services, file_path)
    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    return AuditReport(
        file_path=os.path.abspath(file_path),
        services_scanned=len(services),
        findings=findings,
        scan_timestamp=now_str,
    )


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if not args.command:
        parser.print_help()
        return 0

    if args.command == "audit":
        try:
            report = run_audit(args.file)
        except ParseError as err:
            sys.stderr.write(f"Error: {str(err)}\n")
            return 2

        if args.format == "json":
            output_content = format_json(report)
        elif args.format == "markdown":
            output_content = format_markdown(report)
        else:
            output_content = format_terminal(report, use_color=not args.no_color)

        if args.output:
            try:
                with open(args.output, "w", encoding="utf-8") as f:
                    f.write(output_content + "\n")
                print(f"Report successfully saved to: {args.output}")
            except Exception as e:
                sys.stderr.write(f"Failed to write output to {args.output}: {e}\n")
                return 1
        else:
            print(output_content)

        if args.strict and report.has_errors:
            return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
