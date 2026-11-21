"""Security audit rules engine for Docker Compose configurations."""

import re
from typing import List, Dict, Any
from compose_scout.models import Finding, Severity

SENSITIVE_PORTS = {
    5432: "PostgreSQL",
    3306: "MySQL/MariaDB",
    6379: "Redis",
    27017: "MongoDB",
    9200: "Elasticsearch",
    2375: "Docker Daemon (Unencrypted)",
    2376: "Docker Daemon (TLS)",
    8500: "Consul",
    2181: "ZooKeeper",
}

SECRET_KEY_PATTERN = re.compile(r".*(PASSWORD|SECRET|KEY|TOKEN|CREDENTIAL|PRIVATE).*", re.IGNORECASE)


def check_privileged_containers(service_name: str, config: Dict[str, Any]) -> List[Finding]:
    findings = []
    if config.get("privileged") is True:
        findings.append(
            Finding(
                rule_id="CS-002",
                service_name=service_name,
                title="Privileged Container Flag Enabled",
                description="Container is configured with 'privileged: true', disabling isolation and granting full host root capabilities.",
                severity=Severity.CRITICAL,
                remediation="Remove 'privileged: true' and grant only specifically required capabilities using 'cap_add'.",
            )
        )
    return findings


def check_host_namespaces(service_name: str, config: Dict[str, Any]) -> List[Finding]:
    findings = []
    for mode_key, severity in [("network_mode", Severity.HIGH), ("pid", Severity.HIGH), ("ipc", Severity.HIGH)]:
        val = str(config.get(mode_key, "")).lower()
        if val == "host":
            findings.append(
                Finding(
                    rule_id="CS-004",
                    service_name=service_name,
                    title=f"Host Namespace Sharing ({mode_key}: host)",
                    description=f"Service shares the host's {mode_key} namespace, eliminating process and network isolation.",
                    severity=severity,
                    remediation=f"Remove '{mode_key}: host' and use custom bridge networks or isolated namespaces.",
                )
            )
    return findings


def check_capabilities(service_name: str, config: Dict[str, Any]) -> List[Finding]:
    findings = []
    caps = config.get("cap_add", [])
    if isinstance(caps, list):
        for cap in caps:
            cap_str = str(cap).upper()
            if cap_str == "ALL" or cap_str == "CAP_SYS_ADMIN" or cap_str == "SYS_ADMIN":
                findings.append(
                    Finding(
                        rule_id="CS-003",
                        service_name=service_name,
                        title=f"Excessive Capability Granted: {cap_str}",
                        description=f"Capability '{cap_str}' gives extensive control over the host kernel or all capabilities.",
                        severity=Severity.CRITICAL if cap_str == "ALL" else Severity.HIGH,
                        remediation="Drop all capabilities ('cap_drop: [ALL]') and explicitly add only minimal necessary capabilities.",
                    )
                )
    return findings


def check_socket_mounts(service_name: str, config: Dict[str, Any]) -> List[Finding]:
    findings = []
    volumes = config.get("volumes", [])
    if isinstance(volumes, list):
        for vol in volumes:
            vol_str = ""
            if isinstance(vol, str):
                vol_str = vol
            elif isinstance(vol, dict):
                vol_str = f"{vol.get('source', '')}:{vol.get('target', '')}"

            if "/var/run/docker.sock" in vol_str or "docker.sock" in vol_str:
                findings.append(
                    Finding(
                        rule_id="CS-005",
                        service_name=service_name,
                        title="Docker Daemon Socket Mounted",
                        description="Mounting the Docker daemon socket inside a container allows full root-equivalent host takeover.",
                        severity=Severity.CRITICAL,
                        remediation="Do not expose 'docker.sock'. Use Docker-in-Docker sidecars or dedicated API proxies with scoped permissions.",
                    )
                )
    return findings


def check_exposed_ports(service_name: str, config: Dict[str, Any]) -> List[Finding]:
    findings = []
    ports = config.get("ports", [])
    if isinstance(ports, list):
        for p in ports:
            p_str = str(p)
            # Match formats: "5432:5432", "0.0.0.0:5432:5432", "5432"
            parts = p_str.split(":")
            host_port = None
            bind_ip = "0.0.0.0"

            if len(parts) == 1:
                if parts[0].isdigit():
                    host_port = int(parts[0])
            elif len(parts) == 2:
                if parts[0].isdigit():
                    host_port = int(parts[0])
            elif len(parts) == 3:
                bind_ip = parts[0]
                if parts[1].isdigit():
                    host_port = int(parts[1])

            if host_port in SENSITIVE_PORTS and (bind_ip == "0.0.0.0" or bind_ip == "" or not bind_ip):
                db_name = SENSITIVE_PORTS[host_port]
                findings.append(
                    Finding(
                        rule_id="CS-001",
                        service_name=service_name,
                        title=f"Publicly Bound Sensitive Port ({host_port} - {db_name})",
                        description=f"Port {host_port} ({db_name}) is published to all interfaces (0.0.0.0) without restriction.",
                        severity=Severity.HIGH,
                        remediation=f"Bind exclusively to loopback (127.0.0.1:{host_port}:{host_port}) or rely entirely on Docker internal networks without publishing.",
                    )
                )
    return findings


def check_root_user(service_name: str, config: Dict[str, Any]) -> List[Finding]:
    findings = []
    user = config.get("user")
    if not user or str(user).strip() in ("0", "root", "0:0"):
        findings.append(
            Finding(
                rule_id="CS-006",
                service_name=service_name,
                title="Service Runs as Root",
                description="No unprivileged user is defined for this service, causing processes to run as root by default.",
                severity=Severity.MEDIUM,
                remediation="Specify a non-root user via 'user: 10001:10001' or configure a non-root USER directive in the Dockerfile.",
            )
        )
    return findings


def check_resource_limits(service_name: str, config: Dict[str, Any]) -> List[Finding]:
    findings = []
    deploy = config.get("deploy", {})
    resources = deploy.get("resources", {}) if isinstance(deploy, dict) else {}
    limits = resources.get("limits", {}) if isinstance(resources, dict) else {}

    has_mem = "memory" in limits or "mem_limit" in config
    has_cpu = "cpus" in limits or "cpus" in config or "cpu_quota" in config

    if not has_mem or not has_cpu:
        findings.append(
            Finding(
                rule_id="CS-007",
                service_name=service_name,
                title="Missing CPU or Memory Limits",
                description="Service does not declare memory or CPU resource constraints, leaving the host vulnerable to resource exhaustion / DoS.",
                severity=Severity.LOW,
                remediation="Configure 'deploy.resources.limits.memory' (e.g., 512M) and 'cpus' (e.g., '1.0').",
            )
        )
    return findings


def check_hardcoded_secrets(service_name: str, config: Dict[str, Any]) -> List[Finding]:
    findings = []
    env = config.get("environment")
    pairs = {}

    if isinstance(env, dict):
        pairs = env
    elif isinstance(env, list):
        for item in env:
            if isinstance(item, str) and "=" in item:
                k, v = item.split("=", 1)
                pairs[k] = v

    for key, val in pairs.items():
        if val is None:
            continue
        val_str = str(val).strip()
        if SECRET_KEY_PATTERN.match(key):
            # Check if value is a literal rather than an env reference like ${SECRET}
            if val_str and not val_str.startswith("${") and len(val_str) > 3:
                findings.append(
                    Finding(
                        rule_id="CS-008",
                        service_name=service_name,
                        title=f"Potential Hardcoded Secret in Environment: {key}",
                        description=f"Key '{key}' appears to contain an inline plaintext credential instead of an environment variable reference.",
                        severity=Severity.HIGH,
                        remediation=f"Store '{key}' in a secure .env file or secret manager and reference it as '${{{key}}}'.",
                    )
                )
    return findings


def check_read_only_filesystem(service_name: str, config: Dict[str, Any]) -> List[Finding]:
    findings = []
    if not config.get("read_only"):
        findings.append(
            Finding(
                rule_id="CS-009",
                service_name=service_name,
                title="Root Filesystem Not Read-Only",
                description="Container root filesystem is writable, allowing persistence or file tampering during an intrusion.",
                severity=Severity.LOW,
                remediation="Enable 'read_only: true' and mount writable directories explicitly via tmpfs or volumes.",
            )
        )
    return findings


ALL_RULES = [
    check_privileged_containers,
    check_host_namespaces,
    check_capabilities,
    check_socket_mounts,
    check_exposed_ports,
    check_root_user,
    check_resource_limits,
    check_hardcoded_secrets,
    check_read_only_filesystem,
]


def audit_services(services: Dict[str, Any], path: str) -> List[Finding]:
    """Runs all security audit checks across every defined service in the compose file."""
    all_findings: List[Finding] = []
    for svc_name, svc_conf in services.items():
        if not isinstance(svc_conf, dict):
            continue
        for rule_fn in ALL_RULES:
            findings = rule_fn(svc_name, svc_conf)
            all_findings.extend(findings)
    return all_findings
