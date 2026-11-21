"""Unit tests for Compose Scout rule detection engine."""

import pytest
from compose_scout.models import Severity
from compose_scout.rules import (
    check_privileged_containers,
    check_host_namespaces,
    check_capabilities,
    check_socket_mounts,
    check_exposed_ports,
    check_root_user,
    check_resource_limits,
    check_hardcoded_secrets,
)


def test_privileged_container_flag():
    svc = {"privileged": True}
    findings = check_privileged_containers("web", svc)
    assert len(findings) == 1
    assert findings[0].rule_id == "CS-002"
    assert findings[0].severity == Severity.CRITICAL


def test_host_namespace_sharing():
    svc = {"network_mode": "host", "pid": "host"}
    findings = check_host_namespaces("web", svc)
    assert len(findings) == 2
    assert all(f.rule_id == "CS-004" for f in findings)


def test_excessive_capabilities():
    svc = {"cap_add": ["ALL", "SYS_ADMIN"]}
    findings = check_capabilities("backend", svc)
    assert len(findings) == 2
    rule_ids = [f.rule_id for f in findings]
    assert rule_ids == ["CS-003", "CS-003"]


def test_docker_socket_mount():
    svc = {"volumes": ["/var/run/docker.sock:/var/run/docker.sock"]}
    findings = check_socket_mounts("deployer", svc)
    assert len(findings) == 1
    assert findings[0].rule_id == "CS-005"
    assert findings[0].severity == Severity.CRITICAL


def test_exposed_sensitive_ports():
    svc = {"ports": ["5432:5432", "127.0.0.1:6379:6379", "3306"]}
    findings = check_exposed_ports("db", svc)
    # 5432:5432 is 0.0.0.0 bound -> should trigger
    # 127.0.0.1:6379:6379 is loopback -> should NOT trigger
    # 3306 is 0.0.0.0 bound -> should trigger
    assert len(findings) == 2
    rule_ids = [f.rule_id for f in findings]
    assert all(r == "CS-001" for r in rule_ids)


def test_hardcoded_secrets_detection():
    svc = {
        "environment": {
            "DB_PASSWORD": "plaintext_super_secret_value",
            "APP_ENV": "production",
            "API_TOKEN": "${API_TOKEN}",  # Safe env reference
        }
    }
    findings = check_hardcoded_secrets("api", svc)
    assert len(findings) == 1
    assert findings[0].rule_id == "CS-008"
    assert "DB_PASSWORD" in findings[0].title
