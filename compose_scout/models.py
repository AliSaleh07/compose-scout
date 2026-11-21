"""Data models and severity classifications for Compose Scout."""

from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional, Dict, Any


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass
class Finding:
    rule_id: str
    service_name: str
    title: str
    description: str
    severity: Severity
    remediation: str
    line_hint: Optional[str] = None


@dataclass
class AuditReport:
    file_path: str
    services_scanned: int
    findings: List[Finding] = field(default_factory=list)
    scan_timestamp: str = ""

    @property
    def has_errors(self) -> bool:
        return any(f.severity in (Severity.CRITICAL, Severity.HIGH) for f in self.findings)

    @property
    def count_by_severity(self) -> Dict[str, int]:
        counts = {s.value: 0 for s in Severity}
        for f in self.findings:
            counts[f.severity.value] += 1
        return counts
