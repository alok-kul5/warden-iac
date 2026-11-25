from __future__ import annotations

from dataclasses import dataclass, field

SEVERITIES = ["low", "medium", "high", "critical"]
# GitHub code scanning reads "security-severity" (0-10) to bucket alerts.
SECURITY_SEVERITY = {"low": "3.0", "medium": "5.5", "high": "8.0", "critical": "9.5"}


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    severity: str
    description: str
    fix: str
    cwe: str = ""
    cis: str = ""   # CIS AWS Foundations Benchmark v3.0.0 control, if one exists


@dataclass
class Finding:
    rule: Rule
    resource: str
    file: str
    line: int
    message: str
    path: list[dict] = field(default_factory=list)  # privesc steps, if any

    @property
    def severity(self) -> str:
        return self.rule.severity

    def to_dict(self) -> dict:
        out = {
            "rule": self.rule.id,
            "title": self.rule.title,
            "severity": self.severity,
            "resource": self.resource,
            "file": self.file,
            "line": self.line,
            "message": self.message,
        }
        if self.path:
            out["path"] = self.path
        return out


def at_least(sev: str, floor: str) -> bool:
    return SEVERITIES.index(sev) >= SEVERITIES.index(floor)
