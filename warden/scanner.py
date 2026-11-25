from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from . import iam, rules
from .findings import SEVERITIES, Finding, Rule
from .loader import load


@dataclass
class Result:
    target: str
    resources: int
    findings: list[Finding]
    graph: iam.IAMGraph

    def counts(self) -> dict[str, int]:
        c = {s: 0 for s in SEVERITIES}
        for f in self.findings:
            c[f.severity] += 1
        return c


def all_rules() -> list[Rule]:
    return [meta for meta, _, _ in rules.RULES.values()] + iam.ALL_RULES


def scan(target: str | Path) -> Result:
    resources = load(target)
    stack = rules.Stack(resources)
    findings = rules.run(stack)
    iam_findings, graph = iam.analyze(stack)
    findings += iam_findings
    order = {s: i for i, s in enumerate(reversed(SEVERITIES))}
    findings.sort(key=lambda f: (order[f.severity], f.file, f.line, f.rule.id))
    return Result(str(target), len(resources), findings, graph)
