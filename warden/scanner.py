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
    graphs: dict[str, iam.IAMGraph]   # one per Terraform module (directory)

    def counts(self) -> dict[str, int]:
        c = {s: 0 for s in SEVERITIES}
        for f in self.findings:
            c[f.severity] += 1
        return c


def all_rules() -> list[Rule]:
    return [meta for meta, _, _ in rules.RULES.values()] + iam.ALL_RULES


def module_of(file: str) -> str:
    return file.rsplit("/", 1)[0] if "/" in file else "."


def scan(target: str | Path) -> Result:
    """Scan every Terraform module under target. Each directory is its own module,
    as in Terraform, so names in one module never resolve against another."""
    resources = load(target)
    modules: dict[str, list] = {}
    for r in resources:
        modules.setdefault(module_of(r.file), []).append(r)
    findings: list[Finding] = []
    graphs: dict[str, iam.IAMGraph] = {}
    for mod, res in sorted(modules.items()):
        stack = rules.Stack(res)
        findings += rules.run(stack)
        iam_findings, graphs[mod] = iam.analyze(stack)
        findings += iam_findings
    order = {s: i for i, s in enumerate(reversed(SEVERITIES))}
    findings.sort(key=lambda f: (order[f.severity], f.file, f.line, f.rule.id))
    return Result(str(target), len(resources), findings, graphs)
