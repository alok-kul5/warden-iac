"""Output formats: terminal text, JSON, SARIF 2.1.0, Markdown and a Mermaid graph."""

from __future__ import annotations

import json
import os

from . import __version__
from .findings import SECURITY_SEVERITY, SEVERITIES
from .iam import ADMIN
from .scanner import Result, all_rules

COLORS = {"critical": "\033[1;31m", "high": "\033[31m", "medium": "\033[33m", "low": "\033[36m"}
RESET = "\033[0m"


def text(res: Result, color: bool = True) -> str:
    def c(sev, s):
        return f"{COLORS[sev]}{s}{RESET}" if color else s

    lines = [f"warden {__version__}  scanned {res.resources} resources in {res.target}", ""]
    for f in res.findings:
        lines.append(f"{c(f.severity, f.severity.upper().ljust(8))} {f.rule.id}  {f.rule.title}")
        lines.append(f"         {f.resource}  ({f.file}:{f.line})")
        if f.path:
            lines.append(f"         {f.path[0]['from']}")
            for step in f.path:
                lines.append(f"           └─ {step['technique']} → {step['to']}")
        else:
            lines.append(f"         {f.message}")
        lines.append(f"         fix: {f.rule.fix}")
        lines.append("")
    counts = res.counts()
    summary = ", ".join(f"{counts[s]} {s}" for s in reversed(SEVERITIES) if counts[s])
    lines.append(f"{len(res.findings)} findings" + (f" ({summary})" if summary else ""))
    return "\n".join(lines)


def as_json(res: Result) -> str:
    return json.dumps({"tool": "warden", "version": __version__, "target": res.target,
                       "resources": res.resources, "counts": res.counts(),
                       "findings": [f.to_dict() for f in res.findings]}, indent=2)


def sarif(res: Result, base: str = "") -> str:
    rules = all_rules()
    index = {r.id: i for i, r in enumerate(rules)}
    level = {"critical": "error", "high": "error", "medium": "warning", "low": "note"}

    def uri(path):
        return (os.path.join(base, path) if base else path).replace("\\", "/")

    results = []
    for f in res.findings:
        result = {
            "ruleId": f.rule.id,
            "ruleIndex": index[f.rule.id],
            "level": level[f.severity],
            "message": {"text": f"{f.resource}: {f.message}"},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": uri(f.file)},
                "region": {"startLine": f.line}}}],
            "partialFingerprints": {"resource/v1": f"{f.rule.id}:{f.file}:{f.resource}"},
        }
        if f.path:
            result["codeFlows"] = [{"threadFlows": [{"locations": [
                {"location": {"message": {"text": f"{s['from']} --{s['technique']}--> {s['to']}"},
                              "physicalLocation": {"artifactLocation": {"uri": uri(f.file)},
                                                   "region": {"startLine": f.line}}}}
                for s in f.path]}]}]
        results.append(result)
    doc = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "warden",
                "version": __version__,
                "informationUri": "https://github.com/alok-kul5/warden-iac",
                "rules": [{
                    "id": r.id,
                    "name": "".join(w.capitalize() for w in r.title.replace("-", " ").split()[:6]),
                    "shortDescription": {"text": r.title},
                    "fullDescription": {"text": r.description},
                    "help": {"text": r.fix, "markdown": f"**Fix:** {r.fix}"},
                    "defaultConfiguration": {"level": level[r.severity]},
                    "properties": {"security-severity": SECURITY_SEVERITY[r.severity],
                                   "tags": ["security", "terraform", "aws"] + ([r.cwe] if r.cwe else [])},
                } for r in rules],
            }},
            "results": results,
        }],
    }
    return json.dumps(doc, indent=2)


def markdown(res: Result) -> str:
    counts = res.counts()
    out = [f"### warden: {len(res.findings)} findings in `{res.target}`", "",
           " · ".join(f"**{counts[s]}** {s}" for s in reversed(SEVERITIES)), "",
           "| Severity | Rule | Resource | Detail |", "|---|---|---|---|"]
    for f in res.findings:
        out.append(f"| {f.severity} | `{f.rule.id}` {f.rule.title} | `{f.resource}` "
                   f"[{f.file}:{f.line}] | {f.message.replace('|', '/')} |")
    return "\n".join(out)


def mermaid(res: Result) -> str:
    """Escalation paths as a Mermaid flowchart (renders on GitHub)."""
    from .scanner import module_of
    out = ["flowchart LR"]
    ids: dict[tuple[str, str], str] = {}
    prefix = len(res.graphs) > 1

    def node(mod, key):
        k = ("", "admin") if key in ("admin", ADMIN) else (mod, key)
        if k not in ids:
            ids[k] = f"n{len(ids)}"
            if k[1] == "admin":
                out.append(f'    {ids[k]}(["admin"])')
            else:
                p = res.graphs[mod].principals.get(key)
                label = f"{p.kind}: {p.name}" if p else key
                if prefix:
                    label = f"{mod}/ {label}"
                out.append(f'    {ids[k]}["{label}"]')
        return ids[k]

    edges = set()
    for f in res.findings:
        mod = module_of(f.file)
        for s in f.path:
            a, b = node(mod, s["from"]), node(mod, s["to"])
            edges.add((a, s["technique"], b))
            if s is f.path[-1] and s["to"] != "admin":
                edges.add((b, "is admin", node(mod, "admin")))
    for a, t, b in sorted(edges):
        out.append(f"    {a} -- {t} --> {b}")
    if ("", "admin") in ids:
        out.append(f"    style {ids[('', 'admin')]} fill:#b42318,color:#fff,stroke:#b42318")
    return "\n".join(out)
