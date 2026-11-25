"""Self-contained HTML report: posture score, findings by severity, CIS mapping,
and an interactive privilege-escalation graph. One file, no network needed."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from importlib.resources import files

import networkx as nx

from . import __version__
from .findings import SEVERITIES
from .iam import ADMIN
from .scanner import Result, all_rules, module_of

WEIGHTS = {"critical": 10, "high": 5, "medium": 2, "low": 1}


def score(res: Result) -> tuple[int, str]:
    penalty = sum(WEIGHTS[f.severity] for f in res.findings)
    s = max(0, round(100 - 100 * penalty / (penalty + 40)))   # smooth: 0 findings = 100
    grade = "A" if s >= 90 else "B" if s >= 75 else "C" if s >= 60 else "D" if s >= 40 else "F"
    return s, grade


def _graph(res: Result) -> dict:
    """Merge every module's escalation graph into one, with layers for layout."""
    big = nx.DiGraph()
    big.add_node("admin", kind="admin", label="admin", module="")
    path_edges: set[tuple[str, str]] = set()
    multi = len(res.graphs) > 1
    for mod, ig in res.graphs.items():
        g = getattr(ig, "graph", None)
        if g is None:
            continue

        def nid(k):
            return "admin" if k == ADMIN else f"{mod}::{k}"

        for a, b, d in g.edges(data=True):
            for k in (a, b):
                if k != ADMIN and nid(k) not in big:
                    n = g.nodes[k]
                    big.add_node(nid(k), kind=n["kind"], label=n["name"], module=mod if multi else "",
                                 address=k, admin=n.get("admin", False))
            big.add_edge(nid(a), nid(b), technique=d["technique"], detail=d["detail"])
    for f in res.findings:
        if not f.path:
            continue
        mod = module_of(f.file)
        hops = [f"{mod}::{s['from']}" for s in f.path]
        last = f.path[-1]["to"]
        hops.append("admin" if last == "admin" else f"{mod}::{last}")
        if hops[-1] != "admin":
            hops.append("admin")
        path_edges |= set(zip(hops, hops[1:]))
    dist = nx.single_source_shortest_path_length(big.reverse(copy=False), "admin")
    far = max(dist.values(), default=0) + 1
    nodes = [{"id": n, **{k: v for k, v in d.items()}, "layer": dist.get(n, far),
              "risky": n in dist and n != "admin"} for n, d in big.nodes(data=True)]
    edges = [{"source": a, "target": b, **d, "onPath": (a, b) in path_edges} for a, b, d in big.edges(data=True)]
    return {"nodes": nodes, "edges": edges}


def render(res: Result) -> str:
    s, grade = score(res)
    rules = {r.id: r for r in all_rules()}
    findings = []
    for f in res.findings:
        mod = module_of(f.file)
        d = f.to_dict()
        d.update(fix=f.rule.fix, description=f.rule.description, cis=f.rule.cis, cwe=f.rule.cwe, module=mod)
        if f.path:
            hops = [f"{mod}::{x['from']}" for x in f.path] + [
                "admin" if f.path[-1]["to"] == "admin" else f"{mod}::{f.path[-1]['to']}"]
            d["hops"] = hops
        findings.append(d)
    by_rule: dict[str, int] = {}
    for f in res.findings:
        by_rule[f.rule.id] = by_rule.get(f.rule.id, 0) + 1
    cis = sorted({r.cis for r in rules.values() if r.cis})
    data = {
        "tool": "warden", "version": __version__, "target": res.target,
        "generated": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        "resources": res.resources, "modules": len(res.graphs),
        "counts": res.counts(), "score": s, "grade": grade,
        "rulesTotal": len(rules), "rulesHit": len(by_rule),
        "cisControls": len(cis),
        "cisFailing": len({rules[r].cis for r in by_rule if rules[r].cis}),
        "findings": findings, "graph": _graph(res),
        "severities": list(reversed(SEVERITIES)),
    }
    template = (files("warden") / "report_template.html").read_text(encoding="utf-8")
    blob = json.dumps(data).replace("</", "<\\/")
    return template.replace("/*__DATA__*/null", blob)
