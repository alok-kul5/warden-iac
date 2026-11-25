"""Load Terraform files into a flat list of resources with clean Python values."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

import hcl2

from . import hclexpr

_IGNORE = re.compile(r"warden:ignore\s+([A-Z0-9_\-, ]+)")
_HEREDOC = re.compile(r"^<<-?([A-Za-z_]+)\n(.*)\n\s*\1$", re.S)


@dataclass
class Resource:
    kind: str          # "resource" or "data"
    type: str
    name: str
    body: dict
    file: str
    line: int
    ignored: set[str] = field(default_factory=set)

    @property
    def address(self) -> str:
        if self.kind == "provider":
            return f"provider.{self.type}"
        base = f"{self.type}.{self.name}"
        return base if self.kind == "resource" else f"data.{base}"

    def get(self, key, default=None):
        return self.body.get(key, default)

    def blocks(self, key) -> list[dict]:
        val = self.body.get(key)
        if val is None:
            return []
        return val if isinstance(val, list) else [val]


def _unquote(s: str):
    if len(s) >= 2 and s[0] == '"' and s[-1] == '"':
        inner = s[1:-1]
        m = _HEREDOC.match(inner)
        if m:
            inner = m.group(2)
            try:
                return json.loads(inner)
            except ValueError:
                return inner
        return inner.replace('\\"', '"')
    if s.startswith("${jsonencode(") and s.endswith(")}"):
        try:
            return hclexpr.parse(s[len("${jsonencode("):-2])
        except hclexpr.ParseError:
            return s
    return s


def normalize(val):
    if isinstance(val, dict):
        return {_unquote(k) if isinstance(k, str) else k: normalize(v)
                for k, v in val.items() if k != "__is_block__"}
    if isinstance(val, list):
        return [normalize(v) for v in val]
    if isinstance(val, str):
        out = _unquote(val)
        return normalize(out) if isinstance(out, (dict, list)) else out
    return val


def _locate(text: str, kind: str, rtype: str, name: str) -> tuple[int, int]:
    """Return (start_line, end_line) of a block, 1-based, by scanning the source."""
    if kind == "provider":
        pat = re.compile(rf'^\s*provider\s+"?{re.escape(rtype)}"?\s*\{{', re.M)
    else:
        pat = re.compile(rf'^\s*{kind}\s+"?{re.escape(rtype)}"?\s+"?{re.escape(name)}"?', re.M)
    m = pat.search(text)
    if not m:
        return 1, 1
    start = text.count("\n", 0, m.start()) + 1
    depth, i, seen = 0, m.end() - (1 if kind == "provider" else 0), False
    while i < len(text):
        c = text[i]
        if c == "{":
            depth += 1
            seen = True
        elif c == "}":
            depth -= 1
            if seen and depth == 0:
                break
        i += 1
    return start, text.count("\n", 0, i) + 1


def load_file(path: Path, root: Path | None = None) -> list[Resource]:
    text = path.read_text(encoding="utf-8")
    with path.open(encoding="utf-8") as fh:
        doc = hcl2.load(fh)
    rel = path.relative_to(root).as_posix() if root else path.as_posix()
    lines = text.splitlines()
    out: list[Resource] = []
    for kind in ("resource", "data"):
        for entry in doc.get(kind, []):
            for rtype, named in entry.items():
                rtype = _unquote(rtype)
                for name, body in named.items():
                    name = _unquote(name)
                    start, end = _locate(text, kind, rtype, name)
                    ignored: set[str] = set()
                    for ln in lines[start - 1:end]:
                        m = _IGNORE.search(ln)
                        if m:
                            ignored |= {x.strip() for x in m.group(1).replace(",", " ").split() if x.strip()}
                    out.append(Resource(kind, rtype, name, normalize(body), rel, start, ignored))
    for entry in doc.get("provider", []):
        for ptype, body in entry.items():
            ptype = _unquote(ptype)
            start, _ = _locate(text, "provider", ptype, "")
            out.append(Resource("provider", ptype, "default", normalize(body), rel, start))
    return out


def load(target: str | Path) -> list[Resource]:
    """Load every .tf file under a directory (or a single file)."""
    target = Path(target)
    if target.is_file():
        return load_file(target, target.parent)
    resources: list[Resource] = []
    for path in sorted(target.rglob("*.tf")):
        if ".terraform" in path.parts:
            continue
        resources.extend(load_file(path, target))
    return resources
