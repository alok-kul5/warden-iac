"""Every example stack is labelled with `# expect: RULE` comments inside the
block that should be flagged. The scan must match the labels exactly: no
missed findings and no extra ones."""

import re
from pathlib import Path

import pytest

from warden.loader import _locate
from warden.scanner import scan

EXAMPLES = Path(__file__).parent.parent / "examples"
EXPECT = re.compile(r"#\s*expect:\s*([A-Z0-9\-, ]+)")
BLOCK = re.compile(r'^(resource|data)\s+"([^"]+)"\s+"([^"]+)"', re.M)


def labels(stack: Path) -> set[tuple[str, str]]:
    out = set()
    for tf in stack.rglob("*.tf"):
        text = tf.read_text(encoding="utf-8")
        lines = text.splitlines()
        for m in BLOCK.finditer(text):
            kind, rtype, name = m.groups()
            start, end = _locate(text, kind, rtype, name)
            for ln in lines[start - 1:end]:
                hit = EXPECT.search(ln)
                if hit:
                    for rule in hit.group(1).replace(",", " ").split():
                        out.add((rule, f"{rtype}.{name}"))
    return out


@pytest.mark.parametrize("stack", sorted(p.name for p in EXAMPLES.iterdir() if p.is_dir()))
def test_scan_matches_labels(stack):
    res = scan(EXAMPLES / stack)
    got = {(f.rule.id, f.resource) for f in res.findings}
    want = labels(EXAMPLES / stack)
    assert got - want == set(), "unexpected findings"
    assert want - got == set(), "missed findings"


def test_hardened_is_clean():
    assert scan(EXAMPLES / "hardened").findings == []
