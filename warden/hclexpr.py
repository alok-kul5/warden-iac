"""Tiny parser for the HCL expression subset found inside jsonencode(...).

python-hcl2 hands back the body of a jsonencode() call as raw HCL text. Policies
written this way are the most common style in real Terraform, so we turn that
text into plain Python data. Anything we can't evaluate (a reference such as
aws_iam_role.app.arn, or a function call) is kept as an "${...}" string, the same
shape python-hcl2 uses for references elsewhere.
"""

from __future__ import annotations

import re

_PUNCT = set("{}[](),=:")
_TRAVERSAL = re.compile(r"[A-Za-z_][A-Za-z0-9_\-]*(?:\.[A-Za-z0-9_\-*]+|\[[^\]]*\])*")
_NUMBER = re.compile(r"-?\d+(?:\.\d+)?")


class ParseError(ValueError):
    pass


def _tokens(text: str):
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        if c.isspace():
            i += 1
        elif c == "#" or text.startswith("//", i):
            while i < n and text[i] != "\n":
                i += 1
        elif c == '"':
            j, depth, buf = i + 1, 0, []
            while j < n:
                ch = text[j]
                if ch == "\\" and j + 1 < n:
                    nxt = text[j + 1]
                    buf.append({"n": "\n", "t": "\t", '"': '"', "\\": "\\"}.get(nxt, "\\" + nxt))
                    j += 2
                    continue
                if text.startswith("${", j):
                    depth += 1
                elif ch == "}" and depth:
                    depth -= 1
                elif ch == '"' and not depth:
                    break
                buf.append(ch)
                j += 1
            else:
                raise ParseError("unterminated string")
            yield ("str", "".join(buf))
            i = j + 1
        elif c in _PUNCT:
            yield ("p", c)
            i += 1
        else:
            m = _NUMBER.match(text, i)
            if m and (m.end() == n or not (text[m.end()].isalnum() or text[m.end()] == "_")):
                s = m.group()
                yield ("num", float(s) if "." in s else int(s))
                i = m.end()
                continue
            m = _TRAVERSAL.match(text, i)
            if not m:
                raise ParseError(f"unexpected character {c!r}")
            yield ("id", m.group())
            i = m.end()


class _Parser:
    def __init__(self, text: str):
        self.toks = list(_tokens(text))
        self.pos = 0

    def peek(self):
        return self.toks[self.pos] if self.pos < len(self.toks) else ("eof", None)

    def take(self):
        tok = self.peek()
        self.pos += 1
        return tok

    def expect(self, value):
        tok = self.take()
        if tok != ("p", value):
            raise ParseError(f"expected {value!r}, got {tok[1]!r}")

    def value(self):
        kind, val = self.take()
        if kind == "p" and val == "{":
            return self.obj()
        if kind == "p" and val == "[":
            return self.lst()
        if kind in ("str", "num"):
            return val
        if kind == "id":
            if val == "true":
                return True
            if val == "false":
                return False
            if val == "null":
                return None
            if self.peek() == ("p", "("):
                return "${" + val + "(" + self.raw_call() + ")}"
            return "${" + val + "}"
        raise ParseError(f"unexpected token {val!r}")

    def raw_call(self) -> str:
        # Skip a function call's arguments; we keep only a marker for it.
        self.expect("(")
        depth, parts = 1, []
        while depth:
            kind, val = self.take()
            if kind == "eof":
                raise ParseError("unterminated call")
            if (kind, val) == ("p", "("):
                depth += 1
            elif (kind, val) == ("p", ")"):
                depth -= 1
                if not depth:
                    break
            parts.append(f'"{val}"' if kind == "str" else str(val))
        return " ".join(parts)

    def obj(self):
        out = {}
        while True:
            if self.peek() == ("p", "}"):
                self.take()
                return out
            kind, key = self.take()
            if kind not in ("id", "str"):
                raise ParseError(f"bad object key {key!r}")
            sep = self.take()
            if sep not in (("p", "="), ("p", ":")):
                raise ParseError("expected = or :")
            out[str(key)] = self.value()
            if self.peek() == ("p", ","):
                self.take()

    def lst(self):
        out = []
        while True:
            if self.peek() == ("p", "]"):
                self.take()
                return out
            out.append(self.value())
            if self.peek() == ("p", ","):
                self.take()


def parse(text: str):
    """Parse one HCL value expression into Python data."""
    p = _Parser(text)
    val = p.value()
    if p.peek()[0] != "eof":
        raise ParseError("trailing input")
    return val
