import json
from pathlib import Path

from warden import hclexpr, report
from warden.cli import main
from warden.scanner import scan

EXAMPLES = Path(__file__).parent.parent / "examples"


def test_jsonencode_expression():
    val = hclexpr.parse('{Version = "2012-10-17", Statement = [{Effect = "Allow", '
                        'Action = ["s3:*"], Resource = aws_s3_bucket.b.arn, N = 3, B = true}]}')
    st = val["Statement"][0]
    assert st["Action"] == ["s3:*"]
    assert st["Resource"] == "${aws_s3_bucket.b.arn}"
    assert st["N"] == 3 and st["B"] is True


def test_function_calls_and_interpolation_are_kept_as_refs():
    val = hclexpr.parse('{R = "${aws_s3_bucket.b.arn}/*", L = concat(var.a, ["x"])}')
    assert val["R"] == "${aws_s3_bucket.b.arn}/*"
    assert val["L"].startswith("${concat(")


def test_sarif_is_valid_shape():
    doc = json.loads(report.sarif(scan(EXAMPLES / "startup-stack")))
    run = doc["runs"][0]
    ids = {r["id"] for r in run["tool"]["driver"]["rules"]}
    assert doc["version"] == "2.1.0"
    assert run["results"] and all(r["ruleId"] in ids for r in run["results"])
    for r in run["tool"]["driver"]["rules"]:
        assert 0 < float(r["properties"]["security-severity"]) <= 10
    loc = run["results"][0]["locations"][0]["physicalLocation"]
    assert loc["artifactLocation"]["uri"].endswith(".tf") and loc["region"]["startLine"] > 0


def test_sarif_privesc_has_code_flow():
    doc = json.loads(report.sarif(scan(EXAMPLES / "iam-escalation")))
    flows = [r for r in doc["runs"][0]["results"] if r["ruleId"] == "WDN-IAM-001"]
    assert flows and all("codeFlows" in r for r in flows)


def test_exit_codes(tmp_path):
    out = str(tmp_path / "x.txt")
    assert main(["scan", str(EXAMPLES / "hardened"), "-o", out]) == 0
    assert main(["scan", str(EXAMPLES / "startup-stack"), "-o", out]) == 1
    assert main(["scan", str(EXAMPLES / "startup-stack"), "--fail-on", "none", "-o", out]) == 0
    assert main(["scan", str(tmp_path / "missing")]) == 2


def test_mermaid_graph_mentions_admin():
    assert '(["admin"])' in report.mermaid(scan(EXAMPLES / "iam-escalation"))
