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


def test_secrets_in_nested_blocks_and_providers(tmp_path):
    key_id = "AKIA" + "Z" * 16  # built at runtime so no key-shaped string sits in the repo
    (tmp_path / "main.tf").write_text(f'''
provider "aws" {{
  region     = "us-east-1"
  secret_key = "not-a-real-secret"
}}

resource "aws_lambda_function" "f" {{
  function_name = "f"
  role          = "arn:aws:iam::123456789012:role/f"
  environment {{
    variables = {{
      DB_PASSWORD = "hunter2"
    }}
  }}
}}

resource "aws_instance" "i" {{
  ami       = "ami-1"
  user_data = "export AWS_ACCESS_KEY_ID={key_id}"
  metadata_options {{
    http_tokens = "required"
  }}
  root_block_device {{
    encrypted = true
  }}
}}
''', encoding="utf-8")
    hits = {(f.resource, f.message) for f in scan(tmp_path).findings if f.rule.id == "WDN-SECRET-001"}
    assert ("provider.aws", "secret_key is set to a literal value") in hits
    assert ("aws_lambda_function.f", "environment.variables.DB_PASSWORD is set to a literal value") in hits
    assert ("aws_instance.i", "user_data contains an AWS access key") in hits


def test_variable_references_are_not_secrets(tmp_path):
    (tmp_path / "main.tf").write_text('''
resource "aws_db_instance" "d" {
  identifier          = "d"
  password            = var.db_password
  storage_encrypted   = true
}
''', encoding="utf-8")
    assert not [f for f in scan(tmp_path).findings if f.rule.id == "WDN-SECRET-001"]


def test_public_queue_policy_and_lambda_permission(tmp_path):
    (tmp_path / "main.tf").write_text('''
resource "aws_sqs_queue_policy" "q" {
  queue_url = "https://sqs/q"
  policy = jsonencode({ Statement = [{ Effect = "Allow", Principal = "*", Action = "sqs:SendMessage", Resource = "*" }] })
}

resource "aws_lambda_permission" "p" {
  statement_id  = "any"
  action        = "lambda:InvokeFunction"
  function_name = "f"
  principal     = "*"
}
''', encoding="utf-8")
    hits = {f.resource for f in scan(tmp_path).findings if f.rule.id == "WDN-POL-001"}
    assert hits == {"aws_sqs_queue_policy.q", "aws_lambda_permission.p"}


def test_each_directory_is_its_own_module():
    # hardened/ has a public access block for a bucket also named "uploads";
    # it must not cover startup-stack's bucket when both are scanned together.
    together = {(f.rule.id, f.file) for f in scan(EXAMPLES).findings}
    alone = {(f.rule.id, "startup-stack/" + f.file) for f in scan(EXAMPLES / "startup-stack").findings}
    assert alone <= together
    assert len(scan(EXAMPLES).findings) == sum(len(scan(EXAMPLES / d).findings)
                                               for d in ("startup-stack", "iam-escalation", "hardened"))
