"""Terraform misconfiguration rules for AWS.

Each check takes one resource plus the whole stack (some settings, such as an S3
bucket's public access block, live in a separate resource) and yields messages.
"""

from __future__ import annotations

import re
from collections import defaultdict
from typing import Callable, Iterable

from .findings import Finding, Rule
from .loader import Resource

OPEN_CIDRS = {"0.0.0.0/0", "::/0"}
ADMIN_PORTS = {22: "SSH", 3389: "RDP"}
DATA_PORTS = {3306: "MySQL", 5432: "PostgreSQL", 1433: "SQL Server", 1521: "Oracle",
              27017: "MongoDB", 6379: "Redis", 9200: "Elasticsearch", 5601: "Kibana",
              11211: "Memcached", 2379: "etcd"}
SECRET_KEYS = ("password", "secret", "secret_key", "access_key", "token", "api_key", "master_password")


class Stack:
    """All resources in a scan, indexed for cross-resource lookups."""

    def __init__(self, resources: list[Resource]):
        self.resources = resources
        self.by_type: dict[str, list[Resource]] = defaultdict(list)
        for r in resources:
            self.by_type[r.type].append(r)

    def linked(self, rtype: str, attr: str, target: Resource) -> list[Resource]:
        return [r for r in self.by_type.get(rtype, []) if refers_to(r.get(attr), target)]


def refers_to(value, target: Resource) -> bool:
    if isinstance(value, list):
        return any(refers_to(v, target) for v in value)
    if not isinstance(value, str):
        return False
    if f"{target.type}.{target.name}." in value or value.endswith(f"{target.type}.{target.name}}}"):
        return True
    names = {target.get("bucket"), target.get("name"), target.get("identifier")} - {None}
    return value in names


def is_true(v) -> bool:
    return v is True or (isinstance(v, str) and v.lower() == "true")


def is_literal(v) -> bool:
    return isinstance(v, str) and v != "" and "${" not in v


Check = Callable[[Resource, Stack], Iterable[str]]
RULES: dict[str, tuple[Rule, tuple[str, ...], Check]] = {}


def rule(id, title, severity, types, description, fix, cwe=""):
    def wrap(fn: Check):
        RULES[id] = (Rule(id, title, severity, description, fix, cwe), tuple(types), fn)
        return fn
    return wrap


# ---------------------------------------------------------------- S3

@rule("WDN-S3-001", "S3 bucket ACL grants public access", "high",
      ["aws_s3_bucket", "aws_s3_bucket_acl"],
      "A canned ACL of public-read or public-read-write lets anyone on the internet list or write objects.",
      "Remove the public ACL and serve content through CloudFront with origin access control.", "CWE-284")
def s3_public_acl(r, stack):
    acl = r.get("acl")
    if acl in ("public-read", "public-read-write", "authenticated-read"):
        yield f"acl is '{acl}'"


@rule("WDN-S3-002", "S3 bucket has no public access block", "medium", ["aws_s3_bucket"],
      "Without all four public access block settings, a later ACL or bucket policy change can expose the bucket.",
      "Add aws_s3_bucket_public_access_block with all four settings set to true.", "CWE-284")
def s3_no_pab(r, stack):
    blocks = stack.linked("aws_s3_bucket_public_access_block", "bucket", r)
    if not blocks:
        yield "no aws_s3_bucket_public_access_block for this bucket"
        return
    keys = ("block_public_acls", "block_public_policy", "ignore_public_acls", "restrict_public_buckets")
    off = [k for k in keys if not is_true(blocks[0].get(k))]
    if off:
        yield "public access block leaves " + ", ".join(off) + " off"


@rule("WDN-S3-003", "S3 bucket versioning is off", "low", ["aws_s3_bucket"],
      "Without versioning, a deleted or overwritten object (or a ransomware run) cannot be recovered.",
      "Add aws_s3_bucket_versioning with status = \"Enabled\".")
def s3_versioning(r, stack):
    inline = [b for b in r.blocks("versioning") if is_true(b.get("enabled"))]
    linked = [v for v in stack.linked("aws_s3_bucket_versioning", "bucket", r)
              if any(c.get("status") == "Enabled" for c in v.blocks("versioning_configuration"))]
    if not inline and not linked:
        yield "versioning is not enabled"


POLICY_ATTRS = {"aws_s3_bucket_policy": "policy", "aws_sqs_queue_policy": "policy",
                "aws_sns_topic_policy": "policy", "aws_ecr_repository_policy": "policy",
                "aws_elasticsearch_domain_policy": "access_policies",
                "aws_opensearch_domain_policy": "access_policies",
                "aws_elasticsearch_domain": "access_policies", "aws_opensearch_domain": "access_policies",
                "aws_kms_key": "policy", "aws_secretsmanager_secret_policy": "policy"}


@rule("WDN-POL-001", "Resource policy allows any principal", "critical", list(POLICY_ATTRS) + ["aws_lambda_permission"],
      "A resource policy statement with Principal \"*\" and no condition opens the bucket, queue, topic, "
      "key or domain to every AWS account and often to anonymous callers.",
      "Name the principals explicitly, or add a condition such as aws:SourceVpce, aws:SourceArn or aws:PrincipalOrgID.",
      "CWE-284")
def resource_policy_public(r, stack):
    if r.type == "aws_lambda_permission":
        if r.get("principal") == "*" and not r.get("source_arn") and not r.get("principal_org_id"):
            yield "lambda permission grants invoke to principal \"*\""
        return
    from .iam import statements
    for st in statements(r.get(POLICY_ATTRS[r.type]), stack):
        if st.effect == "Allow" and st.principal_is_anyone() and not st.conditions:
            yield f"statement allows {', '.join(st.actions) or 'every action'} to Principal \"*\""
            return


# ---------------------------------------------------------------- network

def _ingress_rules(r: Resource):
    if r.type == "aws_security_group":
        for b in r.blocks("ingress"):
            yield b
    elif r.type == "aws_security_group_rule" and r.get("type") == "ingress":
        yield r.body
    elif r.type == "aws_vpc_security_group_ingress_rule":
        yield {"from_port": r.get("from_port"), "to_port": r.get("to_port"),
               "protocol": r.get("ip_protocol"),
               "cidr_blocks": [c for c in (r.get("cidr_ipv4"), r.get("cidr_ipv6")) if c]}


def _open(b: dict) -> bool:
    cidrs = list(b.get("cidr_blocks") or []) + list(b.get("ipv6_cidr_blocks") or [])
    return any(c in OPEN_CIDRS for c in cidrs)


def _ports(b: dict) -> tuple[int, int] | None:
    if str(b.get("protocol")) in ("-1", "all"):
        return 0, 65535
    try:
        lo, hi = int(b.get("from_port")), int(b.get("to_port"))
    except (TypeError, ValueError):
        return None
    return (0, 65535) if (lo, hi) == (-1, -1) else (lo, hi)


SG_TYPES = ["aws_security_group", "aws_security_group_rule", "aws_vpc_security_group_ingress_rule"]


@rule("WDN-NET-001", "Security group opens all ports to the internet", "critical", SG_TYPES,
      "An ingress rule from 0.0.0.0/0 or ::/0 covering every port exposes every service on the instance.",
      "Allow only the ports the service needs, from known CIDRs or another security group.", "CWE-284")
def sg_all_ports(r, stack):
    for b in _ingress_rules(r):
        p = _ports(b)
        if _open(b) and p and p[0] <= 0 and p[1] >= 65535:
            yield "ingress from the internet on all ports"


@rule("WDN-NET-002", "Security group exposes SSH or RDP to the internet", "high", SG_TYPES,
      "Remote admin ports open to the world are brute-forced within minutes of launch (CIS AWS 5.2 / 5.3).",
      "Use SSM Session Manager, or restrict the rule to a VPN or bastion CIDR.", "CWE-284")
def sg_admin(r, stack):
    for b in _ingress_rules(r):
        p = _ports(b)
        if not (_open(b) and p) or (p[0] <= 0 and p[1] >= 65535):
            continue
        for port, name in ADMIN_PORTS.items():
            if p[0] <= port <= p[1]:
                yield f"{name} (port {port}) open to {', '.join(sorted(set(b.get('cidr_blocks') or []) | set(b.get('ipv6_cidr_blocks') or [])))}"


@rule("WDN-NET-003", "Security group exposes a database port to the internet", "high", SG_TYPES,
      "Databases and caches should only be reachable from the application tier.",
      "Reference the app tier's security group instead of a public CIDR.", "CWE-284")
def sg_data(r, stack):
    for b in _ingress_rules(r):
        p = _ports(b)
        if not (_open(b) and p) or (p[0] <= 0 and p[1] >= 65535):
            continue
        for port, name in DATA_PORTS.items():
            if p[0] <= port <= p[1]:
                yield f"{name} (port {port}) open to the internet"


# ---------------------------------------------------------------- compute

@rule("WDN-EC2-001", "EC2 instance allows IMDSv1", "medium", ["aws_instance", "aws_launch_template"],
      "IMDSv1 answers plain GET requests, so any SSRF bug in the app can read the instance role's credentials.",
      "Set metadata_options { http_tokens = \"required\" }.", "CWE-918")
def imdsv1(r, stack):
    opts = r.blocks("metadata_options")
    if not opts or opts[0].get("http_tokens") != "required":
        yield "metadata_options.http_tokens is not \"required\""


@rule("WDN-EC2-002", "EBS volume is not encrypted", "medium", ["aws_ebs_volume", "aws_instance"],
      "Unencrypted volumes and their snapshots can be copied and read outside the account.",
      "Set encrypted = true (or turn on EBS encryption by default for the account).", "CWE-311")
def ebs_encryption(r, stack):
    if r.type == "aws_ebs_volume":
        if not is_true(r.get("encrypted")):
            yield "encrypted is not true"
        return
    for b in r.blocks("root_block_device") + r.blocks("ebs_block_device"):
        if not is_true(b.get("encrypted")):
            yield "a block device has encrypted unset"
            return
    if not r.blocks("root_block_device") and not stack.by_type.get("aws_ebs_encryption_by_default"):
        yield "root volume encryption is not set"


@rule("WDN-LAMBDA-001", "Lambda function URL needs no authentication", "high", ["aws_lambda_function_url"],
      "authorization_type NONE makes the function callable by anyone who finds the URL.",
      "Use authorization_type = \"AWS_IAM\", or put the function behind API Gateway with auth.", "CWE-306")
def lambda_url(r, stack):
    if r.get("authorization_type") == "NONE":
        yield "authorization_type is NONE"


@rule("WDN-EKS-001", "EKS API endpoint is public to the whole internet", "medium", ["aws_eks_cluster"],
      "A public Kubernetes API endpoint with no CIDR limit is an easy target for credential stuffing and CVEs.",
      "Turn off endpoint_public_access, or set public_access_cidrs to your office or VPN ranges.", "CWE-284")
def eks_public(r, stack):
    for vpc in r.blocks("vpc_config"):
        public = vpc.get("endpoint_public_access", True)
        cidrs = vpc.get("public_access_cidrs") or ["0.0.0.0/0"]
        if public is not False and any(c in OPEN_CIDRS for c in cidrs):
            yield "endpoint_public_access is on with no CIDR limit"


# ---------------------------------------------------------------- data

@rule("WDN-RDS-001", "RDS instance is publicly accessible", "high", ["aws_db_instance", "aws_rds_cluster_instance"],
      "A public RDS endpoint gets a public DNS name and IP, one security group mistake away from exposure.",
      "Set publicly_accessible = false and reach it through the VPC.", "CWE-284")
def rds_public(r, stack):
    if is_true(r.get("publicly_accessible")):
        yield "publicly_accessible is true"


@rule("WDN-RDS-002", "RDS storage is not encrypted", "medium", ["aws_db_instance", "aws_rds_cluster"],
      "Unencrypted database storage, snapshots and replicas expose data at rest.",
      "Set storage_encrypted = true (this needs a new instance for existing databases).", "CWE-311")
def rds_encryption(r, stack):
    if not is_true(r.get("storage_encrypted")):
        yield "storage_encrypted is not true"


AWS_KEY_ID = re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b")
AWS_SECRET = re.compile(r"aws_secret_access_key\s*[=:]\s*['\"]?[A-Za-z0-9/+]{40}", re.I)


def _walk(val, path=""):
    if isinstance(val, dict):
        for k, v in val.items():
            yield from _walk(v, f"{path}.{k}" if path else str(k))
    elif isinstance(val, list):
        for v in val:
            yield from _walk(v, path)
    else:
        yield path, val


@rule("WDN-SECRET-001", "Hardcoded secret in Terraform", "high", ["*"],
      "Literal passwords and keys end up in git history and in plain text in the state file.",
      "Use manage_master_user_password, a random_password resource, Secrets Manager, or a sensitive variable.",
      "CWE-798")
def hardcoded_secret(r, stack):
    for path, val in _walk(r.body):
        if not isinstance(val, str):
            continue
        key = path.rsplit(".", 1)[-1].lower()
        if any(key == s or key.endswith("_" + s) for s in SECRET_KEYS) and is_literal(val):
            yield f"{path} is set to a literal value"
        elif AWS_KEY_ID.search(val) or AWS_SECRET.search(val):
            yield f"{path} contains an AWS access key"


# ---------------------------------------------------------------- logging and keys

@rule("WDN-LOG-001", "CloudTrail is not multi-region", "medium", ["aws_cloudtrail"],
      "A single-region trail misses activity in every other region, where attackers like to run miners (CIS AWS 3.1).",
      "Set is_multi_region_trail = true.", "CWE-778")
def trail_region(r, stack):
    if not is_true(r.get("is_multi_region_trail")):
        yield "is_multi_region_trail is not true"


@rule("WDN-LOG-002", "CloudTrail log file validation is off", "low", ["aws_cloudtrail"],
      "Without digest files nobody can prove the logs were not edited after an incident (CIS AWS 3.2).",
      "Set enable_log_file_validation = true.", "CWE-354")
def trail_validation(r, stack):
    if not is_true(r.get("enable_log_file_validation")):
        yield "enable_log_file_validation is not true"


@rule("WDN-KMS-001", "KMS key rotation is off", "low", ["aws_kms_key"],
      "Yearly rotation limits how much data a single leaked key version can decrypt.",
      "Set enable_key_rotation = true.", "CWE-320")
def kms_rotation(r, stack):
    spec = r.get("customer_master_key_spec", "SYMMETRIC_DEFAULT")
    if spec == "SYMMETRIC_DEFAULT" and not is_true(r.get("enable_key_rotation")):
        yield "enable_key_rotation is not true"


@rule("WDN-ECR-001", "ECR repository does not scan images on push", "low", ["aws_ecr_repository"],
      "Images with known CVEs reach production unnoticed.",
      "Add image_scanning_configuration { scan_on_push = true }.", "CWE-1104")
def ecr_scan(r, stack):
    cfg = r.blocks("image_scanning_configuration")
    if not cfg or not is_true(cfg[0].get("scan_on_push")):
        yield "scan_on_push is not true"


def run(stack: Stack) -> list[Finding]:
    out: list[Finding] = []
    for r in stack.resources:
        if r.kind == "data":
            continue
        for rid, (meta, types, check) in RULES.items():
            if r.kind == "provider" and types != ("*",):
                continue
            if rid in r.ignored or (types != ("*",) and r.type not in types):
                continue
            for msg in check(r, stack):
                out.append(Finding(meta, r.address, r.file, r.line, msg))
    return out
