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
NOT_SECRETS = {"creation_token", "client_token", "idempotency_token", "token_validity_units", "secret_name"}


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
    names = {v for v in (target.get("bucket"), target.get("name"), target.get("identifier")) if isinstance(v, str)}
    return value in names


def is_true(v) -> bool:
    return v is True or (isinstance(v, str) and v.lower() == "true")


def is_literal(v) -> bool:
    return isinstance(v, str) and v != "" and "${" not in v


Check = Callable[[Resource, Stack], Iterable[str]]
RULES: dict[str, tuple[Rule, tuple[str, ...], Check]] = {}


# CIS AWS Foundations Benchmark v3.0.0 controls. Rules without an entry are AWS
# best practice that the benchmark does not cover.
CIS = {
    "WDN-S3-001": "2.1.4", "WDN-S3-002": "2.1.4", "WDN-S3-004": "2.1.1",
    "WDN-NET-001": "5.2, 5.3", "WDN-NET-002": "5.2, 5.3", "WDN-NET-004": "5.1", "WDN-NET-005": "5.4",
    "WDN-EC2-001": "5.6", "WDN-EC2-002": "2.2.1", "WDN-EC2-003": "2.2.1",
    "WDN-RDS-001": "2.3.3", "WDN-RDS-002": "2.3.1", "WDN-RDS-003": "2.3.2", "WDN-EFS-001": "2.4.1",
    "WDN-LOG-001": "3.1", "WDN-LOG-002": "3.2", "WDN-LOG-003": "3.5", "WDN-LOG-004": "3.1",
    "WDN-LOG-005": "3.3", "WDN-LOG-006": "3.7", "WDN-KMS-001": "3.6",
    "WDN-IAM-005": "1.8, 1.9", "WDN-IAM-006": "1.15", "WDN-IAM-007": "1.20",
}

PROVIDER = "@provider"   # account-level checks that run once per root module


def rule(id, title, severity, types, description, fix, cwe=""):
    def wrap(fn: Check):
        RULES[id] = (Rule(id, title, severity, description, fix, cwe, CIS.get(id, "")), tuple(types), fn)
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
        if key not in NOT_SECRETS and any(key == s or key.endswith("_" + s) for s in SECRET_KEYS) and is_literal(val):
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


# ---------------------------------------------------------------- more S3, network, storage

@rule("WDN-S3-004", "S3 bucket allows plain HTTP requests", "low", ["aws_s3_bucket"],
      "Without a policy that denies aws:SecureTransport = false, clients can read and write objects over HTTP.",
      "Add a bucket policy statement that denies s3:* when aws:SecureTransport is false.", "CWE-319")
def s3_https_only(r, stack):
    from .iam import statements
    for pol in stack.linked("aws_s3_bucket_policy", "bucket", r):
        for st in statements(pol.get("policy"), stack):
            if st.effect == "Deny" and "SecureTransport" in str(st.conditions):
                return
    yield "no bucket policy denies requests without TLS"


def _nacl_rules(r: Resource):
    if r.type == "aws_network_acl":
        for b in r.blocks("ingress"):
            yield b
    elif r.type == "aws_network_acl_rule" and not is_true(r.get("egress")):
        yield r.body


@rule("WDN-NET-004", "Network ACL allows SSH or RDP from the internet", "medium",
      ["aws_network_acl", "aws_network_acl_rule"],
      "NACLs are the subnet-level backstop; letting admin ports in from anywhere removes it.",
      "Deny 22 and 3389 from 0.0.0.0/0 in the NACL, and allow only your admin CIDRs.", "CWE-284")
def nacl_admin(r, stack):
    for b in _nacl_rules(r):
        action = str(b.get("action") or b.get("rule_action") or "").lower()
        cidr = b.get("cidr_block") or b.get("ipv6_cidr_block")
        if action != "allow" or cidr not in OPEN_CIDRS:
            continue
        p = _ports(b)
        if p and any(p[0] <= port <= p[1] for port in ADMIN_PORTS):
            yield f"allows ports {p[0]}-{p[1]} from {cidr}"
            return


@rule("WDN-NET-005", "Default security group allows traffic", "medium", ["aws_default_security_group"],
      "Anything launched without an explicit group lands in the default one, so it should allow nothing.",
      "Manage aws_default_security_group with no ingress or egress blocks.", "CWE-284")
def default_sg(r, stack):
    if r.blocks("ingress") or r.blocks("egress"):
        yield "the default security group has rules"


@rule("WDN-EC2-003", "EBS encryption by default is not enabled", "low", [PROVIDER],
      "Account-level EBS encryption by default makes every new volume and snapshot encrypted, even ones made by hand.",
      "Add aws_ebs_encryption_by_default { enabled = true }.", "CWE-311")
def ebs_default(r, stack):
    if not any(is_true(x.get("enabled", True)) for x in stack.by_type.get("aws_ebs_encryption_by_default", [])):
        yield "no aws_ebs_encryption_by_default in this root module"


@rule("WDN-RDS-003", "RDS automatic minor upgrades are off", "low", ["aws_db_instance", "aws_rds_cluster_instance"],
      "Minor versions carry security patches; turning automatic upgrades off leaves known bugs in place.",
      "Remove auto_minor_version_upgrade = false (the default is true).", "CWE-1104")
def rds_minor(r, stack):
    if r.get("auto_minor_version_upgrade") is False:
        yield "auto_minor_version_upgrade is false"


@rule("WDN-RDS-004", "RDS automated backups are off", "medium", ["aws_db_instance"],
      "A backup retention period of 0 turns off automated backups and point-in-time restore.",
      "Set backup_retention_period to 7 or more.", "CWE-693")
def rds_backups(r, stack):
    if str(r.get("backup_retention_period")) == "0":
        yield "backup_retention_period is 0"


@rule("WDN-EFS-001", "EFS file system is not encrypted", "medium", ["aws_efs_file_system"],
      "EFS encryption at rest can only be chosen at creation time.",
      "Set encrypted = true (and kms_key_id for a customer key).", "CWE-311")
def efs_encryption(r, stack):
    if not is_true(r.get("encrypted")):
        yield "encrypted is not true"


@rule("WDN-ELB-001", "Load balancer listener serves plain HTTP", "medium", ["aws_lb_listener", "aws_alb_listener"],
      "An HTTP listener that does not redirect sends cookies and tokens in clear text.",
      "Redirect port 80 to HTTPS, and serve the app on an HTTPS listener with a TLS 1.2+ policy.", "CWE-319")
def lb_http(r, stack):
    if str(r.get("protocol", "")).upper() == "HTTP":
        if not any(a.get("type") == "redirect" for a in r.blocks("default_action")):
            yield "HTTP listener does not redirect to HTTPS"


# ---------------------------------------------------------------- more logging

@rule("WDN-LOG-003", "CloudTrail logs are not encrypted with KMS", "medium", ["aws_cloudtrail"],
      "SSE-KMS adds a second permission check: reading the logs also needs kms:Decrypt.",
      "Set kms_key_id to a customer-managed KMS key.", "CWE-311")
def trail_kms(r, stack):
    if not r.get("kms_key_id"):
        yield "kms_key_id is not set"


@rule("WDN-LOG-004", "No CloudTrail trail in this account", "high", [PROVIDER],
      "Without CloudTrail there is no record of who did what, which makes incident response guesswork.",
      "Add a multi-region aws_cloudtrail with log file validation and KMS encryption.", "CWE-778")
def no_trail(r, stack):
    if not stack.by_type.get("aws_cloudtrail"):
        yield "no aws_cloudtrail in this root module"


@rule("WDN-LOG-005", "AWS Config is not recording", "medium", [PROVIDER],
      "AWS Config keeps the change history of every resource, which you need to see when a setting drifted.",
      "Add aws_config_configuration_recorder (all supported types) with a delivery channel and recorder status.",
      "CWE-778")
def no_config(r, stack):
    if not stack.by_type.get("aws_config_configuration_recorder"):
        yield "no aws_config_configuration_recorder in this root module"


@rule("WDN-LOG-006", "VPC has no flow logs", "medium", ["aws_vpc"],
      "Flow logs are the only record of which IPs talked to which instances.",
      "Add aws_flow_log with vpc_id pointing at this VPC.", "CWE-778")
def vpc_flow(r, stack):
    if not stack.linked("aws_flow_log", "vpc_id", r):
        yield "no aws_flow_log for this VPC"


# ---------------------------------------------------------------- account IAM

@rule("WDN-IAM-005", "Weak IAM password policy", "medium", [PROVIDER],
      "Console passwords should be 14+ characters and not reused (CIS 1.8 and 1.9).",
      "Add aws_iam_account_password_policy with minimum_password_length = 14 and password_reuse_prevention = 24.",
      "CWE-521")
def password_policy(r, stack):
    pols = stack.by_type.get("aws_iam_account_password_policy", [])
    if not pols:
        yield "no aws_iam_account_password_policy in this root module"
        return
    p = pols[0]
    try:
        if int(p.get("minimum_password_length", 8)) < 14:
            yield "minimum_password_length is below 14"
        if int(p.get("password_reuse_prevention", 0)) < 24:
            yield "password_reuse_prevention is below 24"
    except (TypeError, ValueError):
        pass


@rule("WDN-IAM-006", "IAM user has policies attached directly", "low",
      ["aws_iam_user_policy", "aws_iam_user_policy_attachment"],
      "Permissions on individual users drift and get forgotten; grant them through groups or roles (CIS 1.15).",
      "Put the user in a group and attach the policy to the group instead.", "CWE-269")
def user_direct(r, stack):
    yield "policy is attached to a user, not a group"


@rule("WDN-IAM-007", "IAM Access Analyzer is not enabled", "low", [PROVIDER],
      "Access Analyzer flags resources shared outside the account, like a bucket opened to another account.",
      "Add aws_accessanalyzer_analyzer with type = \"ACCOUNT\" (or ORGANIZATION).", "CWE-284")
def access_analyzer(r, stack):
    if not stack.by_type.get("aws_accessanalyzer_analyzer"):
        yield "no aws_accessanalyzer_analyzer in this root module"


def run(stack: Stack) -> list[Finding]:
    out: list[Finding] = []
    for r in stack.resources:
        if r.kind == "data":
            continue
        for rid, (meta, types, check) in RULES.items():
            if r.kind == "provider":
                if types not in (("*",), (PROVIDER,)) or (types == (PROVIDER,) and r.type != "aws"):
                    continue
            elif types == (PROVIDER,):
                continue
            if rid in r.ignored or (types not in (("*",), (PROVIDER,)) and r.type not in types):
                continue
            for msg in check(r, stack):
                out.append(Finding(meta, r.address, r.file, r.line, msg))
    return out
