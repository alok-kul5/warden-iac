"""IAM model and privilege-escalation path finder.

Builds every user, group and role in the Terraform, works out what each one is
allowed to do, then searches for chains of known escalation techniques that
end at an administrator. The techniques follow the public research on AWS IAM
privilege escalation (Rhino Security Labs, Bishop Fox's iam-vulnerable).
"""

from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass, field

import networkx as nx

from .findings import Finding, Rule
from .loader import Resource

# AWS managed policies we know the meaning of without fetching them.
MANAGED = {
    "AdministratorAccess": [{"Effect": "Allow", "Action": "*", "Resource": "*"}],
    "IAMFullAccess": [{"Effect": "Allow", "Action": ["iam:*", "organizations:Describe*",
                                                       "organizations:List*"], "Resource": "*"}],
    "PowerUserAccess": [{"Effect": "Allow", "NotAction": ["iam:*", "organizations:*", "account:*"], "Resource": "*"},
                        {"Effect": "Allow", "Action": ["iam:CreateServiceLinkedRole", "iam:DeleteServiceLinkedRole",
                                                        "iam:ListRoles", "organizations:DescribeOrganization"],
                         "Resource": "*"}],
    "ReadOnlyAccess": [{"Effect": "Allow", "Action": ["*:Describe*", "*:Get*", "*:List*"], "Resource": "*"}],
    "AmazonEC2FullAccess": [{"Effect": "Allow", "Action": ["ec2:*", "elasticloadbalancing:*",
                                                             "cloudwatch:*", "autoscaling:*"], "Resource": "*"}],
    "AWSLambda_FullAccess": [{"Effect": "Allow", "Action": ["lambda:*", "cloudformation:DescribeStacks",
                                                              "logs:*", "iam:PassRole"], "Resource": "*"}],
}

ADMIN = "ADMIN"


def _as_list(v) -> list:
    if v is None:
        return []
    return v if isinstance(v, list) else [v]


@dataclass
class Statement:
    effect: str
    actions: list[str]
    not_actions: list[str]
    resources: list[str]
    principals: dict[str, list[str]]
    conditions: dict

    def matches_action(self, action: str) -> bool:
        a = action.lower()
        if self.not_actions:
            return not any(fnmatch.fnmatchcase(a, p.lower()) for p in self.not_actions)
        return any(fnmatch.fnmatchcase(a, p.lower()) for p in self.actions)

    def principal_is_anyone(self) -> bool:
        return any("*" in ids for ids in self.principals.values()) or self.principals.get("*") is not None


def _from_json(doc) -> list[Statement]:
    if not isinstance(doc, dict):
        return []
    out = []
    for st in _as_list(doc.get("Statement")):
        if not isinstance(st, dict):
            continue
        princ = st.get("Principal")
        principals: dict[str, list[str]] = {}
        if princ == "*":
            principals = {"AWS": ["*"]}
        elif isinstance(princ, dict):
            principals = {k: [str(x) for x in _as_list(v)] for k, v in princ.items()}
        out.append(Statement(
            effect=st.get("Effect", "Allow"),
            actions=[str(x) for x in _as_list(st.get("Action"))],
            not_actions=[str(x) for x in _as_list(st.get("NotAction"))],
            resources=[str(x) for x in _as_list(st.get("Resource"))] or ["*"],
            principals=principals,
            conditions=st.get("Condition") or {},
        ))
    return out


def _from_document(r: Resource) -> list[Statement]:
    """aws_iam_policy_document data source -> statements."""
    out = []
    for st in r.blocks("statement"):
        principals: dict[str, list[str]] = {}
        for p in _as_list(st.get("principals")):
            principals.setdefault(p.get("type", "AWS"), []).extend(str(x) for x in _as_list(p.get("identifiers")))
        out.append(Statement(
            effect=st.get("effect", "Allow"),
            actions=[str(x) for x in _as_list(st.get("actions"))],
            not_actions=[str(x) for x in _as_list(st.get("not_actions"))],
            resources=[str(x) for x in _as_list(st.get("resources"))] or ["*"],
            principals=principals,
            conditions={c.get("test"): c.get("variable") for c in _as_list(st.get("condition"))},
        ))
    return out


_DOC_REF = re.compile(r"data\.aws_iam_policy_document\.([A-Za-z0-9_\-]+)\.json")


def statements(policy, stack) -> list[Statement]:
    """Turn any policy value Terraform allows (JSON, jsonencode, doc ref) into statements."""
    if isinstance(policy, dict):
        return _from_json(policy)
    if isinstance(policy, str):
        m = _DOC_REF.search(policy)
        if m:
            for d in stack.by_type.get("aws_iam_policy_document", []):
                if d.name == m.group(1) and d.kind == "data":
                    return _from_document(d)
        if policy.strip().startswith("{"):
            import json
            try:
                return _from_json(json.loads(policy))
            except ValueError:
                return []
    return []


# ---------------------------------------------------------------- principals

@dataclass
class Principal:
    key: str            # terraform address, e.g. aws_iam_user.dev
    kind: str           # user | group | role
    name: str           # IAM name
    resource: Resource
    statements: list[Statement] = field(default_factory=list)
    groups: list[str] = field(default_factory=list)
    trust: list[Statement] = field(default_factory=list)
    via: list[str] = field(default_factory=list)   # where the permissions came from

    @property
    def arn(self) -> str:
        return f"arn:aws:iam::123456789012:{self.kind}/{self.name}"


class IAMGraph:
    def __init__(self, stack):
        self.stack = stack
        self.principals: dict[str, Principal] = {}
        self.policies: dict[str, list[Statement]] = {}
        kinds = {"aws_iam_user": "user", "aws_iam_group": "group", "aws_iam_role": "role"}
        for rtype, kind in kinds.items():
            for r in stack.by_type.get(rtype, []):
                p = Principal(r.address, kind, str(r.get("name") or r.name), r)
                if kind == "role":
                    p.trust = statements(r.get("assume_role_policy"), stack)
                    for ip in r.blocks("inline_policy"):
                        self._grant(p, statements(ip.get("policy"), stack), f"inline_policy {ip.get('name', '')}".strip())
                    for arn in _as_list(r.get("managed_policy_arns")):
                        self._grant(p, self._policy(arn), str(arn))
                self.principals[p.key] = p
        for r in stack.by_type.get("aws_iam_policy", []):
            self.policies[r.address] = statements(r.get("policy"), stack)
        self._attachments()

    # -- resolution helpers
    def _find(self, value, kind: str) -> list[Principal]:
        out = []
        for v in _as_list(value):
            v = str(v)
            for p in self.principals.values():
                if p.kind != kind:
                    continue
                if f"{p.key}." in v or v == p.name:
                    out.append(p)
        return out

    def _policy(self, ref) -> list[Statement]:
        ref = str(ref)
        for addr, sts in self.policies.items():
            if f"{addr}." in ref:
                return sts
        m = re.search(r"policy/(?:[\w-]+/)*([\w-]+)$", ref)
        if m and m.group(1) in MANAGED:
            return _from_json({"Statement": MANAGED[m.group(1)]})
        return []

    def _policy_name(self, ref) -> str:
        ref = str(ref)
        for addr in self.policies:
            if f"{addr}." in ref:
                return addr
        return ref.rsplit("/", 1)[-1]

    def _iam_name(self, addr: str) -> str:
        for r in self.stack.by_type.get("aws_iam_policy", []):
            if r.address == addr:
                return str(r.get("name") or r.name)
        return addr.split(".")[-1]

    def _grant(self, p: Principal, sts: list[Statement], source: str):
        if sts:
            p.statements.extend(sts)
            p.via.append(source)

    def _attachments(self):
        s = self.stack.by_type
        for kind in ("user", "group", "role"):
            for r in s.get(f"aws_iam_{kind}_policy_attachment", []):
                for p in self._find(r.get(kind), kind):
                    self._grant(p, self._policy(r.get("policy_arn")), self._policy_name(r.get("policy_arn")))
            for r in s.get(f"aws_iam_{kind}_policy", []):
                for p in self._find(r.get(kind), kind):
                    self._grant(p, statements(r.get("policy"), self.stack), r.address)
        for r in s.get("aws_iam_policy_attachment", []):
            for kind in ("user", "group", "role"):
                for p in self._find(r.get(kind + "s"), kind):
                    self._grant(p, self._policy(r.get("policy_arn")), self._policy_name(r.get("policy_arn")))
        for r in s.get("aws_iam_user_group_membership", []):
            for u in self._find(r.get("user"), "user"):
                u.groups += [g.key for g in self._find(r.get("groups"), "group")]
        for r in s.get("aws_iam_group_membership", []):
            for g in self._find(r.get("group"), "group"):
                for u in self._find(r.get("users"), "user"):
                    u.groups.append(g.key)

    # -- permission evaluation
    def effective(self, p: Principal) -> list[Statement]:
        sts = list(p.statements)
        for g in p.groups:
            sts += self.principals[g].statements
        return sts

    def allows(self, p: Principal, action: str, target: str = "*") -> bool:
        sts = self.effective(p)
        allowed = False
        for st in sts:
            if not st.matches_action(action) or not self._res_match(st.resources, target):
                continue
            if st.effect == "Deny":
                return False
            allowed = True
        return allowed

    @staticmethod
    def _res_match(patterns: list[str], target: str) -> bool:
        for pat in patterns:
            if pat == "*" or target == "*":
                return True
            if "${" in pat:
                # a reference such as ${aws_iam_role.app.arn}
                if target in pat:
                    return True
                continue
            if fnmatch.fnmatchcase(target, pat):
                return True
        return False

    def is_admin(self, p: Principal) -> bool:
        for st in self.effective(p):
            if st.effect == "Allow" and "*" in st.resources and not st.not_actions and "*" in st.actions:
                return True
        return False

    def target_ids(self, p: Principal) -> list[str]:
        """Strings a policy Resource might use to point at this principal."""
        return [p.arn, p.key]

    def can_on(self, actor: Principal, action: str, target: Principal) -> bool:
        return any(self.allows(actor, action, t) for t in self.target_ids(target)) if self._has(actor, action) else False

    def _has(self, actor: Principal, action: str) -> bool:
        return any(st.effect == "Allow" and st.matches_action(action) for st in self.effective(actor))

    def trusts(self, role: Principal, actor: Principal | None = None, service: str | None = None) -> bool:
        for st in role.trust:
            if st.effect != "Allow" or not st.matches_action("sts:AssumeRole"):
                continue
            if service and service in st.principals.get("Service", []):
                return True
            if actor is not None:
                for ident in st.principals.get("AWS", []):
                    if ident == "*" or f"{actor.key}." in ident or ident == actor.arn or ident.endswith(":root"):
                        return True
        return False

    # -- escalation edges
    def edges(self, p: Principal):
        """Yield (target_key, technique, detail) for every single escalation step."""
        if p.kind == "group":
            return
        self_steps = [
            ("iam:CreatePolicyVersion", "CreatePolicyVersion",
             "publish a new default version of an attached policy with Action \"*\""),
            ("iam:SetDefaultPolicyVersion", "SetDefaultPolicyVersion",
             "roll an attached policy back to an older, broader version"),
        ]
        if p.kind == "user":
            self_steps += [("iam:AttachUserPolicy", "AttachUserPolicy", "attach AdministratorAccess to itself"),
                           ("iam:PutUserPolicy", "PutUserPolicy", "write an inline admin policy on itself")]
            for g in p.groups:
                self_steps += [("iam:AttachGroupPolicy", "AttachGroupPolicy",
                                f"attach AdministratorAccess to its group {g}"),
                               ("iam:PutGroupPolicy", "PutGroupPolicy", f"write an admin policy on its group {g}")]
        if p.kind == "role":
            self_steps += [("iam:AttachRolePolicy", "AttachRolePolicy", "attach AdministratorAccess to itself"),
                           ("iam:PutRolePolicy", "PutRolePolicy", "write an inline admin policy on itself")]
        own_policies = [v for v in p.via + [x for g in p.groups for x in self.principals[g].via]
                        if v.startswith("aws_iam_policy.")]
        for action, tech, detail in self_steps:
            if action.endswith("PolicyVersion"):
                hit = self._has(p, action) and any(
                    self.allows(p, action, t) for pol in own_policies
                    for t in (pol, f"arn:aws:iam::123456789012:policy/{self._iam_name(pol)}"))
            else:
                hit = self.can_on(p, action, p)
            if hit:
                yield ADMIN, tech, detail
                break

        lambdas = self.stack.by_type.get("aws_lambda_function", [])
        for q in self.principals.values():
            if q.key == p.key:
                continue
            if q.kind == "user":
                for action, tech, verb in [("iam:CreateAccessKey", "CreateAccessKey", "mint an access key for"),
                                           ("iam:CreateLoginProfile", "CreateLoginProfile", "set a console password for"),
                                           ("iam:UpdateLoginProfile", "UpdateLoginProfile", "reset the console password of")]:
                    if self.can_on(p, action, q):
                        yield q.key, tech, f"{verb} {q.key}"
                        break
            elif q.kind == "group" and p.kind == "user" and q.key not in p.groups:
                if self.can_on(p, "iam:AddUserToGroup", q):
                    yield q.key, "AddUserToGroup", f"add itself to {q.key}"
            elif q.kind == "role":
                if self.trusts(q, actor=p) and self.can_on(p, "sts:AssumeRole", q):
                    yield q.key, "AssumeRole", f"assume {q.key}, whose trust policy allows it"
                    continue
                if self.can_on(p, "iam:UpdateAssumeRolePolicy", q) and self._has(p, "sts:AssumeRole"):
                    yield q.key, "UpdateAssumeRolePolicy", f"rewrite the trust policy of {q.key} and assume it"
                    continue
                if not self.can_on(p, "iam:PassRole", q):
                    for fn in lambdas:
                        if f"{q.key}." in str(fn.get("role")) and self._has(p, "lambda:UpdateFunctionCode"):
                            yield q.key, "UpdateFunctionCode", f"replace the code of {fn.address}, which runs as {q.key}"
                            break
                    continue
                combos = [
                    ("ec2.amazonaws.com", ["ec2:RunInstances"], "PassRole+RunInstances",
                     "launch an EC2 instance with"),
                    ("lambda.amazonaws.com", ["lambda:CreateFunction", "lambda:InvokeFunction"],
                     "PassRole+CreateFunction", "create and invoke a Lambda function as"),
                    ("glue.amazonaws.com", ["glue:CreateDevEndpoint"], "PassRole+Glue", "create a Glue dev endpoint as"),
                    ("cloudformation.amazonaws.com", ["cloudformation:CreateStack"], "PassRole+CloudFormation",
                     "deploy a CloudFormation stack as"),
                    ("codebuild.amazonaws.com", ["codebuild:CreateProject", "codebuild:StartBuild"],
                     "PassRole+CodeBuild", "run a CodeBuild project as"),
                    ("ecs-tasks.amazonaws.com", ["ecs:RunTask", "ecs:RegisterTaskDefinition"],
                     "PassRole+ECS", "run an ECS task as"),
                ]
                for service, needs, tech, verb in combos:
                    if self.trusts(q, service=service) and all(self._has(p, a) for a in needs):
                        yield q.key, tech, f"{verb} {q.key}"
                        break
                else:
                    for fn in lambdas:
                        if f"{q.key}." in str(fn.get("role")) and self._has(p, "lambda:UpdateFunctionCode"):
                            yield q.key, "UpdateFunctionCode", f"replace the code of {fn.address}, which runs as {q.key}"
                            break

    def build_graph(self) -> nx.DiGraph:
        """Directed graph: principals are nodes, escalation techniques are edges,
        and every principal that already is admin points at the ADMIN sink."""
        g = nx.DiGraph()
        g.add_node(ADMIN, kind="admin", name="admin")
        for key, p in self.principals.items():
            g.add_node(key, kind=p.kind, name=p.name, admin=False)
        for key, p in self.principals.items():
            full = (p.kind != "group" and self.is_admin(p)) or (p.kind == "group" and any(
                st.effect == "Allow" and "*" in st.actions and "*" in st.resources for st in p.statements))
            if full:
                g.nodes[key]["admin"] = True
                g.add_edge(key, ADMIN, technique="is admin", detail=f"{key} already has full admin rights")
        for key, p in self.principals.items():
            if g.nodes[key]["admin"]:
                continue
            for target, tech, detail in self.edges(p):
                if not g.has_edge(key, target):      # keep the first (cheapest) technique per pair
                    g.add_edge(key, target, technique=tech, detail=detail)
        return g

    def paths(self, max_depth: int = 5) -> list[tuple[Principal, list[tuple[str, str, str, str]]]]:
        """Shortest escalation path from every non-admin user or role to admin."""
        g = self.graph = self.build_graph()
        found = []
        for key, p in self.principals.items():
            if p.kind == "group" or g.nodes[key]["admin"] or not nx.has_path(g, key, ADMIN):
                continue
            nodes = nx.shortest_path(g, key, ADMIN)
            steps = [(a, g.edges[a, b]["technique"], g.edges[a, b]["detail"], b) for a, b in zip(nodes, nodes[1:])]
            if len(steps) > 1 and steps[-1][1] == "is admin":
                steps = steps[:-1]            # the hop into an admin principal is the last real step
            if len(steps) <= max_depth:
                found.append((p, steps))
        return found


PRIVESC_RULE = Rule(
    "WDN-IAM-001", "IAM privilege-escalation path to admin", "critical",
    "A principal that is not an administrator can chain IAM permissions until it holds admin rights.",
    "Remove the first permission in the chain, or scope it to specific resources with a permissions boundary.",
    "CWE-269")
WILDCARD_RULE = Rule(
    "WDN-IAM-002", "IAM policy grants every action on every resource", "high",
    "Action \"*\" on Resource \"*\" is full admin. Grant it to a break-glass role at most.",
    "Replace the wildcard with the actions the workload calls; IAM Access Analyzer can generate them from CloudTrail.",
    "CWE-250", "1.16")
TRUST_RULE = Rule(
    "WDN-IAM-003", "Role can be assumed by any AWS account", "critical",
    "A trust policy with Principal \"*\" and no condition lets anyone with an AWS account assume the role.",
    "Name the trusted account or role, and add an sts:ExternalId condition for third parties.", "CWE-284")
USER_KEY_RULE = Rule(
    "WDN-IAM-004", "Long-lived IAM access key", "medium",
    "Access keys never expire on their own and are the most common way AWS accounts get breached.",
    "Use IAM roles, SSO, or OIDC federation for CI instead of user access keys.", "CWE-798", "1.14")


def _display(v) -> str:
    v = str(v)
    m = re.fullmatch(r"\$\{(.+?)(?:\.(?:name|arn|id))?\}", v)
    return m.group(1) if m else v


def analyze(stack) -> tuple[list[Finding], IAMGraph]:
    g = IAMGraph(stack)
    out: list[Finding] = []
    for start, path in g.paths():
        if PRIVESC_RULE.id in start.resource.ignored:
            continue
        last = path[-1][3]
        hops = [s[3] for s in path]
        hops[-1] = "admin" if last == ADMIN else f"{last} (admin)"
        chain = " -> ".join([start.key] + hops)
        out.append(Finding(PRIVESC_RULE, start.key, start.resource.file, start.resource.line,
                           f"{chain}: " + "; then ".join(s[2] for s in path),
                           path=[{"from": s[0], "technique": s[1], "detail": s[2],
                                  "to": "admin" if s[3] == ADMIN else s[3]} for s in path]))
    for r in stack.resources:
        if r.kind != "resource":
            continue
        policy_attrs = {"aws_iam_policy": "policy", "aws_iam_user_policy": "policy",
                        "aws_iam_role_policy": "policy", "aws_iam_group_policy": "policy"}
        if r.type in policy_attrs and WILDCARD_RULE.id not in r.ignored:
            for st in statements(r.get(policy_attrs[r.type]), stack):
                if st.effect == "Allow" and "*" in st.actions and "*" in st.resources:
                    out.append(Finding(WILDCARD_RULE, r.address, r.file, r.line, "statement allows \"*\" on \"*\""))
                    break
        if r.type == "aws_iam_role" and TRUST_RULE.id not in r.ignored:
            for st in statements(r.get("assume_role_policy"), stack):
                if st.effect == "Allow" and st.principal_is_anyone() and not st.conditions:
                    out.append(Finding(TRUST_RULE, r.address, r.file, r.line, "trust policy allows Principal \"*\""))
                    break
        if r.type == "aws_iam_access_key" and USER_KEY_RULE.id not in r.ignored:
            out.append(Finding(USER_KEY_RULE, r.address, r.file, r.line, f"access key for {_display(r.get('user'))}"))
    return out, g


ALL_RULES = [PRIVESC_RULE, WILDCARD_RULE, TRUST_RULE, USER_KEY_RULE]
