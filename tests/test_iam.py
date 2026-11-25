import textwrap

from warden.scanner import scan


def run(tmp_path, tf):
    (tmp_path / "main.tf").write_text(textwrap.dedent(tf), encoding="utf-8")
    return scan(tmp_path)


def privesc(res):
    return {f.resource: f for f in res.findings if f.rule.id == "WDN-IAM-001"}


USER = """
resource "aws_iam_user" "u" {
  name = "u"
}
resource "aws_iam_user_policy" "u" {
  user   = aws_iam_user.u.name
  policy = jsonencode({ Statement = [%s] })
}
"""

ADMIN_GROUP = """
resource "aws_iam_group" "admins" {
  name = "admins"
}
resource "aws_iam_group_policy_attachment" "a" {
  group      = aws_iam_group.admins.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}
"""

ROLE = """
resource "aws_iam_role" "r" {
  name = "r"
  assume_role_policy = jsonencode({ Statement = [{ Effect = "Allow", Action = "sts:AssumeRole", Principal = { Service = "%s" } }] })
}
resource "aws_iam_role_policy_attachment" "r" {
  role       = aws_iam_role.r.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}
"""

BOSS = """
resource "aws_iam_user" "boss" {
  name = "boss"
}
resource "aws_iam_user_policy_attachment" "boss" {
  user       = aws_iam_user.boss.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}
"""


def test_attach_user_policy_on_self(tmp_path):
    res = run(tmp_path, USER % '{ Effect = "Allow", Action = "iam:AttachUserPolicy", Resource = "*" }')
    assert privesc(res)["aws_iam_user.u"].path[0]["technique"] == "AttachUserPolicy"


def test_attach_user_policy_scoped_to_someone_else_is_safe(tmp_path):
    res = run(tmp_path, USER % '{ Effect = "Allow", Action = "iam:AttachUserPolicy", '
                               'Resource = "arn:aws:iam::*:user/other" }')
    assert privesc(res) == {}


def test_explicit_deny_blocks_the_path(tmp_path):
    res = run(tmp_path, USER % (
        '{ Effect = "Allow", Action = "iam:*", Resource = "*" },'
        '{ Effect = "Deny", Action = ["iam:Attach*", "iam:Put*", "iam:Create*", "iam:Update*", '
        '"iam:SetDefaultPolicyVersion", "iam:AddUserToGroup"], Resource = "*" }') + BOSS)
    assert privesc(res) == {}


def test_wildcard_action_prefix_matches(tmp_path):
    res = run(tmp_path, USER % '{ Effect = "Allow", Action = "iam:Put*", Resource = "*" }')
    assert privesc(res)["aws_iam_user.u"].path[0]["technique"] == "PutUserPolicy"


def test_not_action_power_user_cannot_escalate(tmp_path):
    res = run(tmp_path, """
    resource "aws_iam_user" "dev" {
      name = "dev"
    }
    resource "aws_iam_user_policy_attachment" "dev" {
      user       = aws_iam_user.dev.name
      policy_arn = "arn:aws:iam::aws:policy/PowerUserAccess"
    }
    """ + ADMIN_GROUP)
    assert privesc(res) == {}


def test_add_user_to_admin_group(tmp_path):
    res = run(tmp_path, USER % '{ Effect = "Allow", Action = "iam:AddUserToGroup", Resource = "*" }' + ADMIN_GROUP)
    assert privesc(res)["aws_iam_user.u"].path[0]["technique"] == "AddUserToGroup"


def test_group_membership_grants_permissions(tmp_path):
    res = run(tmp_path, """
    resource "aws_iam_user" "a" {
      name = "a"
    }
    resource "aws_iam_group" "g" {
      name = "g"
    }
    resource "aws_iam_group_membership" "m" {
      name  = "m"
      group = aws_iam_group.g.name
      users = [aws_iam_user.a.name]
    }
    resource "aws_iam_group_policy" "g" {
      group  = aws_iam_group.g.name
      policy = jsonencode({ Statement = [{ Effect = "Allow", Action = "iam:PutGroupPolicy", Resource = "*" }] })
    }
    """)
    assert privesc(res)["aws_iam_user.a"].path[0]["technique"] == "PutGroupPolicy"


def test_passrole_needs_a_matching_service_trust(tmp_path):
    user = USER % ('{ Effect = "Allow", Action = ["iam:PassRole", "lambda:CreateFunction", '
                   '"lambda:InvokeFunction"], Resource = "*" }')
    assert "aws_iam_user.u" in privesc(run(tmp_path, ROLE % "lambda.amazonaws.com" + user))
    assert privesc(run(tmp_path, ROLE % "ec2.amazonaws.com" + user)) == {}


def test_heredoc_policy(tmp_path):
    res = run(tmp_path, '''
    resource "aws_iam_user" "u" {
      name = "u"
    }
    resource "aws_iam_user_policy" "u" {
      user   = aws_iam_user.u.name
      policy = <<POLICY
    {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "iam:CreateLoginProfile", "Resource": "*"}]}
    POLICY
    }
    ''' + BOSS)
    assert privesc(res)["aws_iam_user.u"].path[-1]["to"] == "aws_iam_user.boss"
