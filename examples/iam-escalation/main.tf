# Classic AWS IAM privilege-escalation setups. Each user below looks harmless on
# its own; the scanner has to chain permissions to see that it reaches admin.
# "expect:" comments are the labels the test suite checks against.

resource "aws_iam_role" "admin" {
  name = "platform-admin"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy_attachment" "admin" {
  role       = aws_iam_role.admin.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

# 1. PassRole + RunInstances: start an instance with the admin role, read its creds.
resource "aws_iam_user" "ci_deployer" {
  name = "ci-deployer" # expect: WDN-IAM-001
}

resource "aws_iam_user_policy" "ci_deployer" {
  user = aws_iam_user.ci_deployer.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      { Effect = "Allow", Action = ["ec2:RunInstances", "ec2:Describe*"], Resource = "*" },
      { Effect = "Allow", Action = "iam:PassRole", Resource = "*" },
    ]
  })
}

# 2. A policy that lets a user edit its own policy versions.
resource "aws_iam_user" "analyst" {
  name = "analyst" # expect: WDN-IAM-001
}

resource "aws_iam_policy" "analyst" {
  name = "analyst-self-service"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      { Effect = "Allow", Action = ["s3:GetObject", "athena:*"], Resource = "*" },
      { Effect = "Allow", Action = ["iam:CreatePolicyVersion", "iam:GetPolicy"], Resource = "arn:aws:iam::*:policy/analyst-self-service" },
    ]
  })
}

resource "aws_iam_user_policy_attachment" "analyst" {
  user       = aws_iam_user.analyst.name
  policy_arn = aws_iam_policy.analyst.arn
}

# 3. Two hops: helpdesk can reset the console password of an admin user.
resource "aws_iam_user" "ops_lead" {
  name = "ops-lead"
}

resource "aws_iam_user_policy_attachment" "ops_lead" {
  user       = aws_iam_user.ops_lead.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

resource "aws_iam_user" "helpdesk" {
  name = "helpdesk" # expect: WDN-IAM-001
}

data "aws_iam_policy_document" "helpdesk" {
  statement {
    actions   = ["iam:UpdateLoginProfile", "iam:ListUsers"]
    resources = ["arn:aws:iam::*:user/*"]
  }
}

resource "aws_iam_user_policy" "helpdesk" {
  user   = aws_iam_user.helpdesk.name
  policy = data.aws_iam_policy_document.helpdesk.json
}

# 4. Two hops through a role: intern assumes the build role, and the build role
#    can mint an access key for the admin user ops-lead.
resource "aws_iam_group" "admins" {
  name = "admins"
}

resource "aws_iam_group_policy_attachment" "admins" {
  group      = aws_iam_group.admins.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

resource "aws_iam_user" "intern" {
  name = "intern" # expect: WDN-IAM-001
}

resource "aws_iam_user_policy" "intern" {
  user = aws_iam_user.intern.name
  policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = "sts:AssumeRole", Resource = aws_iam_role.build.arn }]
  })
}

resource "aws_iam_role" "build" {
  name = "build" # expect: WDN-IAM-001
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { AWS = aws_iam_user.intern.arn }
    }]
  })
}

resource "aws_iam_role_policy" "build" {
  role = aws_iam_role.build.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = ["iam:CreateAccessKey"], Resource = "arn:aws:iam::*:user/ops-lead" }]
  })
}

# 5. Lambda code swap: the function already runs as the admin-ish role.
resource "aws_iam_role" "nightly_job" {
  name = "nightly-job"
  assume_role_policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = "sts:AssumeRole", Principal = { Service = "lambda.amazonaws.com" } }]
  })
}

resource "aws_iam_role_policy_attachment" "nightly_job" {
  role       = aws_iam_role.nightly_job.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

resource "aws_lambda_function" "nightly" {
  function_name = "nightly-report"
  role          = aws_iam_role.nightly_job.arn
  handler       = "app.handler"
  runtime       = "python3.12"
  filename      = "nightly.zip"
}

resource "aws_iam_user" "data_eng" {
  name = "data-eng" # expect: WDN-IAM-001
}

resource "aws_iam_user_policy" "data_eng" {
  user = aws_iam_user.data_eng.name
  policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = ["lambda:UpdateFunctionCode", "lambda:InvokeFunction"], Resource = "*" }]
  })
}

# 6. A role anyone on AWS can assume.
resource "aws_iam_role" "vendor_audit" {
  name = "vendor-audit" # expect: WDN-IAM-003
  assume_role_policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = "sts:AssumeRole", Principal = { AWS = "*" } }]
  })
}

resource "aws_iam_role_policy_attachment" "vendor_audit" {
  role       = aws_iam_role.vendor_audit.name
  policy_arn = "arn:aws:iam::aws:policy/ReadOnlyAccess"
}

# Not an escalation: PassRole is scoped to a role that only trusts Lambda, and
# this user cannot create functions. The scanner must stay quiet here.
resource "aws_iam_user" "reporting" {
  name = "reporting"
}

resource "aws_iam_user_policy" "reporting" {
  user = aws_iam_user.reporting.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      { Effect = "Allow", Action = "iam:PassRole", Resource = aws_iam_role.nightly_job.arn },
      { Effect = "Allow", Action = ["ec2:RunInstances"], Resource = "*" },
      { Effect = "Allow", Action = ["cloudwatch:GetMetricData"], Resource = "*" },
    ]
  })
}
