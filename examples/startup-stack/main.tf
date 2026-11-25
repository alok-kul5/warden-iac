# A typical first-year startup stack: it works, and it has the mistakes that
# show up in real breach reports. "expect:" comments label each one.

resource "aws_s3_bucket" "uploads" {
  bucket = "acme-user-uploads" # expect: WDN-S3-002, WDN-S3-003
}

resource "aws_s3_bucket_acl" "uploads" {
  bucket = aws_s3_bucket.uploads.id
  acl    = "public-read" # expect: WDN-S3-001
}

resource "aws_s3_bucket" "logs" {
  bucket = "acme-access-logs" # expect: WDN-S3-003
}

resource "aws_s3_bucket_public_access_block" "logs" {
  bucket                  = aws_s3_bucket.logs.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_policy" "uploads" {
  bucket = aws_s3_bucket.uploads.id # expect: WDN-S3-004
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = "*"
      Action    = ["s3:GetObject"]
      Resource  = "${aws_s3_bucket.uploads.arn}/*"
    }]
  })
}

resource "aws_security_group" "web" {
  name = "web" # expect: WDN-NET-002
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_security_group" "db" {
  name = "db" # expect: WDN-NET-003
  ingress {
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_security_group_rule" "debug" {
  type              = "ingress" # expect: WDN-NET-001
  security_group_id = aws_security_group.web.id
  from_port         = 0
  to_port           = 0
  protocol          = "-1"
  ipv6_cidr_blocks  = ["::/0"]
}

resource "aws_instance" "api" {
  ami                    = "ami-0abcdef1234567890" # expect: WDN-EC2-001, WDN-EC2-002
  instance_type          = "t3.small"
  vpc_security_group_ids = [aws_security_group.web.id]
  iam_instance_profile   = "api"
}

resource "aws_db_instance" "main" {
  identifier          = "acme-prod" # expect: WDN-RDS-001, WDN-RDS-002, WDN-SECRET-001
  engine              = "postgres"
  instance_class      = "db.t3.micro"
  allocated_storage   = 20
  username            = "acme"
  password            = "Summer2026!"
  publicly_accessible = true
  skip_final_snapshot = true
}

resource "aws_cloudtrail" "main" {
  name           = "acme-trail" # expect: WDN-LOG-001, WDN-LOG-002
  s3_bucket_name = aws_s3_bucket.logs.id
}

resource "aws_kms_key" "app" {
  description = "app data" # expect: WDN-KMS-001
}

resource "aws_lambda_function_url" "webhook" {
  function_name      = "stripe-webhook"
  authorization_type = "NONE" # expect: WDN-LAMBDA-001
}

resource "aws_ecr_repository" "api" {
  name = "api" # expect: WDN-ECR-001
}

resource "aws_eks_cluster" "main" {
  name     = "acme" # expect: WDN-EKS-001
  role_arn = "arn:aws:iam::123456789012:role/eks"
  vpc_config {
    subnet_ids = ["subnet-1", "subnet-2"]
  }
}

resource "aws_iam_user" "github_actions" {
  name = "github-actions"
}

resource "aws_iam_access_key" "github_actions" {
  user = aws_iam_user.github_actions.name # expect: WDN-IAM-004
}

resource "aws_iam_policy" "deploy" {
  name = "deploy" # expect: WDN-IAM-002
  policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = "*", Resource = "*" }]
  })
}

resource "aws_iam_user_policy_attachment" "github_actions" {
  user       = aws_iam_user.github_actions.name
  policy_arn = aws_iam_policy.deploy.arn
}

# A rule the team accepted on purpose, silenced inline.
resource "aws_security_group" "bastion" {
  name = "bastion" # warden:ignore WDN-NET-002
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
