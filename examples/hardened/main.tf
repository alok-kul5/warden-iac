# The same building blocks, configured the way the rules ask. Expect no findings.

resource "aws_s3_bucket" "uploads" {
  bucket = "acme-user-uploads"
}

resource "aws_s3_bucket_public_access_block" "uploads" {
  bucket                  = aws_s3_bucket.uploads.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "uploads" {
  bucket = aws_s3_bucket.uploads.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_security_group" "web" {
  name = "web"
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_security_group" "db" {
  name = "db"
  ingress {
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [aws_security_group.web.id]
  }
}

resource "aws_instance" "api" {
  ami           = "ami-0abcdef1234567890"
  instance_type = "t3.small"
  metadata_options {
    http_tokens = "required"
  }
  root_block_device {
    encrypted = true
  }
}

resource "aws_db_instance" "main" {
  identifier                  = "acme-prod"
  engine                      = "postgres"
  instance_class              = "db.t3.micro"
  allocated_storage           = 20
  username                    = "acme"
  manage_master_user_password = true
  publicly_accessible         = false
  storage_encrypted           = true
}

resource "aws_cloudtrail" "main" {
  name                       = "acme-trail"
  s3_bucket_name             = aws_s3_bucket.uploads.id
  is_multi_region_trail      = true
  enable_log_file_validation = true
}

resource "aws_kms_key" "app" {
  description         = "app data"
  enable_key_rotation = true
}

resource "aws_iam_openid_connect_provider" "github" {
  url             = "https://token.actions.githubusercontent.com"
  client_id_list  = ["sts.amazonaws.com"]
  thumbprint_list = ["6938fd4d98bab03faadb97b34396831e3780aea1"]
}

resource "aws_iam_role" "deploy" {
  name = "github-deploy"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRoleWithWebIdentity"
      Principal = { Federated = aws_iam_openid_connect_provider.github.arn }
      Condition = { StringLike = { "token.actions.githubusercontent.com:sub" = "repo:acme/api:ref:refs/heads/main" } }
    }]
  })
}

resource "aws_iam_role_policy" "deploy" {
  role = aws_iam_role.deploy.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      { Effect = "Allow", Action = ["ecr:PutImage", "ecr:InitiateLayerUpload", "ecr:UploadLayerPart", "ecr:CompleteLayerUpload"], Resource = "arn:aws:ecr:*:123456789012:repository/api" },
      { Effect = "Allow", Action = ["ecs:UpdateService"], Resource = "*" },
    ]
  })
}
