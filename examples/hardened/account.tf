# Account-level controls that every root module with an AWS provider should have.

provider "aws" {
  region = "ap-south-1"
}

resource "aws_iam_account_password_policy" "this" {
  minimum_password_length        = 14
  password_reuse_prevention      = 24
  require_symbols                = true
  require_numbers                = true
  require_uppercase_characters   = true
  require_lowercase_characters   = true
  allow_users_to_change_password = true
}

resource "aws_accessanalyzer_analyzer" "account" {
  analyzer_name = "account"
  type          = "ACCOUNT"
}

resource "aws_ebs_encryption_by_default" "this" {
  enabled = true
}

resource "aws_iam_role" "config" {
  name = "aws-config"
  assume_role_policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = "sts:AssumeRole", Principal = { Service = "config.amazonaws.com" } }]
  })
}

resource "aws_config_configuration_recorder" "this" {
  name     = "default"
  role_arn = aws_iam_role.config.arn
  recording_group {
    all_supported                 = true
    include_global_resource_types = true
  }
}

resource "aws_s3_bucket_policy" "uploads_tls" {
  bucket = aws_s3_bucket.uploads.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "DenyInsecureTransport"
      Effect    = "Deny"
      Principal = "*"
      Action    = "s3:*"
      Resource  = [aws_s3_bucket.uploads.arn, "${aws_s3_bucket.uploads.arn}/*"]
      Condition = { Bool = { "aws:SecureTransport" = "false" } }
    }]
  })
}

resource "aws_vpc" "main" {
  cidr_block = "10.0.0.0/16"
}

resource "aws_flow_log" "main" {
  vpc_id          = aws_vpc.main.id
  traffic_type    = "ALL"
  log_destination = aws_s3_bucket.uploads.arn
}

resource "aws_default_security_group" "default" {
  vpc_id = aws_vpc.main.id
}

resource "aws_lb_listener" "http" {
  load_balancer_arn = "arn:aws:elasticloadbalancing:ap-south-1:123456789012:loadbalancer/app/web/abc"
  port              = 80
  protocol          = "HTTP"
  default_action {
    type = "redirect"
    redirect {
      port        = "443"
      protocol    = "HTTPS"
      status_code = "HTTP_301"
    }
  }
}

resource "aws_efs_file_system" "shared" {
  creation_token = "shared"
  encrypted      = true
}
