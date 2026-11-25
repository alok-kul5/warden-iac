provider "aws" {
  region = "ap-south-1" # expect: WDN-EC2-003, WDN-LOG-005, WDN-IAM-005, WDN-IAM-007
}

resource "aws_iam_account_password_policy" "this" {
  minimum_password_length   = 8
  require_symbols           = true
  password_reuse_prevention = 3
}

resource "aws_vpc" "main" {
  cidr_block = "10.0.0.0/16" # expect: WDN-LOG-006
}

resource "aws_default_security_group" "default" {
  vpc_id = aws_vpc.main.id # expect: WDN-NET-005
  ingress {
    protocol  = "-1"
    self      = true
    from_port = 0
    to_port   = 0
  }
}

resource "aws_network_acl" "public" {
  vpc_id = aws_vpc.main.id # expect: WDN-NET-004
  ingress {
    protocol   = "tcp"
    rule_no    = 100
    action     = "allow"
    cidr_block = "0.0.0.0/0"
    from_port  = 0
    to_port    = 65535
  }
}

resource "aws_lb_listener" "web" {
  load_balancer_arn = "arn:aws:elasticloadbalancing:ap-south-1:123456789012:loadbalancer/app/web/abc"
  port              = 80
  protocol          = "HTTP" # expect: WDN-ELB-001
  default_action {
    type             = "forward"
    target_group_arn = "arn:aws:elasticloadbalancing:ap-south-1:123456789012:targetgroup/web/abc"
  }
}

resource "aws_efs_file_system" "shared" {
  creation_token = "shared" # expect: WDN-EFS-001
}

resource "aws_db_instance" "reporting" {
  identifier                  = "acme-reporting" # expect: WDN-RDS-002, WDN-RDS-003, WDN-RDS-004
  engine                      = "mysql"
  instance_class              = "db.t3.micro"
  allocated_storage           = 20
  username                    = "report"
  manage_master_user_password = true
  backup_retention_period     = 0
  auto_minor_version_upgrade  = false
}
