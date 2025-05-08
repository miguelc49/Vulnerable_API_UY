provider "aws" {
  region = var.aws_region
}

resource "aws_iam_role" "vulnerable_role" {
  name = "vulnerable-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Action = "sts:AssumeRole",
      Principal = {
        Service = "ec2.amazonaws.com"
      },
      Effect = "Allow",
      Sid    = ""
    }]
  })
}

resource "aws_iam_role_policy_attachment" "attach_policy" {
  role       = aws_iam_role.vulnerable_role.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess" # ⚠️ Misconfig: too broad
}

resource "aws_security_group" "vulnerable_sg" {
  name        = "vulnerable-sg"
  description = "Open to the world"

  ingress {
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"] # ⚠️ Misconfig: open all ports
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_instance" "vulnerable_app" {
  ami                         = var.ami_id
  instance_type               = var.instance_type
  security_groups             = [aws_security_group.vulnerable_sg.name]
  iam_instance_profile        = aws_iam_instance_profile.vuln_profile.name
  user_data                   = file("${path.module}/user_data.sh") # ⚠️ Secrets in user data

  tags = {
    Name = "VulnerableFlaskApp"
  }
}

resource "aws_iam_instance_profile" "vuln_profile" {
  name = "vuln-instance-profile"
  role = aws_iam_role.vulnerable_role.name
}

resource "aws_s3_bucket" "public_data" {
  bucket = "vuln-public-data-${random_id.bucket_id.hex}"
  acl    = "public-read" # ⚠️ Public bucket

  tags = {
    Name        = "Vulnerable Public Bucket"
    Environment = "Test"
  }
}

resource "random_id" "bucket_id" {
  byte_length = 4
}
