variable "aws_region" {
  default = "us-east-1"
}

variable "ami_id" {
  description = "AMI ID for EC2"
  default     = "ami-0c02fb55956c7d316" # Amazon Linux 2 (verify before use)
}

variable "instance_type" {
  default = "t2.micro"
}
