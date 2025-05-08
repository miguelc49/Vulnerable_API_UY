output "ec2_instance_public_ip" {
  value = aws_instance.vulnerable_app.public_ip
}