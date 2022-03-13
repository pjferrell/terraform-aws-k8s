output "config_map_aws_auth" {
  value = local.config_map_aws_auth
}

output "kubeconfig_path" {
  value = local_file.kubeconfig.filename
}

output "provider_info" {
  value = {
    provider = "aws"
    region = data.aws_region.current.name
    vpc_id = aws_vpc.main.id
    subnet_ids = aws_subnet.public[*].id
    security_group_ids = [aws_security_group.cluster.id, aws_security_group.node.id]
  }
}