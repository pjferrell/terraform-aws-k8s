output "config_map_aws_auth" {
  value = local.config_map_aws_auth
}

output "kubeconfig_path" {
  value = local_file.kubeconfig.filename
}

output "provider_info" {
  value = {
    cluster_name = var.cluster_name
    provider = "aws"
    region = data.aws_region.current.name
    vpc_id = aws_vpc.main.id
    worker_subnets = [
      for o in aws_subnet.workers:
        {
          name = o.tags["Name"]
          cidr = o.cidr_block
          id = o.id
          availability_zone = o.availability_zone
        }
    ]
    data_subnets = [
      for o in aws_subnet.private:
        {
          name = try(o.tags["Name"], o.tags["infoblox.com/subnet/name"])
          cidr = o.cidr_block
          id = o.id
          availability_zone = o.availability_zone
        }
    ]
    security_group_ids = [aws_security_group.cluster.id, aws_security_group.node.id]
    fqdn = var.fqdn
  }
}
