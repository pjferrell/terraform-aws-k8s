# variables defined here will not be imported by terraform-kubernetes-multi-cloud module
# since they are defined in that module also

variable "kubeconfig" {
  description = "Specify the location of the kubeconfig"
  type        = string
}

variable "cluster_name" {
  description = "Specify the name of the cluster (must be unique within an account)"
  type        = string
}

variable "random_cluster_suffix" {
  description = "Random 6 byte hex suffix for cluster name"
  type        = string
  default     = ""
}

## Kubernetes worker nodes
variable "nodes" {
  description = "Worker nodes (e.g. `3`)"
  type        = number
  default     = 3
}

variable "fqdn" {
  description = "Specify the fully-qualified domain name of the cluster.  This will be used for creating a zone for the cluster"
  type        = string
}
