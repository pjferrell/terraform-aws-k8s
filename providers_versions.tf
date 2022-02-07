terraform {
  required_providers {
    aws = {
      source  = "aws"
      version = ">=2.14"
    }
  }
}

# this is implemented in parent module
# provider "aws" {
#   region  = var.aws_region
#   profile = var.aws_profile
# }