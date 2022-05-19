terraform {
  required_providers {
    aws = {
      source  = "aws"
      version = ">=2.14"
    }
  }
  experiments = [module_variable_optional_attrs]
}