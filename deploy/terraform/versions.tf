terraform {
  required_version = ">= 1.6.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.44"
    }
  }
}

# Example provider block — region/credentials come from the environment, never hard-coded (IA-5).
provider "aws" {
  region = var.region
  default_tags {
    tags = {
      System         = var.system_name
      Environment    = var.environment
      DataOwner      = var.data_owner
      ManagedBy      = "terraform"
      DsopReference  = "true"
    }
  }
}
