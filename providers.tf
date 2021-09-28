########################################################
##  Developed By  :   Pradeepta Kumar Sahu
##  Project       :   Nasuni ElasticSearch Integration
##  Organization  :   Nasuni - Community Tools   
#########################################################

terraform {
  required_providers {
    aws = {
      source = "hashicorp/aws"
      version = "3.60.0"
    }
  }
}

provider "aws" {
  region  = var.region
  profile = var.aws_profile

}
