########################################################
##  Developed By  :   Pradeepta Kumar Sahu
##  Project       :   Nasuni ElasticSearch Integration
##  Organization  :   Nasuni - Community Tools   
#########################################################
variable "template_url" {
  type        = string
  description = "Amazon S3 bucket URL location of a file containing the CloudFormation template body. Maximum file size: 460,800 bytes"
  default     = ""
}


variable "user_parameters" {
  type    = map(string)
  default = {}

  description = "Key-value map of User specific Parameters to be included when passing paramters to CloudFormattion Template, in addition to the ones provided automatically by this module."
}

variable "parameters" {
  type        = map(string)
  description = "Key-value map of input parameters for the Stack Set template. (_e.g._ map(\"BusinessUnit\",\"ABC\")"
  default     = {}
}

variable "capabilities" {
  type        = list(string)
  description = "A list of capabilities. Valid values: CAPABILITY_IAM, CAPABILITY_NAMED_IAM, CAPABILITY_AUTO_EXPAND"
  default     = ["CAPABILITY_IAM"]
}

variable "on_failure" {
  type        = string
  default     = "ROLLBACK"
  description = "Action to be taken if stack creation fails. This must be one of: `DO_NOTHING`, `ROLLBACK`, or `DELETE`"
}

variable "timeout_in_minutes" {
  type        = number
  default     = 10
  description = "The amount of time that can pass before the stack status becomes `CREATE_FAILED`"
}

variable "policy_body" {
  type        = string
  default     = ""
  description = "Structure containing the stack policy body"
}

variable "aws_access_key" {
  default = ""
}
variable "aws_secret_key" {
  default = ""
}


variable "template_file" {
  type        = string
  default     = ""
  description = "location of a file containing the CloudFormation template body."
}

variable "region" {
  default = "us-east-1"
}


variable "VolumeKeyParameter" {
  default = ""
}

variable "VolumeKeyPassphrase" {
  default = ""
}

variable "user_secret" {
  default = "prod/nac/admin"
}

################### Lambda PRovisioning Specific Variables ###################

variable "nac_destination_bucket" {
  default     = ""
  description = "S3 bucket where NAC will be updating the files/data"
}
variable "runtime" {
  default = "python3.6"
}

variable "aws_profile" {
  default = "nasuni"
}

variable "internal_secret" {
  default = "nac-es-internal"
}
variable "volume_name" {
  default = ""
}
variable "external_share_url" {
  default = ""
}
#########################################