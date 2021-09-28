########################################################
##  Developr      :   Pradeepta Kumar Sahu
##  Project       :   Nasuni ElasticSearch Integration
##  Organization  :   Nasuni - Community Tools   
#########################################################
output "name" {
  value       = join("", aws_cloudformation_stack.nac_stack.*.name)
  description = "Name of the CloudFormation Stack"
}

output "id" {
  value       = join("", aws_cloudformation_stack.nac_stack.*.id)
  description = "ID of the CloudFormation Stack"
}

output "outputs" {
  value       = module.this.enabled ? aws_cloudformation_stack.nac_stack[0].outputs : {}
  description = "Outputs of the CloudFormation Stack"
}
