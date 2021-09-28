# nac-terraform
Templates for creating NAC and NAC integrations with terraform

#####################################################################
 Current CF template is being uploaded along with the Terraform script. 
 In Phase II, we will be referring the Template from S3 bucket.
 Sample CF name: nac-cf.template.yaml 
                CF Takes input parameters  
NOTE: Template is placed in a local folder  
#####################################################################

terraform init

terraform validate

terraform fmt

terraform plan -var-file=dev.tfvars 

terraform apply -var-file=dev.tfvars -auto-approve
terraform apply -var-file=test.tfvars -auto-approve
terraform apply -var-file=test.tfvars -auto-approve

terraform destroy -var-file=dev.tfvars -auto-approve
terraform destroy -var-file=test.tfvars -auto-approve
