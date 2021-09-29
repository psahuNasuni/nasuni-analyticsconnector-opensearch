# nac-terraform
Templates for creating NAC and NAC integrations with terraform

#####################################################################
 Current CF template is being uploaded along with the Terraform script. 
 In Phase II, we will be referring the Template from S3 bucket.
 Sample CF name: nac-cf.template.yaml 
                CF Takes input parameters  
NOTE: Template is placed in a local folder  
#####################################################################

TFVARS File:
    Below four key-value pairs need to be passed as input to the terraform script.
        ## region: By default The AWS region is configured as us-east-1, 
        ## however it can be overridden by adding a key pair for region
        ##        Example : If you want to pass region as us-east-2 (us east Ohio) , then add the below:
        ##                     region = "us-east-2" 
        region = "us-east-2" 
        ##  User Secret. Currently the User Secret name is hardcoded as "prod/nac/admin/". So that, Users has to create/update the secret with their respective secrets 
        <!-- user_secret = "<<User secret Name>>" -->
        ##  Provide the AWS Profile
        aws_profile = "<<AWS Profile>>"
        ##  Provide the NMC Volume Name
        volume_name = "<<NMC Volume Name>>"
        ## Provide the external_share_url  - THis is a temporary solution .
        ##              >> Once NMC API is fixed , this value will ve picked from NMC API
        external_share_url = "<<external_share_url>>"

        #############################################################################

        Need to provide user specific inputs as a Secret in AWS SecresManager.
        Create Secret in AWS SecretManager with below keys:
        nmc_api_username  =  <<Provide NMC User Name>>
        nmc_api_password  =  <<Provide NMC User password>>
        nac_product_key	  =  <<Provide latest NAC Product Key>>  
        nmc_api_endpoint  =  <<Provide NMC API endpoint Ex: 123.200.3.130/api/v1.1 >>
        web_access_appliance_address = <<Provide the Filer IP Address>>
        volume_key        = <<Provide the Volume key>>
        volume_key_passphrase = <<Provide the passphrase for the Volume key>>
        destination_bucket  = <<Provide the destination bucket name. This bucket will be used by NAC as destination bucket >>

        To provision the Infrastructure, Run the below commands:

                terraform init
                terraform apply -var-file=<<TFVARS FILE path with Extension>> -auto-approve

        To Destroy the Infrastructure, Run the below commands:
                terraform destroy -var-file=<<TFVARS FILE path with Extension>> -auto-approve
