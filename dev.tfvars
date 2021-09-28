########################################################
##  Developed By  :   Pradeepta Kumar Sahu
##  Project       :   Nasuni ElasticSearch Integration
##  Organization  :   Nasuni - Community Tools   
#########################################################

## region: By default The AWS region is configured as us-east-1, 
## however it can be overridden by adding a key pair for region
##        Example : If you want to pass region as us-east-2 (us east Ohio) , then add the below:
##                     region = "us-east-2" 
## Or Uncomment the below line for Ohio region
 region = "us-east-2"

##  Provide values from secret manager 
user_secret = "<<User secret Name>>"

##  Provide the AWS Profile
aws_profile = "<<AWS Profile>>"

##  Provide the NMC Volume Name
volume_name = "<<NMC Volume Name>>"

external_share_url = "<<external_share_url>>"