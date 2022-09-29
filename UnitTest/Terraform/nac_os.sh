#!/bin/bash
export TF_LOG=debug
export TF_LOG_PATH=./terraform_UnitTestOS.log

OS_TFVARS="$1"
exit_status=0
check_if_terraform_exists(){
   terraform -version || exit_status=$?
if [ $exit_status -eq 0 ]; then
    echo "INFO ::: Terraform installed"
elif [ $exit_status -eq 1 ]; then
    echo "ERROR ::: Terraform not installed"
    exit 1
fi
}
check_if_terraform_exists
echo "INFO ::: Amazon_NAC_OpenSearch_Service ::: BEGIN ::: Executing ::: Terraform Init ."
cp ./nac_os.tfvars ../../
cd ../../
terraform init
echo "INFO ::: Amazon_NAC_OpenSearch_Service ::: FINISHED ::: Executing ::: Terraform Init  ."

echo "INFO ::: Amazon_NAC_OpenSearch_Service ::: BEGIN ::: Executing ::: Terraform apply  ."
COMMAND="terraform apply -var-file=$OS_TFVARS -auto-approve"
$COMMAND || exit_status=$?

if [ $exit_status -eq 0 ]; then
    echo "INFO ::: Amazon_NAC_OpenSearch_Service ::: FINISHED ::: Executing ::: Terraform apply  ."
    

elif [ $exit_status -eq 1 ]; then
    echo "INFO ::: Amazon_NAC_OpenSearch_Service ::: FAILED ::: Executing ::: Terraform apply  ."
    exit 1
fi

echo "INFO ::: Amazon_OpenSearch_Service provisioning ::: BEGIN ::: DESTROY INFRA ::: Terraform Destroy."
terraform destroy -var-file=$OS_TFVARS -auto-approve
echo "INFO ::: Amazon_OpenSearch_Service provisioning ::: COMPLETED ::: DESTROY INFRA ::: Terraform Destroy."
