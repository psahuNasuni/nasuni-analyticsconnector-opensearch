#!/bin/bash
export TF_LOG=debug
export TF_LOG_PATH=./terraform_UnitTestPy.log

exit_status=0
check_if_python_exists(){
   python --version || exit_status=$?
if [ $exit_status -eq 0 ]; then
    echo "INFO ::::::::::::::: Python installed"
elif [ $exit_status -eq 1 ]; then
    echo "ERROR ::::::::::::::: Python not installed"
    exit 1
fi
}
check_if_terraform_exists(){
   terraform -version || exit_status=$?
if [ $exit_status -eq 0 ]; then
    echo "INFO ::::::::::::::: Terraform installed"
elif [ $exit_status -eq 1 ]; then
    echo "ERROR ::::::::::::::: Terraform not installed"
    exit 1
fi
}
check_if_python_exists
check_if_terraform_exists

echo "INFO ::: Amazon_NAC_OpenSearch_Service ::: BEGIN ::: Executing ::: Terraform Init ."
cd ../..
INIT="terraform init"
$INIT||init_exit_status=$?

if [ $init_exit_status -eq 0 ]; then
    echo "INFO ::: Amazon_NAC_OpenSearch_Service ::: FINISHED ::: Executing ::: Terraform init  ."
    

elif [ $init_exit_status -eq 1 ]; then
    echo "INFO ::: Amazon_NAC_OpenSearch_Service ::: FAILED ::: Executing ::: Terraform init  ."
    exit 1
fi

echo "INFO ::: Amazon_NAC_OpenSearch_Service ::: BEGIN ::: Executing ::: Python Get_volume_data  ."
COMMAND="python fetch_volume_data_from_nmc_api.py 10.0.140.25 automation dangerous SSO-east-2 43434 10.0.133.252"
$COMMAND || exit_status=$?

if [ $exit_status -eq 0 ]; then
    echo "INFO ::: Amazon_NAC_OpenSearch_Service ::: FINISHED ::: Executing ::: Python Get_volume_data  ."
    

elif [ $exit_status -eq 1 ]; then
    echo "INFO ::: Amazon_NAC_OpenSearch_Service ::: FAILED ::: Executing ::: Python Get_volume_data  ."
    exit 1
fi
