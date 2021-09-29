#!/bin/bash
set -e

export NACStackDestructionFailed=302
export NACStackCreationFailed=301
export NACTerraformInitFailed=303

{
    # RUN terraform init
    echo "NAC PROVISIONING ::: STARTED ::: Executing the Terraform scripts . . . . . . . . . . . ."
    COMMAND="terraform init"
    $COMMAND
    echo "NAC PROVISIONING ::: Initialized Terraform Libraries/Dependencies"
    COMMAND="terraform apply -var-file=test.tfvars -auto-approve"
    $COMMAND
    echo "NAC PROVISIONING ::: COMPLETED ::: Terraform apply . . . . . . . . . . . . . . . . . . ."

    # Get the NAC discovery lambda function name
    DISCOVERY_LAMBDA_NAME=$(aws secretsmanager get-secret-value --secret-id nac-es-internal | jq -r '.SecretString' | jq -r '.discovery_lambda_name')
    echo "DISCOVERY_LAMBDA_NAME ::: $DISCOVERY_LAMBDA_NAME"
    i_cnt=0
    ### Check If Lambda Execution Completed ?
    LAST_UPDATE_STATUS="runnung"
    while [ "$LAST_UPDATE_STATUS" != "InProgress" ]
    do
        LAST_UPDATE_STATUS=$(aws lambda get-function-configuration --function-name $DISCOVERY_LAMBDA_NAME | jq -r '.LastUpdateStatus' )
        echo "LAST_UPDATE_STATUS ::: $LAST_UPDATE_STATUS"
        if [ "$LAST_UPDATE_STATUS" == "Successful" ]; then
            echo "Lambda execution COMPLETED."
            echo "STARTED ::: CLEANUP NAC STACK and dependent resources . . . . . . . . . . . . . . . . . . . . ."
            # RUN terraform destroy to CLEANUP NAC STACK and dependent resources
            COMMAND="terraform destroy -var-file=test.tfvars -auto-approve"
            $COMMAND
            echo "COMPLETED ::: CLEANUP NAC STACK and dependent resources ! ! ! ! "
            exit 0
        elif [ "$LAST_UPDATE_STATUS" == "Failed" ]; then
            echo "Lambda execution FAILED."
            # RUN terraform destroy to CLEANUP NAC STACK and dependent resources
            COMMAND="terraform destroy -var-file=test.tfvars -auto-approve"
            $COMMAND
            echo "COMPLETED ::: CLEANUP NAC STACK and dependent resources ! ! ! ! "
            exit 0
        elif [ "$LAST_UPDATE_STATUS" == "" ]; then
            echo "Lambda Function Not found."
            exit 0
        fi
        let i_cnt=i_cnt+1
        $sleep 5
        if [ i_cnt == 10 ]; then
            echo "WARN ::: TimeOut"
            exit 1
        fi

    done
} || { 
	echo "Failed NAC Povisioning" && throw $NACStackCreationFailed
	
}

