#!/bin/bash
set -e

export NACStackCreationFailed=301

{
    echo "INFO ::: Start - Git Clone "
    ### Download NAC Provisioning Code from GitHub
    GIT_REPO="https://github.com/psahuNasuni/nac-es.git"
    GIT_REPO_NAME=$(echo ${GIT_REPO} | sed 's/.*\/\([^ ]*\/[^.]*\).*/\1/' | cut -d "/" -f 2)
    echo "$GIT_REPO"
    echo "GIT_REPO_NAME $GIT_REPO_NAME"
    pwd
    ls
    rm -rf "${GIT_REPO_NAME}"
    CLEANUP="N"

    COMMAND="git clone -b main ${GIT_REPO}"
    $COMMAND
    RESULT=$?
    if [ $RESULT -eq 0 ]; then
        echo "INFO ::: git clone SUCCESS"
        cd "${GIT_REPO_NAME}"
    elif [ $RESULT -eq 128 ]; then
        # echo "ERROR: Destination path $GIT_REPO_NAME already exists and is not an empty directory."
        exit 0
    else
        cd "${GIT_REPO_NAME}"
        echo "$GIT_REPO_NAME"
        COMMAND="git pull origin main"
        $COMMAND
    fi
    cd ..
    echo "copy TFVARS file to $(pwd)/${GIT_REPO_NAME}/nac_es.tfvars"

    cp nac_es.tfvars $(pwd)/${GIT_REPO_NAME}/nac_es.tfvars
    cd $(pwd)/${GIT_REPO_NAME}
    ##### RUN terraform init
    echo "NAC PROVISIONING ::: STARTED ::: Executing the Terraform scripts . . . . . . . . . . . ."
    COMMAND="terraform init"
    $COMMAND
    echo "NAC PROVISIONING ::: Initialized Terraform Libraries/Dependencies"
    echo "NAC PROVISIONING ::: STARTED ::: Terraform apply . . . . . . . . . . . . . . . . . . ."
    COMMAND="terraform apply -var-file=nac_es.tfvars -auto-approve"
    $COMMAND
    if [ $? -ne 0 ];then
        echo "ERROR ::: NAC Deployment failed. "
        CLEANUP="Y"
         if [ "$CLEANUP" == "Y" ]; then
            echo "Lambda execution COMPLETED."
            echo "STARTED ::: CLEANUP NAC STACK and dependent resources . . . . . . . . . . . . . . . . . . . . ."
            # RUN terraform destroy to CLEANUP NAC STACK and dependent resources
            COMMAND="terraform destroy -var-file=nac_es.tfvars -auto-approve"
            $COMMAND
            echo "COMPLETED ::: CLEANUP NAC STACK and dependent resources ! ! ! ! "
            exit 0
        fi
    fi
    echo "NAC PROVISIONING ::: Terraform apply ::: COMPLETED . . . . . . . . . . . . . . . . . . ."
    exit 11
    sleep 10
    
    ### Get the NAC discovery lambda function name
    DISCOVERY_LAMBDA_NAME=$(aws secretsmanager get-secret-value --secret-id nac-es-internal | jq -r '.SecretString' | jq -r '.discovery_lambda_name')
    echo "INFO ::: Discovery lambda name ::: $DISCOVERY_LAMBDA_NAME"
    if [ "${DISCOVERY_LAMBDA_NAME}" == "" ];then
        echo "ERROR ::: NAC Deployment failed. "
    fi

    i_cnt=0
    ### Check If Lambda Execution Completed ?
    LAST_UPDATE_STATUS="runnung"
    while [ "$LAST_UPDATE_STATUS" != "InProgress" ]; do
        LAST_UPDATE_STATUS=$(aws lambda get-function-configuration --function-name "$DISCOVERY_LAMBDA_NAME" | jq -r '.LastUpdateStatus')
        echo "LAST_UPDATE_STATUS ::: $LAST_UPDATE_STATUS"
        if [ "$LAST_UPDATE_STATUS" == "Successful" ]; then
            echo "INFO ::: Lambda execution COMPLETED. Preparing for cleanup of NAC Stack and dependent resources . . . . . . . . . . "
            CLEANUP="Y"
            break
        elif [ "$LAST_UPDATE_STATUS" == "Failed" ]; then
            echo "INFO ::: Lambda execution FAILED. Preparing for cleanup of NAC Stack and dependent resources . . . . . . . . . .  "
            CLEANUP="Y"
            break
        elif [[ "$LAST_UPDATE_STATUS" == "" || "$LAST_UPDATE_STATUS" == null ]]; then
            echo "INFO ::: NAC associated Lambda Function Not found. Possibly, the NAC Stack provisioning failed."
            CLEANUP="Y"
            break
        fi
        ((i_cnt++)) || true

        if [ $((i_cnt)) -eq 5 ]; then
            if [[ -z "${LAST_UPDATE_STATUS}" ]]; then
                echo "WARN ::: System TimeOut"
                CLEANUP="Y"
                break
            fi

        fi
    done
    echo "CleanUp Flag: $CLEANUP"
    ###################################################
    if [ "$CLEANUP" == "Y" ]; then
        echo "Lambda execution COMPLETED."
        echo "STARTED ::: CLEANUP NAC STACK and dependent resources . . . . . . . . . . . . . . . . . . . . ."
        # RUN terraform destroy to CLEANUP NAC STACK and dependent resources
        COMMAND="terraform destroy -var-file=nac_es.tfvars -auto-approve"
        $COMMAND
        echo "COMPLETED ::: CLEANUP NAC STACK and dependent resources ! ! ! ! "
        exit 0
    fi

} || {
    echo "Failed NAC Povisioning" && throw $NACStackCreationFailed

}
