#!/usr/bin/env bash

CF_STACK_NAME="avp-stack"

get_account_id() {
  ACCOUNT_ID=$(aws sts get-caller-identity \
      --query 'Account' --output text)
}

get_stack_region() {
  STACK_REGION=$(aws configure get region)
}

get_cognito_users_password() {
  local command_output

  command_output=$(aws cloudformation describe-stacks \
    --stack-name ${CF_STACK_NAME} \
    --no-paginate | jq -r '.')

  COGNITO_USERS_PASSWORD=$(echo "$command_output" \
    | jq -r '.Stacks[0].Parameters[] | select(.ParameterKey=="UserPassword").ParameterValue')
  echo "Password: $COGNITO_USERS_PASSWORD"
}

get_cognito_username_and_password() {
  local command_output

  command_output=$(aws cloudformation describe-stacks \
    --stack-name ${CF_STACK_NAME} \
    --no-paginate | jq -r '.')

  COGNITO_USERS_PASSWORD=$(echo "$command_output" \
    | jq -r '.Stacks[0].Parameters[] | select(.ParameterKey=="UserPassword").ParameterValue')
  EXTERNAL_USER_NAME1=$(echo "$command_output" \
    | jq -r '.Stacks[0].Parameters[] | select(.ParameterKey=="ExternalUser1Name").ParameterValue')
  EXTERNAL_USER_NAME2=$(echo "$command_output" \
    | jq -r '.Stacks[0].Parameters[] | select(.ParameterKey=="ExternalUser2Name").ParameterValue')
  INTERNAL_USER_NAME1=$(echo "$command_output" \
    | jq -r '.Stacks[0].Parameters[] | select(.ParameterKey=="InternalUser1Name").ParameterValue')
  INTERNAL_USER_NAME2=$(echo "$command_output" \
    | jq -r '.Stacks[0].Parameters[] | select(.ParameterKey=="InternalUser2Name").ParameterValue')
}

get_api_url_cognitouser_cognitouserpass_cognitoclientid() {
  local command_output

  command_output=$(aws cloudformation describe-stacks \
    --stack-name ${CF_STACK_NAME} \
    --no-paginate | jq -r '.')

  COGNITO_USERS_PASSWORD=$(echo "$command_output" \
    | jq -r '.Stacks[0].Parameters[] | select(.ParameterKey=="UserPassword").ParameterValue')
  EXTERNAL_USER_NAME1=$(echo "$command_output" \
    | jq -r '.Stacks[0].Parameters[] | select(.ParameterKey=="ExternalUser1Name").ParameterValue')
  EXTERNAL_USER_NAME2=$(echo "$command_output" \
    | jq -r '.Stacks[0].Parameters[] | select(.ParameterKey=="ExternalUser2Name").ParameterValue')
  INTERNAL_USER_NAME1=$(echo "$command_output" \
    | jq -r '.Stacks[0].Parameters[] | select(.ParameterKey=="InternalUser1Name").ParameterValue')
  INTERNAL_USER_NAME2=$(echo "$command_output" \
    | jq -r '.Stacks[0].Parameters[] | select(.ParameterKey=="InternalUser2Name").ParameterValue')

  API_URL=$(echo "$command_output" \
    | jq -r '.Stacks[0].Outputs[] | select(.OutputKey=="ApiGatewayDeploymentUrlApiEndpoint").OutputValue')
  INTERNAL_COGNITO_CLIENT_ID=$(echo "$command_output" \
    | jq -r '.Stacks[0].Outputs[] | select(.OutputKey=="CognitoUserPoolClientInternal").OutputValue')
  EXTERNAL_COGNITO_CLIENT_ID=$(echo "$command_output" \
    | jq -r '.Stacks[0].Outputs[] | select(.OutputKey=="CognitoUserPoolClientExternal").OutputValue')
}

get_api_url_v2_cognitouser_cognitouserpass_cognitoclientid() {
  local command_output

  command_output=$(aws cloudformation describe-stacks \
    --stack-name ${CF_STACK_NAME} \
    --no-paginate | jq -r '.')

  COGNITO_USERS_PASSWORD=$(echo "$command_output" \
    | jq -r '.Stacks[0].Parameters[] | select(.ParameterKey=="UserPassword").ParameterValue')
  EXTERNAL_USER_NAME1=$(echo "$command_output" \
    | jq -r '.Stacks[0].Parameters[] | select(.ParameterKey=="ExternalUser1Name").ParameterValue')
  EXTERNAL_USER_NAME2=$(echo "$command_output" \
    | jq -r '.Stacks[0].Parameters[] | select(.ParameterKey=="ExternalUser2Name").ParameterValue')
  INTERNAL_USER_NAME1=$(echo "$command_output" \
    | jq -r '.Stacks[0].Parameters[] | select(.ParameterKey=="InternalUser1Name").ParameterValue')
  INTERNAL_USER_NAME2=$(echo "$command_output" \
    | jq -r '.Stacks[0].Parameters[] | select(.ParameterKey=="InternalUser2Name").ParameterValue')

  API_URL=$(echo "$command_output" \
    | jq -r '.Stacks[0].Outputs[] | select(.OutputKey=="ApiGatewayDeploymentUrlApiEndpoint").OutputValue')
  INTERNAL_COGNITO_CLIENT_ID=$(echo "$command_output" \
    | jq -r '.Stacks[0].Outputs[] | select(.OutputKey=="CognitoUserPoolClientInternal").OutputValue')
  EXTERNAL_COGNITO_CLIENT_ID=$(echo "$command_output" \
    | jq -r '.Stacks[0].Outputs[] | select(.OutputKey=="CognitoUserPoolClientExternal").OutputValue')
}

get_api_url() {
  API_URL=$(aws cloudformation describe-stacks \
    --stack-name ${CF_STACK_NAME} \
    --query 'Stacks[0].Outputs[?OutputKey==`ApiGatewayDeploymentUrlApiEndpoint`].OutputValue' --output text)
}

get_login_payload_data() {

  DATA=$(cat<<EOF
{
  "AuthParameters" : {
    "USERNAME" : "$1",
    "PASSWORD" : "$2"
  },
  "AuthFlow" : "USER_PASSWORD_AUTH",
  "ClientId" : "$3"
}
EOF)
}

get_access_token() {
  get_stack_region

  ACCESS_TOKEN=$(curl -s -X POST --data "${DATA}" \
  -H 'X-Amz-Target: AWSCognitoIdentityProviderService.InitiateAuth' \
  -H 'Content-Type: application/x-amz-json-1.1' \
  https://cognito-idp."${STACK_REGION}".amazonaws.com/ | jq -r '.AuthenticationResult.IdToken')

  echo "Access Token: $ACCESS_TOKEN"
}

create_s3_bucket_for_lambdas() {
  get_account_id
  get_stack_region

  S3_BUCKET_NAME="${CF_STACK_NAME}-${ACCOUNT_ID}-${STACK_REGION}-lambdas"

  if [[ "${STACK_REGION}" == "us-east-1" ]]
  then
    aws s3api create-bucket \
      --bucket "${S3_BUCKET_NAME}" \
      --region "${STACK_REGION}" > /dev/null
  else
    aws s3api create-bucket \
      --bucket "${S3_BUCKET_NAME}" \
      --region "${STACK_REGION}" \
      --create-bucket-configuration LocationConstraint="${STACK_REGION}" > /dev/null
  fi

  aws s3 cp ./cf-lambdas/custom-auth.zip s3://"${S3_BUCKET_NAME}"
  aws s3 cp ./cf-lambdas/pets-clinic-api.zip s3://"${S3_BUCKET_NAME}" 
}

delete_s3_bucket_for_lambdas() {
  get_account_id
  get_stack_region

  S3_BUCKET_NAME="${CF_STACK_NAME}-${ACCOUNT_ID}-${STACK_REGION}-lambdas"

  aws s3 rm s3://"${S3_BUCKET_NAME}/custom-auth.zip"
  aws s3 rm s3://"${S3_BUCKET_NAME}/pets-clinic-api.zip"

  aws s3api delete-bucket \
    --bucket "${S3_BUCKET_NAME}" \
    --region "${STACK_REGION}" > /dev/null
}

check_for_function_exit_code() {
  EXIT_CODE="$1"
  MSG="$2"

  if [[ "$?" == "${EXIT_CODE}" ]]
  then
    echo "${MSG}"
  else
    echo "Error occured. Please verify your configurations and try again."
  fi
}

for var in "$@"
do
  case "$var" in
    cf-create-stack-gen-password)
      COGNITO_USER_PASS=Pa%%word-$(date +%F-%H-%M-%S)
      echo "Starting..." && echo "Generated password: ${COGNITO_USER_PASS}"
      COGNITO_USER_PASS="${COGNITO_USER_PASS}" bash ./helper.sh cf-create-stack
      ;;
    cf-create-stack-openssl-gen-password)
      COGNITO_USER_PASS=Pa%%word-$(openssl rand -hex 12)
      echo "" && echo "Generated password: ${COGNITO_USER_PASS}"
      COGNITO_USER_PASS="${COGNITO_USER_PASS}" bash ./helper.sh cf-create-stack
      ;;
    cf-create-stack)
      create_s3_bucket_for_lambdas

    echo "Creating CloudFormation Stack in region ${STACK_REGION}."
      STACK_ID=$(aws cloudformation create-stack \
        --stack-name ${CF_STACK_NAME} \
        --template-body file://infrastructure/stack-no-auth.template \
        --parameters ParameterKey=UserPassword,ParameterValue=${COGNITO_USER_PASS} \
        --capabilities CAPABILITY_NAMED_IAM \
        --query 'StackId' --output text)

      aws cloudformation wait stack-create-complete \
        --stack-name ${STACK_ID}

      check_for_function_exit_code "$?" "Successfully created CloudFormation stack."
      ;;
    cf-update-stack)
      get_cognito_users_password

      STACK_ID=$(aws cloudformation update-stack \
        --stack-name ${CF_STACK_NAME} \
        --template-body file://infrastructure/stack-with-auth.template \
        --parameters ParameterKey=UserPassword,ParameterValue=${COGNITO_USERS_PASSWORD} \
        --capabilities CAPABILITY_NAMED_IAM \
        --query 'StackId' --output text)

      aws cloudformation wait stack-update-complete \
        --stack-name ${STACK_ID}

      check_for_function_exit_code "$?" "Successfully updated CloudFormation stack."
      ;;
    cf-delete-stack)
      delete_s3_bucket_for_lambdas

      aws cloudformation delete-stack \
        --stack-name ${CF_STACK_NAME} >> /dev/null

      echo "Deleting CloudFormation stack. If you want to wait for delete complition please run command below."
      echo "bash ./helper.sh cf-delete-stack-completed"
      ;;
    cf-delete-stack-completed)
      aws cloudformation wait stack-delete-complete \
        --stack-name ${CF_STACK_NAME}

      check_for_function_exit_code "$?" "Successfully deleted CloudFormation stack."
      ;;
    open-cognito-internal-domain-ui)
      COGNITO_UI_URL=$(aws cloudformation describe-stacks \
    --stack-name ${CF_STACK_NAME} \
    --query 'Stacks[0].Outputs[?OutputKey==`CognitoHostedUiInternalDomainUrl`].OutputValue' --output text)

    get_cognito_username_and_password

      echo "Opening Cognito UI..."
      echo "URL:  ${COGNITO_UI_URL}"
      echo ""
      echo "Please use following credentials to login and validate for any internal users:"
      echo ""
      echo "Username: ${INTERNAL_USER_NAME1}"
      echo "Password: ${COGNITO_USERS_PASSWORD}"
      echo "Username: ${INTERNAL_USER_NAME2}"
      echo "Password: ${COGNITO_USERS_PASSWORD}"

      # for visual effect for user to recognize msg above
      ./helper.sh visual 6

      open "${COGNITO_UI_URL}"
      ;;
    open-cognito-external-domain-ui)
      COGNITO_UI_URL=$(aws cloudformation describe-stacks \
    --stack-name ${CF_STACK_NAME} \
    --query 'Stacks[0].Outputs[?OutputKey==`CognitoHostedUiExternalDomainUrl`].OutputValue' --output text)

      get_cognito_username_and_password

      echo "Opening Cognito UI..."
      echo "URL:  ${COGNITO_UI_URL}"
      echo ""
      echo "Please use following credentials to login and validate for any external users:"
      echo ""
      echo "Username: ${EXTERNAL_USER_NAME1}"
      echo "Password: ${COGNITO_USERS_PASSWORD}"
      echo ""
      echo "Username: ${EXTERNAL_USER_NAME2}"
      echo "Password: ${COGNITO_USERS_PASSWORD}"

      # for visual effect for user to recognize msg above
      ./helper.sh visual 6

      open "${COGNITO_UI_URL}"
      ;;
    curl-api)
      get_api_url
      APPOITMENT_API=$API_URL"/PI-T123"
      echo ""
      echo "API to check his appointment details of PI-T123"
      echo "URL: $APPOITMENT_API"
      echo "Response: "
      curl "${APPOITMENT_API}"
      echo ""

      APPOITMENT_API=$API_URL"/PI-T124"
      echo ""
      echo "API to check his appointment details of PI-T124"
      echo "URL: $APPOITMENT_API"
      echo "Response: "
      curl "${APPOITMENT_API}"
      echo ""

      APPOITMENT_API=$API_URL"/PI-T125"
      echo ""
      echo "API to check his appointment details of PI-T125"
      echo "URL: $APPOITMENT_API"
      echo "Response: "
      curl "${APPOITMENT_API}"
      echo ""
      ;;
    curl-api-invalid-token)
      get_api_url
      APPOITMENT_API=$API_URL"/PI-T123"
      echo ""
      echo "API to check his appointment details of PI-T123 with invalid token"
      curl -s -H "Authorization: Bearer aGVhZGVy.Y2xhaW1z.c2lnbmF0dXJl" "${APPOITMENT_API}"
      echo ""
      ;;
    curl-protected-external-user-api)
      echo ""
      echo "Now calling external userpool users for accessing request"
      get_api_url_cognitouser_cognitouserpass_cognitoclientid
      APPOITMENT_API=$API_URL"/PI-T123"
      echo "User: $EXTERNAL_USER_NAME1"
      echo "Password: $COGNITO_USERS_PASSWORD"
      echo "Resource: PI-T123"
      echo "URL: $APPOITMENT_API"
      get_login_payload_data $EXTERNAL_USER_NAME1 $COGNITO_USERS_PASSWORD $EXTERNAL_COGNITO_CLIENT_ID
      echo ""
      echo "Authenticating to get access_token..."
      get_access_token
      echo ""
      echo "Response: "
      curl -s -H "Authorization: Bearer ${ACCESS_TOKEN}" -H "ClientType: external" "${APPOITMENT_API}"
      echo ""

      APPOITMENT_API=$API_URL"/PI-T123"
      echo ""
      echo "User: $EXTERNAL_USER_NAME2"
      echo "Password $COGNITO_USERS_PASSWORD"
      echo "Resource: PI-T123"
      echo "URL: $APPOITMENT_API"
      get_login_payload_data $EXTERNAL_USER_NAME2 $COGNITO_USERS_PASSWORD $EXTERNAL_COGNITO_CLIENT_ID
      echo ""
      echo "Authenticating to get access_token..."
      get_access_token
      echo ""
      echo "Response: "
      curl -s -H "Authorization: Bearer ${ACCESS_TOKEN}" -H "ClientType: external" "${APPOITMENT_API}"
      echo ""

      APPOITMENT_API=$API_URL"/PI-T124"
      echo ""
      echo "User: $EXTERNAL_USER_NAME2"
      echo "Password $COGNITO_USERS_PASSWORD"
      echo "Resource: PI-T124"
      echo "URL: $APPOITMENT_API"
      get_login_payload_data $EXTERNAL_USER_NAME2 $COGNITO_USERS_PASSWORD $EXTERNAL_COGNITO_CLIENT_ID
      echo ""
      echo "Authenticating to get access_token..."
      get_access_token
      echo ""
      echo "Response: "
      curl -s -H "Authorization: Bearer ${ACCESS_TOKEN}" -H "ClientType: external" "${APPOITMENT_API}"
      echo ""
      ;;
    curl-protected-internal-user-api)
      echo ""
      echo "Getting API URL, Cognito Usernames, Cognito Users Password and Cognito ClientId..."
      get_api_url_cognitouser_cognitouserpass_cognitoclientid
      APPOITMENT_API=$API_URL"/PI-T123"
      echo "User: $INTERNAL_USER_NAME1"
      echo "Password: $COGNITO_USERS_PASSWORD"
      echo "Resource: PI-T123"
      echo "URL: $APPOITMENT_API"
      get_login_payload_data $INTERNAL_USER_NAME1 $COGNITO_USERS_PASSWORD $INTERNAL_COGNITO_CLIENT_ID
      echo ""
      echo "Authenticating to get access_token..."
      get_access_token
      echo ""
      echo "Response: "
      curl -s -H "Authorization: Bearer ${ACCESS_TOKEN}" -H "ClientType: internal" "${APPOITMENT_API}"
      echo ""

      echo ""
      APPOITMENT_API=$API_URL"/PI-T123"
      echo "User: $INTERNAL_USER_NAME2"
      echo "Password: $COGNITO_USERS_PASSWORD"
      echo "Resource: PI-T123"
      echo "URL: $APPOITMENT_API"
      get_login_payload_data $INTERNAL_USER_NAME2 $COGNITO_USERS_PASSWORD $INTERNAL_COGNITO_CLIENT_ID
      echo ""
      echo "Authenticating to get access_token..."
      get_access_token
      echo ""
      echo "Response: "
      curl -s -H "Authorization: Bearer ${ACCESS_TOKEN}" -H "ClientType: internal" "${APPOITMENT_API}"
      echo ""

      echo ""
      APPOITMENT_API=$API_URL"/PI-T125"
      echo "User: $INTERNAL_USER_NAME2"
      echo "Password: $COGNITO_USERS_PASSWORD"
      echo "Resource: PI-T125"
      echo "URL: $APPOITMENT_API"
      get_login_payload_data $INTERNAL_USER_NAME2 $COGNITO_USERS_PASSWORD $INTERNAL_COGNITO_CLIENT_ID
      echo ""
      echo "Authenticating to get access_token..."
      get_access_token
      echo ""
      echo "Response: "
      curl -s -H "Authorization: Bearer ${ACCESS_TOKEN}" -H "ClientType: internal" "${APPOITMENT_API}"
      echo ""
      ;;
    curl-protected-api-not-allowed-endpoint)
      echo "Getting API URL, Cognito Username, Cognito Users Password and Cognito ClientId..."
      get_api_url_v2_cognitouser_cognitouserpass_cognitoclientid

      get_login_payload_data
      echo "Authenticating to get access_token..."
      get_access_token

      echo "Making api call..."
      curl -s -H "Authorization: Bearer ${ACCESS_TOKEN}" "${API_URL_V2}"
      echo ""
      ;;
    create-s3-bucket)
      create_s3_bucket_for_lambdas
      ;;
    delete-s3-bucket)
      delete_s3_bucket_for_lambdas
      ;;
    package-custom-auth)
      cd ./custom-auth
      pip3 install -r requirements.txt --target ./package/dependencies
      cd ./package
      zip -r ../custom-auth.zip . > /dev/null
      cd .. && zip -g custom-auth.zip lambda.py
      mv ./custom-auth.zip ../cf-lambdas
      rm -r ./package
      echo "Successfully completed packaging custom-auth."
      ;;
    package-pets-clinic-api)
      cd ./pets-clinic-api
      zip pets-clinic-api.zip lambda.py && mv pets-clinic-api.zip ../cf-lambdas
      echo "Successfully completed packaging pets-clinic-api."
      ;;
    package-lambda-functions)
      mkdir -p cf-lambdas
      bash ./helper.sh package-custom-auth
      bash ./helper.sh package-pets-clinic-api

      echo "Successfully completed packaging files."
      ;;
    visual)
      for ((i=1;i<=${2};i++));
      do
       sleep 0.5 && echo -n "."
      done
      ;;
    *)
      ;;
  esac
done
