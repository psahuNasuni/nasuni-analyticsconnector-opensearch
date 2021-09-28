########################################################
##  Developed By  :   Pradeepta Kumar Sahu
##  Project       :   Nasuni ElasticSearch Integration
##  Organization  :   Nasuni - Community Tools   
#########################################################

data "aws_s3_bucket" "discovery_source_bucket" {
  bucket = local.discovery_source_bucket
}
data "aws_secretsmanager_secret" "user_secrets" {
  name = var.user_secret
}
data "aws_secretsmanager_secret_version" "current_user_secrets" {
  secret_id = data.aws_secretsmanager_secret.user_secrets.id
}

locals {
  lambda_code_file_name_without_extension = "NAC_Discovery"
  lambda_code_extension                   = ".py"
  handler                                 = "lambda_handler"
  discovery_source_bucket                 = jsondecode(nonsensitive(data.aws_secretsmanager_secret_version.current_user_secrets.secret_string))["destination_bucket"]
  resource_name_prefix                    = "nct-NCE-lambda"
  prams = merge(
    var.user_parameters,
    {
      ###################### Read input Parameters from TFVARS file #####################
      SourceBucketAccessKeyID          = data.local_file.accZes.content
      SourceBucketSecretAccessKey      = data.local_file.secRet.content
      DestinationBucketAccessKeyID     = data.local_file.accZes.content
      DestinationBucketSecretAccessKey = data.local_file.secRet.content

      ###################### Read input Parameters from Secret Manager #####################
      ProductKey          = jsondecode(nonsensitive(data.aws_secretsmanager_secret_version.current_user_secrets.secret_string))["nac_product_key"]
      VolumeKeyParameter  = jsondecode(nonsensitive(data.aws_secretsmanager_secret_version.current_user_secrets.secret_string))["volume_key"]
      VolumeKeyPassphrase = jsondecode(nonsensitive(data.aws_secretsmanager_secret_version.current_user_secrets.secret_string))["volume_key_passphrase"]
      DestinationBucket   = jsondecode(nonsensitive(data.aws_secretsmanager_secret_version.current_user_secrets.secret_string))["destination_bucket"]

      ###################### Read input Parameters from NMC API #####################
      UniFSTOCHandle = data.local_file.toc.content
      SourceBucket   = data.local_file.bkt.content

      # Read input Parameters from Parameter Store
      /* VolumeKeyPassphrase               = jsondecode(data.aws_ssm_parameter.volume_data.*.value)
      /* VolumeKeyPassphrase               = nonsensitive(jsondecode(jsonencode(data.aws_ssm_parameter.volume_data.value))) */
      ############# Hard coding Parameters ##########################################
      StartingPoint        = "/"
      IncludeFilterPattern = "*"
      IncludeFilterType    = "glob"
      ExcludeFilterPattern = ""
      ExcludeFilterType    = "glob"
      MinFileSizeFilter    = "0b"
      MaxFileSizeFilter    = "500gb"
      PrevUniFSTOCHandle   = ""
      DestinationPrefix    = "/NCT/NCE/${var.volume_name}/${data.local_file.toc.content}"
      MaxInvocations       = "900"
    },
  )
}
resource "random_id" "nac_unique_stack_id" {
  byte_length = 6
}
resource "aws_cloudformation_stack" "nac_stack" {
  count = module.this.enabled ? 1 : 0

  name               = "nct-NCE-NasuniAnalyticsConnector-${random_id.nac_unique_stack_id.hex}"
  tags               = module.this.tags
  template_body      = file("${path.cwd}/nac-cf.template.yaml")
  parameters         = local.prams
  capabilities       = var.capabilities
  on_failure         = var.on_failure
  timeout_in_minutes = var.timeout_in_minutes
  policy_body        = var.policy_body

  # provisioner "local-exec" {
  #   command = "rm -rf *.txt"
  # }
  depends_on = [data.local_file.accZes,
    data.local_file.secRet,
    aws_lambda_function.lambda_function,
    aws_secretsmanager_secret_version.internal_secret_u 
    ]
}

################### START - NAC Discovery Lambda ####################################################
data "archive_file" "lambda_zip" {
  type        = "zip"
  source_dir  = "nac-discovery-py/"
  output_path = "${local.lambda_code_file_name_without_extension}.zip"
}

resource "aws_lambda_function" "lambda_function" {
  role             = aws_iam_role.lambda_exec_role.arn
  handler          = "${local.lambda_code_file_name_without_extension}.${local.handler}"
  runtime          = var.runtime
  filename         = "${local.lambda_code_file_name_without_extension}.zip"
  function_name    = "${local.resource_name_prefix}-${local.lambda_code_file_name_without_extension}-${random_id.nac_unique_stack_id.hex}"
  source_code_hash = data.archive_file.lambda_zip.output_base64sha256
  timeout          = 20

  tags = {
    Name            = "${local.resource_name_prefix}-${local.lambda_code_file_name_without_extension}-${random_id.nac_unique_stack_id.hex}"
    Application     = "Nasuni Analytics Connector with Elasticsearch"
    Developer       = "Nasuni"
    PublicationType = "Nasuni Community Tool"
    Version         = "V 0.1"
  }
  depends_on = [
    aws_iam_role_policy_attachment.lambda_logging,
    aws_iam_role_policy_attachment.s3_GetObject_access,
    aws_iam_role_policy_attachment.ESHttpPost_access,
    aws_iam_role_policy_attachment.GetSecretValue_access,
    aws_cloudwatch_log_group.lambda_log_group,
    data.local_file.accZes,
    data.local_file.secRet,
    data.local_file.v_guid,
    data.local_file.bkt,
    data.local_file.toc,
  ]

}

resource "aws_secretsmanager_secret_version" "internal_secret_u" {
  secret_id     = data.aws_secretsmanager_secret.internal_secret.id
  secret_string = jsonencode(local.secret_data_to_update)
  depends_on = [
    aws_iam_role.lambda_exec_role,
    aws_lambda_function.lambda_function,
  ]
}

locals {
  secret_data_to_update = {
    # last-run = timestamp()
    root_handle               = data.local_file.toc.content
    discovery_source_bucket   = jsondecode(nonsensitive(data.aws_secretsmanager_secret_version.current_user_secrets.secret_string))["destination_bucket"]
    es_url                    = jsondecode(nonsensitive(data.aws_secretsmanager_secret_version.internal_secret.secret_string))["es_url"]
    nac_stack                 = "nct-NCE-NasuniAnalyticsConnector-${random_id.nac_unique_stack_id.hex}"
    discovery_lambda_role_arn = aws_iam_role.lambda_exec_role.arn
    aws_region                = var.region
    user_secret_name          = var.user_secret
    volume_name               = var.volume_name
    web_access_appliance_address	= jsondecode(nonsensitive(data.aws_secretsmanager_secret_version.current_user_secrets.secret_string))["web_access_appliance_address"]
    destination_prefix        = "/NCT/NCE/${var.volume_name}/${data.local_file.toc.content}"
    /* external_share_volume_name = data.local_file.external_share_volume_name.content
    external_share_url = data.local_file.external_share_url.content */
    external_share_url = var.external_share_url
  }
}


resource "aws_iam_role" "lambda_exec_role" {
  name        = "${local.resource_name_prefix}-lambda_exec_role-${local.lambda_code_file_name_without_extension}-${random_id.nac_unique_stack_id.hex}"
  path        = "/"
  description = "Allows Lambda Function to call AWS services on your behalf."

  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Service": "lambda.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
EOF

  tags = {
    Name            = "${local.resource_name_prefix}-lambda_exec-${local.lambda_code_file_name_without_extension}-${random_id.nac_unique_stack_id.hex}"
    Application     = "Nasuni Analytics Connector with Elasticsearch"
    Developer       = "Nasuni"
    PublicationType = "Nasuni Community Tool"
    Version         = "V 0.1"
  }
}

############## CloudWatch Integration for Lambda ######################
resource "aws_cloudwatch_log_group" "lambda_log_group" {
  name              = "/aws/lambda/${local.resource_name_prefix}-${local.lambda_code_file_name_without_extension}-${random_id.nac_unique_stack_id.hex}"
  retention_in_days = 14

  tags = {
    Name            = "${local.resource_name_prefix}-lambda_log_group-${local.lambda_code_file_name_without_extension}-${random_id.nac_unique_stack_id.hex}"
    Application     = "Nasuni Analytics Connector with Elasticsearch"
    Developer       = "Nasuni"
    PublicationType = "Nasuni Community Tool"
    Version         = "V 0.1"
  }
}

# AWS Lambda Basic Execution Role
resource "aws_iam_policy" "lambda_logging" {
  name        = "${local.resource_name_prefix}-lambda_logging_policy-${local.lambda_code_file_name_without_extension}-${random_id.nac_unique_stack_id.hex}"
  path        = "/"
  description = "IAM policy for logging from a lambda"

  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": [
        "logs:CreateLogGroup",
        "logs:CreateLogStream",
        "logs:PutLogEvents"
      ],
      "Resource": "arn:aws:logs:*:*:*",
      "Effect": "Allow"
    }
  ]
}
EOF
  tags = {
    Name            = "${local.resource_name_prefix}-lambda_logging_policy-${local.lambda_code_file_name_without_extension}-${random_id.nac_unique_stack_id.hex}"
    Application     = "Nasuni Analytics Connector with Elasticsearch"
    Developer       = "Nasuni"
    PublicationType = "Nasuni Community Tool"
    Version         = "V 0.1"
  }
}

resource "aws_iam_role_policy_attachment" "lambda_logging" {
  role       = aws_iam_role.lambda_exec_role.name
  policy_arn = aws_iam_policy.lambda_logging.arn
}

############## IAM policy for accessing S3 from a lambda ######################
resource "aws_iam_policy" "s3_GetObject_access" {
  name        = "${local.resource_name_prefix}-s3_GetObject_access_policy-${local.lambda_code_file_name_without_extension}-${random_id.nac_unique_stack_id.hex}"
  path        = "/"
  description = "IAM policy for accessing S3 from a lambda"

  policy = <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "s3:GetObject"
            ],
            "Resource": "arn:aws:s3:::*"
        }
    ]
}
EOF
  tags = {
    Name            = "${local.resource_name_prefix}-s3_GetObject_access_policy-${local.lambda_code_file_name_without_extension}-${random_id.nac_unique_stack_id.hex}"
    Application     = "Nasuni Analytics Connector with Elasticsearch"
    Developer       = "Nasuni"
    PublicationType = "Nasuni Community Tool"
    Version         = "V 0.1"
  }

}

resource "aws_iam_role_policy_attachment" "s3_GetObject_access" {
  role       = aws_iam_role.lambda_exec_role.name
  policy_arn = aws_iam_policy.s3_GetObject_access.arn
}

############## IAM policy for accessing ElasticSearch Domain from a lambda ######################
resource "aws_iam_policy" "ESHttpPost_access" {
  name        = "${local.resource_name_prefix}-ESHttpPost_access_policy-${local.lambda_code_file_name_without_extension}-${random_id.nac_unique_stack_id.hex}"
  path        = "/"
  description = "IAM policy for accessing ElasticSearch Domain from a lambda"

  policy = <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "es:ESHttpPost"
            ],
            "Resource": "*"
        }
    ]
}
EOF
  tags = {
    Name            = "${local.resource_name_prefix}-ESHttpPost_access_policy-${local.lambda_code_file_name_without_extension}-${random_id.nac_unique_stack_id.hex}"
    Application     = "Nasuni Analytics Connector with Elasticsearch"
    Developer       = "Nasuni"
    PublicationType = "Nasuni Community Tool"
    Version         = "V 0.1"
  }
}

resource "aws_iam_role_policy_attachment" "ESHttpPost_access" {
  role       = aws_iam_role.lambda_exec_role.name
  policy_arn = aws_iam_policy.ESHttpPost_access.arn
}

############## IAM policy for accessing Secret Manager from a lambda ######################
resource "aws_iam_policy" "GetSecretValue_access" {
  name        = "${local.resource_name_prefix}-GetSecretValue_access_policy-${local.lambda_code_file_name_without_extension}-${random_id.nac_unique_stack_id.hex}"
  path        = "/"
  description = "IAM policy for accessing secretmanager from a lambda"

  policy = <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "VisualEditor0",
            "Effect": "Allow",
            "Action": "secretsmanager:GetSecretValue",
            "Resource": "${data.aws_secretsmanager_secret.user_secrets.arn}"
        },
        {
            "Sid": "VisualEditor1",
            "Effect": "Allow",
            "Action": "secretsmanager:GetSecretValue",
            "Resource": "${data.aws_secretsmanager_secret.internal_secret.arn}"
        }
    ]
}
EOF
  tags = {
    Name            = "${local.resource_name_prefix}-GetSecretValue_access_policy-${local.lambda_code_file_name_without_extension}-${random_id.nac_unique_stack_id.hex}"
    Application     = "Nasuni Analytics Connector with Elasticsearch"
    Developer       = "Nasuni"
    PublicationType = "Nasuni Community Tool"
    Version         = "V 0.1"
  }
}

resource "aws_iam_role_policy_attachment" "GetSecretValue_access" {
  role       = aws_iam_role.lambda_exec_role.name
  policy_arn = aws_iam_policy.GetSecretValue_access.arn
}

################################### Attaching AWS Managed IAM Policies ##############################################################

data "aws_iam_policy" "CloudWatchFullAccess" {
  arn = "arn:aws:iam::aws:policy/CloudWatchFullAccess"
}

resource "aws_iam_role_policy_attachment" "CloudWatchFullAccess" {
  role       = aws_iam_role.lambda_exec_role.name
  policy_arn = data.aws_iam_policy.CloudWatchFullAccess.arn
}

data "aws_iam_policy" "AWSLambdaVPCAccessExecutionRole" {
  arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaVPCAccessExecutionRole"
}

resource "aws_iam_role_policy_attachment" "AWSLambdaVPCAccessExecutionRole" {
  role       = aws_iam_role.lambda_exec_role.name
  policy_arn = data.aws_iam_policy.AWSLambdaVPCAccessExecutionRole.arn
}

data "aws_iam_policy" "AWSCloudFormationFullAccess" {
  arn = "arn:aws:iam::aws:policy/AWSCloudFormationFullAccess"
}

resource "aws_iam_role_policy_attachment" "AWSCloudFormationFullAccess" {
  role       = aws_iam_role.lambda_exec_role.name
  policy_arn = data.aws_iam_policy.AWSCloudFormationFullAccess.arn
}

data "aws_iam_policy" "AmazonS3FullAccess" {
  arn = "arn:aws:iam::aws:policy/AmazonS3FullAccess"
}

resource "aws_iam_role_policy_attachment" "AmazonS3FullAccess" {
  role       = aws_iam_role.lambda_exec_role.name
  policy_arn = data.aws_iam_policy.AmazonS3FullAccess.arn
}

data "aws_iam_policy" "AmazonEC2FullAccess" {
  arn = "arn:aws:iam::aws:policy/AmazonEC2FullAccess"
}

resource "aws_iam_role_policy_attachment" "AmazonEC2FullAccess" {
  role       = aws_iam_role.lambda_exec_role.name
  policy_arn = data.aws_iam_policy.AmazonEC2FullAccess.arn
}

data "aws_iam_policy" "AmazonESFullAccess" {
  arn = "arn:aws:iam::aws:policy/AmazonESFullAccess"
}

resource "aws_iam_role_policy_attachment" "AmazonESFullAccess" {
  role       = aws_iam_role.lambda_exec_role.name
  policy_arn = data.aws_iam_policy.AmazonESFullAccess.arn
}

################# Trigger Lambda Function on S3 Event ######################
resource "aws_lambda_permission" "allow_bucket" {
  statement_id  = "AllowExecutionFromS3Bucket"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.lambda_function.arn
  principal     = "s3.amazonaws.com"
  source_arn    = data.aws_s3_bucket.discovery_source_bucket.arn

  depends_on = [aws_lambda_function.lambda_function]
}

resource "aws_s3_bucket_notification" "bucket_notification" {
  bucket = data.aws_s3_bucket.discovery_source_bucket.id

  lambda_function {
    lambda_function_arn = aws_lambda_function.lambda_function.arn
    events              = ["s3:ObjectCreated:*"]
    filter_prefix       = ""
    # filter_prefix       = "/NCT/NCE/${var.volume_name}/${data.local_file.toc.content}/"
    filter_suffix       = ""
  }
  depends_on = [aws_lambda_permission.allow_bucket]
  /* depends_on = [aws_lambda_permission.allow_bucket,data.local_file.toc] */
}

########################################## Internal Secret  ########################################################

data "aws_secretsmanager_secret" "internal_secret" {
  name = var.internal_secret
}
data "aws_secretsmanager_secret_version" "internal_secret" {
  secret_id = data.aws_secretsmanager_secret.internal_secret.id
}

################################################# END LAMBDA########################################################

resource "random_id" "r_id" {
  byte_length = 1
}
resource "null_resource" "secRet" {
  provisioner "local-exec" {
    command = "aws configure get aws_secret_access_key --profile ${var.aws_profile} > Zsecret_${random_id.r_id.dec}.txt"
  }
  provisioner "local-exec" {
    when    = destroy
    command = "rm -rf Zsecret_*.txt"
  }
}
resource "null_resource" "accZes" {
  provisioner "local-exec" {
    command = "aws configure get aws_access_key_id --profile ${var.aws_profile} > Zaccess_${random_id.r_id.dec}.txt"
  }
  provisioner "local-exec" {
    when    = destroy
    command = "rm -rf Zaccess_*.txt"
  }
}
data "local_file" "secRet" {
  filename   = "${path.cwd}/Zsecret_${random_id.r_id.dec}.txt"
  depends_on = [null_resource.secRet]
}

data "local_file" "accZes" {
  filename   = "${path.cwd}/Zaccess_${random_id.r_id.dec}.txt"
  depends_on = [null_resource.accZes]
}

############################## NMC API CALL ###############################

locals {
  nmc_api_endpoint = jsondecode(nonsensitive(data.aws_secretsmanager_secret_version.current_user_secrets.secret_string))["nmc_api_endpoint"]
  nmc_api_username = jsondecode(nonsensitive(data.aws_secretsmanager_secret_version.current_user_secrets.secret_string))["nmc_api_username"]
  nmc_api_password = jsondecode(nonsensitive(data.aws_secretsmanager_secret_version.current_user_secrets.secret_string))["nmc_api_password"]
}

resource "null_resource" "nmc_api_data" {
  provisioner "local-exec" {
    command = "python3 fetch_volume_data_from_nmc_api.py ${local.nmc_api_endpoint} ${local.nmc_api_username} ${local.nmc_api_password} ${var.volume_name} ${random_id.r_id.dec}"
  }
  provisioner "local-exec" {
    when    = destroy
    command = "rm -rf nmc_api_data_*.txt"
  }
}

# data "local_file" "external_share_url" {
#   filename   = "${path.cwd}/nmc_api_data_external_share_url_${random_id.r_id.dec}.txt"
#   depends_on = [null_resource.nmc_api_data]
# }
# data "local_file" "external_share_volume_name" {
#   filename   = "${path.cwd}/nmc_api_data_external_share_volume_name_${random_id.r_id.dec}.txt"
#   depends_on = [null_resource.nmc_api_data]
# }


data "local_file" "toc" {
  filename   = "${path.cwd}/nmc_api_data_root_handle_${random_id.r_id.dec}.txt"
  depends_on = [null_resource.nmc_api_data]
}


output "root_handle" {
  value      = data.local_file.toc.content
  depends_on = [data.local_file.toc]
}

data "local_file" "bkt" {
  filename   = "${path.cwd}/nmc_api_data_source_bucket_${random_id.r_id.dec}.txt"
  depends_on = [null_resource.nmc_api_data]
}


output "source_bucket" {
  value      = data.local_file.bkt.content
  depends_on = [data.local_file.bkt]
}

data "local_file" "v_guid" {
  filename   = "${path.cwd}/nmc_api_data_v_guid_${random_id.r_id.dec}.txt"
  depends_on = [null_resource.nmc_api_data]
}


output "volume_guid" {
  value      = data.local_file.v_guid.content
  depends_on = [data.local_file.v_guid]
}

############################################################################