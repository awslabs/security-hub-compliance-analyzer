#!/bin/bash

check_and_enable_prerequisites() {
    echo "Checking if AWS Config is enabled..."
    CONFIG_RECORDER_STATUS=$(aws configservice describe-configuration-recorder-status 2>/dev/null)
    
    if [ $? -ne 0 ] || [ -z "$CONFIG_RECORDER_STATUS" ] || [ "$(echo $CONFIG_RECORDER_STATUS | jq -r '.ConfigurationRecordersStatus | length')" -eq 0 ]; then
        echo "AWS Config is not enabled. Enabling now..."
        
        # Create service-linked role for Config
        aws iam create-service-linked-role --aws-service-name config.amazonaws.com 2>/dev/null || true
        
        # Create S3 bucket for Config if needed
        AWS_ACCOUNT_ID=$(aws sts get-caller-identity --query 'Account' --output text)
        AWS_REGION=$(aws configure get region)
        
        # Handle different partition names for different AWS environments
        PARTITION="aws"
        if [[ "$AWS_REGION" == *-gov-* ]]; then
            PARTITION="aws-us-gov"
        elif [[ "$AWS_REGION" == *-iso-* ]]; then
            PARTITION="aws-iso"
        elif [[ "$AWS_REGION" == *-isob-* ]]; then
            PARTITION="aws-iso-b"
        fi
        
        CONFIG_BUCKET_NAME="config-bucket-$AWS_ACCOUNT_ID-$AWS_REGION"
        aws s3 mb s3://$CONFIG_BUCKET_NAME --region $AWS_REGION 2>/dev/null || true
        
        # Add bucket policy for AWS Config
        echo "Adding bucket policy for AWS Config..."
        aws s3api put-bucket-policy --bucket $CONFIG_BUCKET_NAME --policy "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Sid\":\"AWSConfigBucketPermissionsCheck\",\"Effect\":\"Allow\",\"Principal\":{\"Service\":\"config.amazonaws.com\"},\"Action\":\"s3:GetBucketAcl\",\"Resource\":\"arn:$PARTITION:s3:::$CONFIG_BUCKET_NAME\"},{\"Sid\":\"AWSConfigBucketDelivery\",\"Effect\":\"Allow\",\"Principal\":{\"Service\":\"config.amazonaws.com\"},\"Action\":\"s3:PutObject\",\"Resource\":\"arn:$PARTITION:s3:::$CONFIG_BUCKET_NAME/AWSLogs/$AWS_ACCOUNT_ID/*\",\"Condition\":{\"StringEquals\":{\"s3:x-amz-acl\":\"bucket-owner-full-control\"}}}]}"
        
        # Enable Config
        CONFIG_ROLE_ARN="arn:$PARTITION:iam::$AWS_ACCOUNT_ID:role/aws-service-role/config.amazonaws.com/AWSServiceRoleForConfig"
        
        # Handle different parameters for GovCloud vs commercial regions
        if [[ "$AWS_REGION" == *-gov-* ]]; then
            aws configservice put-configuration-recorder --configuration-recorder name=default,roleARN=$CONFIG_ROLE_ARN --recording-group allSupported=true,includeGlobalResourceTypes=true
        else
            aws configservice put-configuration-recorder --configuration-recorder name=default,roleARN=$CONFIG_ROLE_ARN --recording-group allSupported=true,includeGlobalResources=true
        fi
        
        aws configservice put-delivery-channel --delivery-channel name=default,s3BucketName=$CONFIG_BUCKET_NAME
        aws configservice start-configuration-recorder --configuration-recorder-name default
        
        echo "AWS Config has been enabled."
    else
        echo "AWS Config is already enabled."
    fi
    
    echo "Checking if Security Hub is enabled..."
    SECURITY_HUB_STATUS=$(aws securityhub describe-hub 2>/dev/null)
    
    if [ $? -ne 0 ]; then
        echo "Security Hub is not enabled. Enabling now..."
        aws securityhub enable-security-hub
        echo "Security Hub has been enabled."
        # Add a longer delay to allow Security Hub to initialize
        echo "Waiting for Security Hub to initialize (15 seconds)..."
        sleep 15
    else
        echo "Security Hub is already enabled."
    fi
    
    echo "Checking if NIST 800-53 Rev. 5 standard is enabled..."
    NIST_STANDARD=$(aws securityhub get-enabled-standards | jq -r '.StandardsSubscriptions[] | select(.StandardsArn | contains("nist-800-53"))')
    
    if [ -z "$NIST_STANDARD" ]; then
        echo "NIST 800-53 Rev. 5 standard is not enabled. Enabling now..."
        AWS_REGION=$(aws configure get region)
        
        # Handle different partition names for different AWS environments
        PARTITION="aws"
        if [[ "$AWS_REGION" == *-gov-* ]]; then
            PARTITION="aws-us-gov"
        elif [[ "$AWS_REGION" == *-iso-* ]]; then
            PARTITION="aws-iso"
        elif [[ "$AWS_REGION" == *-isob-* ]]; then
            PARTITION="aws-iso-b"
        fi
        
        aws securityhub batch-enable-standards --standards-subscription-requests StandardsArn=arn:$PARTITION:securityhub:$AWS_REGION::standards/nist-800-53/v/5.0.0
        echo "NIST 800-53 Rev. 5 standard has been enabled."
    else
        echo "NIST 800-53 Rev. 5 standard is already enabled."
    fi
    
    echo "All prerequisites are now configured."
}

# Main script execution
AWS_ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
AWS_REGION=$(aws configure get region)
echo "Account ID: $AWS_ACCOUNT_ID"
echo "Region: $AWS_REGION"
echo "Target: aws://$AWS_ACCOUNT_ID/$AWS_REGION"

# Check and enable prerequisites
echo "Checking and enabling prerequisites..."
check_and_enable_prerequisites

# Install CDK and set up environment
echo "Setting up CDK environment..."
sudo npm install -g aws-cdk
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements-deploy.txt

echo "Downloading latest aws_wrangler lambda layer..." 
bash update_aws_wrangler.sh

echo "Bootstrapping CDK in account $AWS_ACCOUNT_ID, region $AWS_REGION..."
cdk bootstrap "aws://$AWS_ACCOUNT_ID/$AWS_REGION"

echo "Deploying SHCA solution..."
cdk deploy
