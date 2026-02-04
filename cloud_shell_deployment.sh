#!/bin/bash

AWS_ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
AWS_REGION=$(aws configure get region)
export CDK_DEFAULT_ACCOUNT=$AWS_ACCOUNT_ID
export CDK_DEFAULT_REGION=$AWS_REGION
echo "$AWS_ACCOUNT_ID"
echo "$AWS_REGION"
echo "aws://$AWS_ACCOUNT_ID/$AWS_REGION"
sudo npm install -g aws-cdk
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements-deploy.txt
echo "Downloading lastest aws_wrangler lambda layer..." 
bash update_aws_wrangler.sh
cdk bootstrap "aws://$AWS_ACCOUNT_ID/$AWS_REGION"
cdk deploy

