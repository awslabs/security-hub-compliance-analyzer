# (c) 2024 Amazon Web Services, Inc. or its affiliates. All Rights Reserved.
# This AWS Content is provided subject to the terms of the AWS Customer
# Agreement available at https://aws.amazon.com/agreement or other written
# agreement between Customer and Amazon Web Services, Inc.

#!/bin/bash

environment=$(jq -r '.context["environment"]' cdk.json)
environment+="-app-stack"
bucket=$(aws cloudformation describe-stacks --stack-name "$environment" --query 'Stacks[0].Outputs[?OutputKey==`bucketname`].OutputValue' --output text)

echo "Uploading aws_stig-main-code.zip to $bucket"
response=$(aws s3api put-object \
    --bucket "$bucket" \
    --body "assets/benchmark/aws_stig-main-code.zip" \
    --key "aws/benchmark/aws_stig-main-code.zip")

echo "$response"
echo "Done uploading aws_stig-main-code.zip to s3://$bucket/aws/benchmark/aws_stig-main-code.zip"
