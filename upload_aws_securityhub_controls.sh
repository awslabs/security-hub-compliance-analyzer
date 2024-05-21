#!/bin/bash

environment=$(jq -r '.context["environment"]' cdk.json)
environment+="-app-stack"
bucket=$(aws cloudformation describe-stacks --stack-name "$environment" --query 'Stacks[0].Outputs[?OutputKey==`bucketname`].OutputValue' --output text)

echo "Uploading CSV to $bucket"
response=$(aws s3api put-object \
    --bucket "$bucket" \
    --body "assets/csv/aws_securityhub_controls.csv" \
    --key "aws/ato_next_securityhub_rules_nist_800_53_rev_5/aws_securityhub_controls.csv")

echo "$response"
echo "Done uploading aws_securityhub_controls.csv to s3://$bucket/aws/ato_next_securityhub_rules_nist_800_53_rev_5/aws_securityhub_controls.csv"