#!/bin/bash

# Fetch the environment and stack name
environment=$(jq -r '.context["environment"]' cdk.json)
environment+="-app-stack"
bucket=$(aws cloudformation describe-stacks --stack-name "$environment" --query 'Stacks[0].Outputs[?OutputKey==`bucketname`].OutputValue' --output text)

# Check if bucket name is retrieved
if [ -z "$bucket" ]; then
    echo "Bucket name not found."
    exit 1
fi

echo "Bucket name: $bucket"

echo "Uploading aws_stig_assessment.sh to $bucket"
response=$(aws s3api put-object \
    --bucket "$bucket" \
    --body "assets/benchmark/aws_stig_assessment.sh" \
    --key "aws/benchmark/aws_stig_assessment.sh")

echo "$response"
echo "Done uploading  aws_stig_assessment.sh to s3://$bucket/aws/benchmark/aws_stig_assessment.sh"

# 1. Download the script from S3
aws s3 cp "s3://$bucket/aws/benchmark/aws_stig_assessment.sh" aws_stig_assessment.sh
echo "Done downloading  aws_stig_assessment.sh from s3://$bucket/aws/benchmark/aws_stig_assessment.sh"


# 2. Use sed to replace 'bucket_name' with the actual bucket name
sed -i "s/bucket_name/$bucket/g" aws_stig_assessment.sh
echo "Done updating bucket_name in  aws_stig_assessment.sh"

# 3. Upload the modified script back to S3
aws s3 cp aws_stig_assessment.sh "s3://$bucket/aws/benchmark/aws_stig_assessment.sh"
echo "Done uploading modified aws_stig_assessment.sh to s3://$bucket/aws/benchmark/aws_stig_assessment.sh"
