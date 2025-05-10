# -----
# File: /Makefile
# Created Date: Wednesday August 16th 2023
# -----
#

VENV           = .venv
VENV_PYTHON    = $(VENV)/bin/python
SYSTEM_PYTHON  = $(or $(shell which python3), $(shell which python))
# If virtualenv exists, use it. If not, find python using PATH
PYTHON         = $(or $(wildcard $(VENV_PYTHON)), $(SYSTEM_PYTHON))
SHELL := /bin/bash

.PHONY: test init deploy check-prerequisites enable-prerequisites deploy-with-prerequisites

venv/bin/activate: requirements-development.txt requirements-deploy.txt
	$(PYTHON) -m venv $(VENV)
	$(SHELL) -c "source $(VENV)/bin/activate; pip install --requirement requirements-development.txt"
	$(SHELL) -c "source $(VENV)/bin/activate; pip install --requirement requirements-deploy.txt"

init: venv/bin/activate

check-prerequisites:
	@echo "Checking prerequisites..."
	@AWS_ACCOUNT_ID=$$(aws sts get-caller-identity --query 'Account' --output text) && \
	AWS_REGION=$$(aws configure get region) && \
	echo "Account: $$AWS_ACCOUNT_ID, Region: $$AWS_REGION" && \
	(aws configservice describe-configuration-recorder-status >/dev/null 2>&1 || (echo "❌ AWS Config is not enabled" && exit 1)) && \
	(aws securityhub describe-hub >/dev/null 2>&1 || (echo "❌ Security Hub is not enabled" && exit 1)) && \
	(aws securityhub get-enabled-standards | grep -q "nist-800-53" || (echo "❌ NIST 800-53 Rev. 5 standard is not enabled" && exit 1)) && \
	echo "✅ All prerequisites are met"

enable-prerequisites:
	@echo "Enabling prerequisites..."
	@AWS_ACCOUNT_ID=$$(aws sts get-caller-identity --query 'Account' --output text) && \
	AWS_REGION=$$(aws configure get region) && \
	echo "Account: $$AWS_ACCOUNT_ID, Region: $$AWS_REGION" && \
	echo "Creating service-linked role for Config..." && \
	aws iam create-service-linked-role --aws-service-name config.amazonaws.com 2>/dev/null || true && \
	echo "Determining AWS partition..." && \
	PARTITION="aws" && \
	if [[ "$$AWS_REGION" == *-gov-* ]]; then PARTITION="aws-us-gov"; fi && \
	if [[ "$$AWS_REGION" == *-iso-* ]]; then PARTITION="aws-iso"; fi && \
	if [[ "$$AWS_REGION" == *-isob-* ]]; then PARTITION="aws-iso-b"; fi && \
	echo "Using partition: $$PARTITION" && \
	echo "Creating S3 bucket for Config..." && \
	CONFIG_BUCKET_NAME="config-bucket-$$AWS_ACCOUNT_ID-$$AWS_REGION" && \
	aws s3 mb s3://$$CONFIG_BUCKET_NAME --region $$AWS_REGION 2>/dev/null || true && \
	echo "Enabling AWS Config..." && \
	CONFIG_ROLE_ARN="arn:$$PARTITION:iam::$$AWS_ACCOUNT_ID:role/aws-service-role/config.amazonaws.com/AWSServiceRoleForConfig" && \
	aws configservice put-configuration-recorder --configuration-recorder name=default,roleARN=$$CONFIG_ROLE_ARN --recording-group allSupported=true,includeGlobalResources=true && \
	aws configservice put-delivery-channel --delivery-channel name=default,s3BucketName=$$CONFIG_BUCKET_NAME && \
	aws configservice start-configuration-recorder --configuration-recorder-name default && \
	echo "Enabling Security Hub..." && \
	aws securityhub enable-security-hub || true && \
	echo "Enabling NIST 800-53 Rev. 5 standard..." && \
	aws securityhub batch-enable-standards --standards-subscription-requests StandardsArn=arn:$$PARTITION:securityhub:$$AWS_REGION::standards/nist-800-53/v/5.0.0 || true && \
	echo "✅ All prerequisites are now enabled"

deploy:
	$(SHELL) update_aws_wrangler.sh
	cdk deploy
	$(SHELL) upload_aws_securityhub_controls.sh

deploy-with-prerequisites: enable-prerequisites
	$(SHELL) update_aws_wrangler.sh
	cdk deploy
	$(SHELL) upload_aws_securityhub_controls.sh

clean:
	rm -rf __pycache__
	rm -rf .venv
	rm -rf cdk.out
	rm -rf assets/lambda/layers/awswrangler/*.zip
