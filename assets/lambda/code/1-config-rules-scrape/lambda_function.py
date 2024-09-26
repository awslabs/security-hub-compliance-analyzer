"""
File: lambda_function.py

Description: This file contains a Lambda function that will retrieve security findings data from
AWS Security Hub and export it in ASFF format and extract list of disabled security hub controls.
"""

import logging
import os
import json
import csv
import tempfile
import boto3
from botocore.exceptions import ClientError
from botocore.config import Config  # pylint: disable=E0602


# Initialize logger
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Define variables and configurations
region = os.environ["AWS_REGION"]
s3_client = boto3.client("s3", region_name=region)
bucket_name = os.environ["BUCKET_NAME"]

config = Config(retries={"max_attempts": 10, "mode": "standard"})
security_hub_client = boto3.client("securityhub", region_name=region, config=config)

def lambda_handler(event, context):
    """
    Lambda function that handles SecurityHub data processing.

    Retrieves SecurityHub findings and disabled rules files 
    from S3 for further processing.
    Args:
    event: The event data that triggered the Lambda function. 
            It is required by AWS Lambda, even if it's not used in this function.
    context: The runtime information provided by AWS Lambda. 
                It is required by AWS Lambda, even if it's not used in this function.
    """
    securityhub_findings_json_key = "shca/original_findings_in_asff/original_findings_asff.json"
    securityhub_disabled_rules_key = "shca/disabled_rules/disabled_rules.csv"

    findings = extract_securityhub_findings()
    disabled_rules = list_disabled_rules()

    # Write and upload the disabled controls to S3
    write_and_upload_disabled_rules_csv(securityhub_disabled_rules_key, disabled_rules)

    # Write and upload the findings to S3
    write_and_upload_securityhub_findings_json(securityhub_findings_json_key, findings)

    return {
        "statusCode": 200,
        "body": "Created and saved securityhub_original_findings_asff.json"
        " and securityhub_disabled_rules.csv to S3",
    }

# Get list of disabled rules from Security Hub
def list_disabled_rules():
    """
    List disabled rules from Security Hub, filtering for NIST 800-53 controls.

    Queries Security Hub for rules that are currently disabled and returns them as a list,
    but only includes those that contain "NIST" or "nist" in the StandardsControlArn.
    """
    disabled_rules = []

    try:
        # Get all enabled standards subscriptions
        subscriptions_response = security_hub_client.get_enabled_standards()

        if 'StandardsSubscriptions' not in subscriptions_response:
            logger.info("No standards subscriptions found.")
            return disabled_rules

        for subscription in subscriptions_response['StandardsSubscriptions']:
            standards_subscription_arn = subscription['StandardsSubscriptionArn']
            logger.info("Processing standards subscription: %s", standards_subscription_arn)

            # Use a paginator for describe_standards_controls
            paginator = security_hub_client.get_paginator("describe_standards_controls")

            for page in paginator.paginate(StandardsSubscriptionArn=standards_subscription_arn):
                if 'Controls' in page:
                    for control in page['Controls']:
                        if control['ControlStatus'] == 'DISABLED' and ('NIST' in control['StandardsControlArn'] or 'nist' in control['StandardsControlArn']):
                            disabled_control_id = control['StandardsControlArn'].split('/')[-1]
                            disabled_rules.append({
                                'StandardsControlArn': control['StandardsControlArn'],
                                'disabled_control_id': disabled_control_id,
                            })
                            logger.info("Disabled NIST 800-53 rule found: %s", disabled_control_id)

    except ClientError as e:
        logger.error("An error occurred while listing disabled controls: %s", str(e))

    return disabled_rules


def extract_securityhub_findings():
    """
    Extract findings from Security Hub and write to JSON.

    Queries Security Hub for latest findings using the client. 
    Dumps the findings to a JSON string and writes it to the 
    specified S3 location.
    """
    filters = {
        "ComplianceStatus": [
            {"Value": "FAILED", "Comparison": "EQUALS"},
            {"Value": "PASSED", "Comparison": "EQUALS"},
            {"Value": "WARNING", "Comparison": "EQUALS"},
            {"Value": "NOT_AVAILABLE", "Comparison": "EQUALS"},
        ],
        "RecordState": [{"Value": "ACTIVE", "Comparison": "EQUALS"}],
    }

    findings = []
    next_token = ""

    logger.info("Get Findings from AWS Security Hub.")
    while next_token is not None:
        try:
            response = security_hub_client.get_findings(
                Filters=filters,
                MaxResults=100,
                NextToken=next_token
            )

            findings.extend(response["Findings"])
            logger.info("Retrieved %s findings so far...", len(findings))

            next_token = response.get("NextToken", None)
        except ClientError as e:
            logger.error("Error getting findings: %s", str(e))
            raise e

    logger.info("Pagination complete.")
    logger.info("Total number of findings: %s", len(findings))

    return findings

def write_and_upload_disabled_rules_csv(securityhub_disabled_rules_key, disabled_rules):
    """
    Write disabled rules to CSV and upload to S3.

    Takes the list of disabled rules, dumps it to a CSV file locally, 
    then uploads it to S3.
    """
    with tempfile.NamedTemporaryFile(
        mode='w', newline='', encoding='utf-8', delete=False
    ) as csvfile:
        fieldnames = ['StandardsControlArn', 'disabled_control_id']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(disabled_rules)

        # Explicitly flush and close the file's buffer
        csvfile.flush()
        csvfile.close()

    # Reopen the file in read mode to ensure it's accessible
    with open(csvfile.name, 'r', encoding='utf-8') as file:
        pass

    # Upload the file to S3
    s3_client.upload_file(csvfile.name, bucket_name, securityhub_disabled_rules_key)
    logger.info("CSV with disabled rules uploaded to S3: %s", securityhub_disabled_rules_key)

def write_and_upload_securityhub_findings_json(securityhub_findings_json_key, findings):
    """
    Write SecurityHub findings to JSON and upload to S3.

    Dumps the findings dictionary to a JSON file locally, then uploads the file 
    to the specified S3 bucket and key. Logs a message on successful upload.
    """
    with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8', delete=False) as jsonfile:
        json.dump(findings, jsonfile)

        # Explicitly flush the file's buffer to ensure data is written to disk
        jsonfile.flush()

        # Get the file path of the temporary file
        file_path = jsonfile.name

    # Reopen the file in read mode to ensure it's accessible
    with open(file_path, 'r', encoding='utf-8') as _:
        pass

    # Upload the file to S3
    s3_client.upload_file(file_path, bucket_name, securityhub_findings_json_key)
    logger.info("ASFF JSON with findings uploaded to S3: %s", securityhub_findings_json_key)
