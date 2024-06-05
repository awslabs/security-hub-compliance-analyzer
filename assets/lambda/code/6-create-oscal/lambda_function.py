"""
lambda_function.py

This file contains a Lambda function that converts AWS Security Hub findings to the 
Open Security Control Assessment Language (OSCAL) format.

The lambda_handler function is invoked by AWS Lambda in response to scheduled 
events. It loads findings data from an S3 bucket, converts each finding to OSCAL
format, and saves the converted findings back to S3. 

The convert_time_to_unix and convert_to_oscal functions contain the logic to 
standardize timestamps and map fields between the SecurityHub and OSCAL formats.

Environment Variables:
  - AWS_REGION: The AWS region
  - BUCKET_NAME: The name of the S3 bucket
"""

import json
import logging
import os
import csv  # Import the csv module
# from dateutil.parser import parse
# from dateutil.parser import ParserError
import boto3

logger = logging.getLogger()
logger.setLevel(logging.INFO)
region = os.environ["AWS_REGION"]
bucket_name = os.environ["BUCKET_NAME"]

s3_client = boto3.client("s3", region_name=region)

def convert_to_oscal(csv_data):
    """
    Convert an AWS Security Hub Control Summary to the OSCAL format.
    """
    oscal_data = []

    reader = csv.DictReader(csv_data.splitlines())
    for row in reader:
        status = row["compliance_status"]
        if status.lower() == "partially compliant":
            status = "non-compliant"

        oscal_entry = {
            "control": {
                "id": row["compliance_control_id"],
                "description": row["narrative"],
            },
            "result": {
                "status": status,
                "percentage": row["percentage"],
                "observation_timestamp": row["lastobservedat"],
            },
            "rule": {"id": row["rule_id"].split(", ")},
        }
        oscal_data.append(oscal_entry)

    return oscal_data


def lambda_handler(event, context):  # pylint: disable=unused-argument
    """
    Handle invocation of the Lambda function.
    """
    securityhub_summary_csv_key = "shca/control_summary_of_findings/nist80053_findings_summary.csv"
    securityhub_findings_oscal_key = "shca/findings_in_oscal/original_findings_oscal.json"
    logger.info("Loading the AWS Security Hub Control Summary from S3.")
    summary_obj = s3_client.get_object(
        Bucket=bucket_name, Key=securityhub_summary_csv_key
    )
    summary_data = summary_obj["Body"].read().decode("utf-8")

    logger.info("Converting AWS Security Hub Control Summary to OSCAL format.")
    oscal_data = convert_to_oscal(summary_data)

    logger.info("Saving converted OSCAL AWS Security Hub Control Summary to S3.")
    s3_client.put_object(
        Body=json.dumps(oscal_data, indent=4),
        Bucket=bucket_name,
        Key=securityhub_findings_oscal_key,
    )

    logger.info("Converted AWS Security Hub Control Summary to OSCAL format.")

    return {
        "statusCode": 200,
        "body": json.dumps(
            {
                "message": "Successfully converted and saved Control Summary to OSCAL format."
            }
        ),
    }
