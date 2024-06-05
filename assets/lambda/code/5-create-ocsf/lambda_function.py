"""
lambda_function.py

This file contains the code for a Lambda function that converts AWS Security Hub findings 
to the Open Cybersecurity Schema Framework (OCSF) format.

The lambda_handler function is invoked by AWS Lambda in response to scheduled events.
It loads findings data from an S3 bucket, converts each finding to OCSF format, 
and saves the converted findings back to S3.

The convert_time_to_unix and convert_to_ocsf functions contain the logic to standardize 
timestamps and map fields between the AWS Security Hub and OCSF formats.
"""

import json
import logging
import os
from dateutil.parser import parse
from dateutil.parser import ParserError
import boto3

logger = logging.getLogger()
logger.setLevel(logging.INFO)
region = os.environ["AWS_REGION"]
bucket_name = os.environ["BUCKET_NAME"]
s3_client = boto3.client("s3", region_name=region)

def convert_time_to_unix(timestamp: str) -> int:
    """
    Converts a timestamp string to a Unix epoch integer

    Parameters: timestamp (str): A timestamp in ISO 8601 format

    Returns: int: The Unix epoch timestamp (seconds since 1970-01-01 00:00:00 UTC)

    This function takes a timestamp string in ISO 8601 format, such as those returned
    from AWS services, and converts it to an integer Unix epoch timestamp.

    It first attempts to parse the timestamp using dateutil. If parsing fails,
    it logs an error and returns None.

    This standardized Unix epoch format allows timestamps to be easily sorted, compared
    and processed in other functions.
    """

    if timestamp is None:
        logger.info("Received None as timestamp input")
        return None

    try:
        return int(parse(timestamp).timestamp())
    except ParserError:
        logger.error("Error parsing timestamp: %s", timestamp)
        return None


def convert_to_ocsf(finding):
    """
    Converts findings data to the OCSF (Open Cybersecurity Schema Framework) format

    The OCSF is an open schema for representing cybersecurity data in JSON format. It was created
    to standardize the exchange of security event data between different tools and platforms.

    This function takes the findings data retrieved from AWS Security Hub and converts it
    to the OCSF format:

    Creates a new OCSF document with the required top-level fields like 'type', 'spec_version', etc.
    Loops through each finding and converts the relevant fields to their OCSF counterparts
    Converts timestamps to Unix epoch
    Maps severity levels, etc.
    Returns the completed OCSF document
    Parameters: findings (list): A list of finding dictionaries from AWS Security Hub

    Returns: ocsf_document (dict): The findings data converted to OCSF format
    """
    # Map the values for activity_id based on the RecordState
    record_state = finding.get("RecordState")
    activity_id = (
        1 if record_state == "ACTIVE" else 2 if record_state == "ARCHIVED" else 0
    )

    # Map the values for severity_id based on the Severity Label
    severity_label = finding.get("Severity", {}).get("Label")
    severity_id = {
        "INFORMATIONAL": 1,
        "LOW": 2,
        "MEDIUM": 3,
        "HIGH": 4,
        "CRITICAL": 5,
    }.get(severity_label, 0)

    # Map the values for state_id and time based on the WorkflowState
    workflow_state = finding.get("Workflow", {}).get("Status")
    state_id_map = {"NEW": 1, "NOTIFIED": 2, "SUPPRESSED": 3, "RESOLVED": 4}
    state_id = state_id_map.get(workflow_state, 0)
    time = convert_time_to_unix(
        finding.get("CreatedAt")
        if workflow_state == "NEW"
        else finding.get("LastObservedAt")
    )

    # Compute type_id
    type_id = 200100 + activity_id

    # Extract the security_control_id and compute service_name
    security_control_id = finding.get("Compliance", {}).get("SecurityControlId")
    service_name = (
        security_control_id.split(".")[0]
        if security_control_id and "." in security_control_id
        else None
    )

    # Change service_name to lower case
    if service_name:
        service_name = service_name.lower()

    ocsf_finding = {
        "activity_id": activity_id,
        "activity_name": "Update",
        "category_name": "Findings",
        "category_uid": 2,
        "class_name": "Security Finding",
        "class_uid": 2001,
        "cloud": {
            "account_uid": finding.get("AwsAccountId"),
            "provider": "AWS",
            "region": finding.get("Region"),
        },
        "compliance": {
            "status": finding.get("Compliance", {}).get("Status"),
            "security_control_id": finding.get("Compliance", {}).get(
                "SecurityControlId"
            ),
            "related_requirements": finding.get("Compliance", {}).get(
                "RelatedRequirements"
            ),
            "associated_standards": finding.get("Compliance", {}).get(
                "AssociatedStandards"
            ),
        },
        "finding": {
            "created_time": convert_time_to_unix(finding.get("CreatedAt")),
            "desc": finding.get("Description"),
            "title": finding.get("Title"),
            "uid": finding.get("Id"),
            "product_name": finding.get("ProductName"),
            "company_name": finding.get("CompanyName"),
            "service_name": service_name,
            "types": finding.get("Types"),
            "first_observed_at": convert_time_to_unix(finding.get("FirstObservedAt")),
            "last_observed_at": convert_time_to_unix(finding.get("LastObservedAt")),
            "updated_at": convert_time_to_unix(finding.get("UpdatedAt")),
            "severity_label": finding.get("Severity", {}).get("Label"),
            "severity_normalized": finding.get("Severity", {}).get("Normalized"),
            "severity_original": finding.get("Severity", {}).get("Original"),
            "remediation_text": finding.get("Remediation", {})
            .get("Recommendation", {})
            .get("Text"),
            "remediation_url": finding.get("Remediation", {})
            .get("Recommendation", {})
            .get("Url"),
            "product_fields": finding.get("ProductFields"),
            "resources": finding.get("Resources"),
        },
        "severity_id": severity_id,
        "state_id": state_id,
        "type_id": type_id,
        "state": finding.get("Workflow", {}).get(
            "Status"
        ),  # Changed to extract from ASFF JSON
        "time": time,
        "unmapped": finding.get(
            "FindingProviderFields"
        ),  # Changed to extract from ASFF JSON
    }
    return ocsf_finding


def lambda_handler(event, context):  # pylint: disable=unused-argument
    """
    Handle Lambda function triggered by an event.

    This function is invoked by AWS Lambda in response to events. It will
    load AWS Security Hub findings from S3, convert them to the OCSF format,
    and save the converted findings back to S3.

    Args:
        event (dict): The event payload received by Lambda
        context: The Lambda runtime information

    Returns:
        None
    """

    securityhub_findings_json_key = "shca/original_findings_in_asff/original_findings_asff.json"
    securityhub_findings_ocsf_key = "shca/original_findings_in_ocsf/original_findings_ocsf.json"

    # Load the original findings from S3
    logger.info("Loading the original AWS Security Hub findings from S3.")
    original_findings_obj = s3_client.get_object(
        Bucket=bucket_name, Key=securityhub_findings_json_key
    )
    original_findings_data = original_findings_obj["Body"].read().decode("utf-8")
    findings = json.loads(original_findings_data)

    # Convert findings to OCSF format
    logger.info("Converting AWS Security Hub findings to OCSF format.")
    ocsf_findings = [convert_to_ocsf(finding) for finding in findings]

    # Save the converted OCSF findings to S3
    logger.info("Saving converted OCSF AWS Security Hub findings to S3.")
    s3_client.put_object(
        Body=json.dumps(ocsf_findings, indent=4),
        Bucket=bucket_name,
        Key=securityhub_findings_ocsf_key,
    )

    logger.info("Converted AWS Security Hub findings saved to S3.")

    return {
        "statusCode": 200,
        "body": json.dumps(
            {"message": "Successfully converted and saved findings to OCSF format."}
        ),
    }
