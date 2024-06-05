"""
Extract NIST SP 800-53 security control findings from AWS Security Hub

This module contains a Lambda function that extracts the latest findings by
resource and security control ID from AWS Security Hub and saves them to a CSV
file stored in an S3 bucket.

The function takes event and context parameters but does not use them. It
retrieves the AWS region from the AWS_REGION environment variable and uses the
boto3 SDK to connect to Security Hub in that region.

Findings are retrieved from Security Hub and converted to a Pandas DataFrame,
which is then serialized to CSV and uploaded to the S3 bucket specified in the
BUCKET_NAME environment variable.
"""
import io
import json
import logging
import os
import urllib.parse
from io import StringIO
import zipfile
import boto3
import pandas as pd

# Set up logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Define constants
REGION = os.environ["AWS_REGION"]
BUCKET_NAME = os.environ["BUCKET_NAME"]
SECURITYHUB_FINDINGS_JSON_KEY = "shca/original_findings_in_asff/original_findings_asff.json"
SECURITYHUB_FINDINGS_CSV_KEY = "shca/condensed_findings/nist80053_findings_condensed.csv"
SECURITYHUB_OPENSCAP_ZIP_KEY = "shca/findings_by_security_control_id/sh_openscap_data.zip"
SECURITYHUB_SUPPRESSED_FINDINGS_KEY = "shca/suppressed_findings/suppressed_findings.csv"

def get_securityhub_findings(s3_client):
    """
    Get findings from AWS Security Hub.

    Queries Security Hub for the latest findings. Returns
    the findings data for further processing.
    """
    logger.info("Loading SecurityHub original findings json.")
    json_obj = s3_client.get_object(Bucket=BUCKET_NAME, Key=SECURITYHUB_FINDINGS_JSON_KEY)
    json_data = json_obj["Body"].read().decode("utf-8")

    logger.info("Validate JSON.")
    try:
        return json.loads(json_data)
    except json.JSONDecodeError:
        logger.info("Invalid or empty JSON.")
        return None

def parse_findings(findings_dict):
    """
    Parse Security Hub findings dictionary.

    Takes the raw findings dictionary and extracts the rule ID, 
    compliance status, and last observed date for each finding. 
    Returns a list of dicts with the parsed data.
    """
    logger.info("Extracting rule id, compliance status, and last observed at.")
    control_compliance = []

    for item in findings_dict:
        generator_id = item["GeneratorId"].split("/")[-1]
        if generator_id is not None:
            # First, try to extract service name from the resource ID
            resources = item.get("Resources", [])
            aws_service = None
            if resources and "Id" in resources[0]:
                resource_id = resources[0]["Id"]
                aws_service = resource_id.split(":")[2] if len(resource_id.split(":")) > 2 else None
            # Fallback to extracting service name from generator_id
            if not aws_service:
                aws_service = generator_id.split(".")[0]
            # Change service to lowercase
            aws_service = aws_service.lower()
            # Change feature 'logs' to service 'cloudwatch'
            if aws_service == "logs":
                aws_service = "cloudwatch"

            # Extract AWS Account ID from the resource ID
            resource_id = item["ProductFields"].get("Resources:0/Id", "")

            # Extract AWS Account ID directly from the item
            aws_account_id = item.get("AwsAccountId", "000000000000")

            # Extracting product name and vendor from 'ProductFields'
            product_fields = item.get("ProductFields", {})
            product_name = product_fields.get("aws/securityhub/ProductName", "Unknown Product")
            product_vendor_name = product_fields.get(
                "aws/securityhub/CompanyName",
                "Unknown Vendor"
            )

            related_requirements = item["Compliance"].get("RelatedRequirements", [])


            finding_id = item["Id"].split("/")[-1]
            workflow_state = item.get("WorkflowState", "")
            status = item.get("Workflow", {}).get("Status", "")
            record_state = item.get("RecordState", "")

            # Create URL based on the values
            title = urllib.parse.quote(item["Title"].replace(" ", "%20"))
            resource_id_url = urllib.parse.quote(resource_id)
            rule_id = urllib.parse.quote(generator_id)
            region = item["Region"]
            url = (
                f"https://{region}.console.aws.amazon.com/securityhub/home?region={region}#"
                "/findings?search=Title%3D%255Coperator%255C%253AEQUALS%255C%253A"
                f"{title}%26ResourceId%3D%255Coperator%255C%253AEQUALS%255C%253A"
                f"{resource_id_url}%26ComplianceSecurityControlId%3D"
                "%255Coperator%255C%253AEQUALS%255C%253A"
                f"{rule_id}"
            )
            for related_requirement in related_requirements:
                compliance_standard_id = None
                compliance_control_id = None
                # Log the input
                logger.info("%sProcessing related requirement:", related_requirement)
                # PCI DSS Parsing
                if "PCI DSS " in related_requirement:
                    compliance_standard_id = "PCI DSS"
                    compliance_control_id = related_requirement.split("PCI DSS ")[-1]

                # CIS AWS Foundations Benchmark Parsing
                elif "CIS AWS Foundations Benchmark" in related_requirement:
                    logger.info("Parse CIS AWS Foundations Benchmark "
                                "into standard_id and control_id.")
                    parts = related_requirement.split("/", 1)
                    compliance_standard_id = parts[0].strip()
                    compliance_control_id = parts[1].strip() if len(parts) > 1 else None

                # NIST.800-53.r5 Parsing
                elif "NIST.800-53.r5" in related_requirement:
                    logger.info("Parse NIST.800-53.r5 into standard_id and control_id.")
                    parts = related_requirement.split(" ", 1)
                    compliance_standard_id = parts[0].strip()
                    compliance_control_id = parts[1].strip() if len(parts) > 1 else None

                else:
                    logger.info("%sUnhandled format:", related_requirement)

                # Only keep NIST findings
                if compliance_standard_id != "NIST.800-53.r5":
                    continue
                # Log the results
                logger.info(
                    f"Standard ID: {compliance_standard_id}, "
                    f"Control ID: {compliance_control_id}"
                )
                control_compliance.append(
                    [
                        resource_id,
                        generator_id,
                        aws_account_id,
                        aws_service,
                        item["Compliance"]["Status"],
                        item["LastObservedAt"],
                        item["Severity"]["Label"],
                        item["Title"],
                        item["Description"],
                        item["Remediation"]["Recommendation"]["Text"],
                        item["Remediation"]["Recommendation"]["Url"],
                        related_requirement,
                        finding_id,
                        url,
                        workflow_state,
                        status,
                        record_state,
                        product_name,
                        product_vendor_name,
                        compliance_standard_id,
                        compliance_control_id,
                        "cloud_resource"
                    ]
                )

    # Create a dataframe from control_compliance list
    logger.info("Create a dataframe from control_compliance list.")
    control_df = pd.DataFrame(
        control_compliance,
        columns=[
            "resource_id",
            "rule_id",
            "aws_account_id",
            "aws_service",
            "compliance_status",
            "lastobservedat",
            "severity",
            "title",
            "description",
            "remediation",
            "reference",
            "related_requirements",
            "finding_id",
            "url",
            "workflow_state",
            "status",
            "record_state",
            "product_name",
            "product_vendor_name",
            "compliance_standard_id",
            "compliance_control_id",
            "compliance_layer"
        ],
    )

    # Convert lastobservedat to datetime
    logger.info("Convert lastobservedat to datetime.")
    control_df["lastobservedat"] = pd.to_datetime(control_df["lastobservedat"])

    # Sort dataframe by finding_id, rule_id, and compliance_control_id
    logger.info("Sort dataframe by finding_id, rule_id, and compliance_control_id.")
    control_df.sort_values(
        by=["finding_id", "rule_id", "compliance_control_id"], inplace=True
    )

    # Create new datframe of suppressed_findings
    suppressed_findings = control_df[control_df['status'] == 'SUPPRESSED']
    # Get the indices of the rows in suppressed_findings
    suppressed_indices = suppressed_findings.index

    suppressed_findings = suppressed_findings.loc[
        :,
        [
            'resource_id',
            'rule_id',
            'aws_account_id',
            'aws_service',
            'severity',
            'finding_id'
        ]
    ]
    suppressed_findings = suppressed_findings.drop_duplicates()

    # Drop these rows from condensed_data
    control_df = control_df.drop(suppressed_indices)

    return control_df, suppressed_findings

def upload_dataframe_to_s3(s3_client, dataframe, key):
    """
    Upload Pandas DataFrame to S3.

    Takes an S3 client, DataFrame, and S3 key. Logs 
    upload message then converts DataFrame to CSV and 
    uploads object to specified S3 key location.
    """
    logger.info("%sUploading dataframe to S3 with key:", key)
    with io.StringIO() as csv_buffer:
        dataframe.to_csv(csv_buffer, index=False)
        s3_client.put_object(
            Body=csv_buffer.getvalue(),
            Bucket=BUCKET_NAME,
            Key=key
        )

def create_zip_file(s3_client, dataframe):
    """
    Create a ZIP file of CSVs from a DataFrame.

    Takes an S3 client and DataFrame. Logs a message, then 
    writes each unique control ID from the DataFrame to its 
    own CSV file inside a ZIP archive in memory.
    """
    logger.info("Creating ZIP file with individual control CSVs.")
    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as zip_file:
        unique_rule_ids = dataframe["rule_id"].unique()
        for rule_id in unique_rule_ids:
            individual_df = dataframe[dataframe["rule_id"] == rule_id]
            csv_buffer = StringIO()
            individual_df.to_csv(csv_buffer, index=False)
            csv_buffer.seek(0)
            zip_file.writestr(f"{rule_id.lower()}.csv", csv_buffer.getvalue())
            logger.info("%s CSV for %s added to zip", rule_id, "Rule ID")

    zip_buffer.seek(0)

    logger.info("Uploading ZIP file to S3.")
    s3_client.put_object(
        Bucket=BUCKET_NAME,
        Key=SECURITYHUB_OPENSCAP_ZIP_KEY,
        Body=zip_buffer.getvalue()
    )
    logger.info("%sZip file uploaded to", SECURITYHUB_OPENSCAP_ZIP_KEY)

def lambda_handler(event, context):
    """
    Lambda function handler.

    Initializes an S3 client and acts as the entry point 
    for the Lambda function. The event parameter contains 
    invocation data and context contains runtime information.
    Args:
        event: The event data that triggered the Lambda function. 
               It is required by AWS Lambda, even if it's not used in this function.
        context: The runtime information provided by AWS Lambda. 
                 It is required by AWS Lambda, even if it's not used in this function.
    """
    s3_client = boto3.client("s3", region_name=REGION)

    findings_dict = get_securityhub_findings(s3_client)
    if findings_dict is None:
        return {"statusCode": 400, "body": json.dumps("Invalid JSON in SecurityHub findings.")}

    control_df, suppressed_findings = parse_findings(findings_dict)
    upload_dataframe_to_s3(s3_client, control_df, SECURITYHUB_FINDINGS_CSV_KEY)
    upload_dataframe_to_s3(s3_client, suppressed_findings, SECURITYHUB_SUPPRESSED_FINDINGS_KEY)

    #create_zip_file(s3_client, control_df)

    return {
        "statusCode": 200,
        "body": json.dumps(
            "CSV and data.zip created successfully and saved to "
            + BUCKET_NAME
            + "/shca/compliance_scraper"
        )
    }

if __name__ == "__main__":
    lambda_handler(None, None)
