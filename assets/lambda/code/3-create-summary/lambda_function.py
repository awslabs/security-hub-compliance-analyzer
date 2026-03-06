"""
This Lambda function analyzes results from previous runs stored in an S3 bucket
and creates a consolidated CSV file with a summary.

It first connects to the specified S3 bucket to retrieve relevant files with 
results in CSV format. These files are read and their data is merged into a single Pandas DataFrame.

Basic analysis is then performed on the consolidated data, 
such as counting records and values for each column.

Finally, the analyzed data is written out to a new CSV file and uploaded back 
to the S3 bucket under a specified key for later consumption.
"""

from io import StringIO
import logging
import os
import re
import tempfile
from datetime import datetime
import pandas as pd
import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger()
logger.setLevel(logging.INFO)
logger.info("Lambda handler started")

region = os.environ["AWS_REGION"]
s3_client = boto3.client("s3", region_name=region)
bucket_name = os.environ["BUCKET_NAME"]


def natural_sort_key(text):
    """Sort key that handles embedded numbers naturally (AC-2 before AC-17)."""
    return [int(c) if c.isdigit() else c.lower() for c in re.split(r"(\d+)", str(text))]


def lambda_handler(event, context):  # pylint: disable=unused-argument
    """
    Lambda function that processes SecurityHub findings data.

    Retrieves condensed findings data, summary data, and other related
    files from S3. Performs initial data cleaning on the condensed
    findings.

    Args:
        event: The event data that triggered the Lambda function.
               It is required by AWS Lambda, even if it's not used in this function.
        context: The runtime information provided by AWS Lambda.
                 It is required by AWS Lambda, even if it's not used in this function.
    """
    # bucket_name = os.environ["BUCKET_NAME"]
    securityhub_findings_by_account_key = "shca/findings_by_account/"
    securityhub_findings_csv_key = (
        "shca/condensed_findings/nist80053_findings_condensed.csv"
    )
    securityhub_summary_csv_key = (
        "shca/control_summary_of_findings/nist80053_findings_summary.csv"
    )
    analysis_summary_html_key = (
        "shca/analysis_summary_in_html/nist80053_analysis_summary.html"
    )
    securityhub_disabled_rules_key = "shca/disabled_rules/disabled_rules.csv"
    securityhub_suppressed_findings_key = (
        "shca/suppressed_findings/suppressed_findings.csv"
    )
    securityhub_unmapped_controls_key = (
        "shca/unmapped_controls/unmapped_nist_controls.csv"
    )

    condensed_data = get_dataframe_from_s3(securityhub_findings_csv_key)
    clean_condensed_data = process_whitespace(condensed_data)

    # --- FIX 1: Exclude NOT_AVAILABLE and WARNING findings ---
    pre_filter_count = len(clean_condensed_data)
    clean_condensed_data = clean_condensed_data[
        clean_condensed_data["compliance_status"].isin(["PASSED", "FAILED"])
    ]
    excluded_status_count = pre_filter_count - len(clean_condensed_data)
    if excluded_status_count:
        logger.info(
            "Excluded %d NOT_AVAILABLE/WARNING findings from analysis",
            excluded_status_count,
        )

    # --- FIX 2: Auto-detect and exclude services not in use ---
    # Security Hub generates findings for all services in a compliance standard,
    # even when no resources exist for that service. These findings carry a
    # reason_code of "CONFIG_EVALUATIONS_EMPTY" (set by AWS Config).
    # A service is considered "not in use" only if ALL of its findings have this
    # reason code. Services with any real evaluations are kept in the analysis.
    # This eliminates the need for a manual EXCLUDED_SERVICES environment variable.
    excluded_services = []
    excluded_service_count = 0
    if "reason_code" in clean_condensed_data.columns:
        svc_groups = clean_condensed_data.groupby("aws_service")["reason_code"]
        excluded_services = sorted(
            svc for svc, codes in svc_groups
            if (codes == "CONFIG_EVALUATIONS_EMPTY").all()
        )
        if excluded_services:
            pre_svc_count = len(clean_condensed_data)
            clean_condensed_data = clean_condensed_data[
                ~clean_condensed_data["aws_service"].isin(excluded_services)
            ]
            excluded_service_count = pre_svc_count - len(clean_condensed_data)
            logger.info(
                "Excluded %d findings from services not in use: %s",
                excluded_service_count,
                excluded_services,
            )

    # Retrieve and process disabled rules data
    disabled_rules_data = get_dataframe_from_s3(securityhub_disabled_rules_key)

    # Retrieve and process supressed findings data
    suppressed_findings_data = get_dataframe_from_s3(
        securityhub_suppressed_findings_key
    )

    # Retrieve unmapped NIST controls (in standard but no RelatedRequirements)
    try:
        unmapped_controls_data = get_dataframe_from_s3(securityhub_unmapped_controls_key)
    except Exception:
        unmapped_controls_data = pd.DataFrame(columns=["control_id"])

    # Generate account-specific reports
    generate_findings_by_account(
        clean_condensed_data, securityhub_findings_by_account_key
    )

    # Generate the HTML table
    (
        html_table,
        percentage_compliant_control_ids,
    ) = create_control_summary_of_findings_data(
        clean_condensed_data, securityhub_summary_csv_key
    )

    metrics_condensed_data = generate_metrics_condensed_data(
        clean_condensed_data, percentage_compliant_control_ids
    )

    # Call the generate_analysis_summary_report_html_report function with all required arguments
    analysis_summary_html = generate_analysis_summary_report_html_report(
        metrics_condensed_data,
        clean_condensed_data,
        html_table,
        disabled_rules_data,
        suppressed_findings_data,
        unmapped_controls_data,
        excluded_services,
        excluded_status_count,
        excluded_service_count,
    )

    write_and_upload_report(analysis_summary_html, analysis_summary_html_key)

    logger.info("Lambda handler completed")
    return {"statusCode": 200, "body": "Files saved to :" + securityhub_summary_csv_key}


def generate_findings_by_account(
    clean_condensed_data, securityhub_findings_by_account_key
):
    """
    Generate and upload account-specific findings reports to S3.
    """
    logger.info("Generating findings by AWS account ID.")

    # Group the data by aws_account_id
    findings_by_account = clean_condensed_data.groupby("aws_account_id")

    # Iterate over each account and create a separate report
    for account_id, account_data in findings_by_account:
        logger.info("Generating findings for account: %s", account_id)

        # Create account summary
        account_summary = (
            account_data.groupby("compliance_control_id")
            .agg(
                {
                    "compliance_status": [
                        determine_compliance_status,
                        calculate_percentage,
                    ],
                    "rule_id": lambda x: sorted(list(set(x))),
                    "lastobservedat": "first",
                }
            )
            .reset_index()
        )

        account_summary.columns = [
            "compliance_control_id",
            "compliance_status",
            "percentage",
            "rule_id",
            "lastobservedat",
        ]

        # Generate account-specific HTML report
        account_metrics = generate_metrics_condensed_data(
            account_data,
            account_summary["percentage"].str.rstrip("%").astype(float).mean(),
        )

        # Save account summary to S3
        account_summary_key = (
            f"{securityhub_findings_by_account_key}{account_id}/account_summary.csv"
        )
        put_dataframe_to_s3(account_summary, account_summary_key)

        # Generate and save account-specific HTML report
        account_html = generate_analysis_summary_report_html_report(
            account_metrics,
            account_data,
            account_summary.to_html(index=False),
            pd.DataFrame(),  # Empty DataFrame for disabled rules
            pd.DataFrame(),  # Empty DataFrame for suppressed findings
            pd.DataFrame(columns=["control_id"]),  # Empty for unmapped controls
            [],  # No excluded services for per-account reports
            0,   # No excluded status count
            0,   # No excluded service count
        )

        account_html_key = (
            f"{securityhub_findings_by_account_key}{account_id}/account_report.html"
        )
        write_and_upload_report(account_html, account_html_key)

        logger.info("Account summary and report for %s saved to S3", account_id)


def get_dataframe_from_s3(key: str) -> pd.DataFrame:
    """
    Retrieves a Pandas DataFrame from an object in an S3 bucket.

    Args:
        bucket_name (str): Name of the S3 bucket.
        key (str): S3 object key.

    Returns:
        pd.DataFrame: DataFrame populated from the CSV data.
    """
    logger.info("Retrieving data from S3.")
    # Create an S3 client
    # s3_client = boto3.client("s3")
    # Get the object from S3
    response = s3_client.get_object(Bucket=bucket_name, Key=key)
    # Read the CSV content
    csv_string = response["Body"].read().decode("utf-8")
    # Create a DataFrame
    df = pd.read_csv(StringIO(csv_string))
    logger.info("Data retrieved from S3.")
    return df


def put_dataframe_to_s3(df: pd.DataFrame, key: str) -> None:
    """
    Uploads a Pandas DataFrame to an S3 bucket as a CSV.

    Args:
    df (pd.DataFrame): The DataFrame to upload.
    bucket_name (str): The name of the S3 bucket.
    key (str): The S3 object key to upload to.

    Raises:
    TypeError: If df is not a Pandas DataFrame.

    """
    logger.info("Uploading data to S3.")
    if not isinstance(df, pd.DataFrame):
        raise TypeError("df must be a Pandas DataFrame")
    csv_string = df.to_csv(index=False)
    s3_client.put_object(Body=csv_string, Bucket=bucket_name, Key=key)
    logger.info("Data uploaded to S3.")


def process_whitespace(df: pd.DataFrame) -> pd.DataFrame:
    """
    Removes leading and trailing whitespace from DataFrame columns.

    Args:
    df (pd.DataFrame): The input DataFrame

    Returns:
    pd.DataFrame: A copy of the DataFrame with whitespace stripped from object columns.

    This function logs the start and completion of whitespace removal. It uses
    DataFrame.apply() to call str.strip() on each column, only if the column
    dtype is object. This removes leading and trailing whitespace from string
    columns while leaving other column types unchanged.

    The cleaned DataFrame is returned while the original input is unchanged.
    """
    logger.info("Removing leading and trailing whitespace from DataFrame columns.")
    cleaned_data = df.apply(
        lambda col: col.str.strip() if col.dtype == "object" else col
    )
    logger.info("Leading and trailing whitespace removed from DataFrame columns.")
    return cleaned_data


# This function is required for generating the securityhub_nist80053_findings_summary.csv.
def generate_narrative(row: pd.Series) -> str:
    """Generates a concise compliance posture statement for a NIST 800-53 control."""
    datetime_format_with_microseconds = "%Y-%m-%d %H:%M:%S.%f%z"
    datetime_format_without_microseconds = "%Y-%m-%d %H:%M:%S%z"
    datetime_string = row["lastobservedat"]

    try:
        observed_at = datetime.strptime(
            datetime_string, datetime_format_with_microseconds
        )
    except ValueError:
        observed_at = datetime.strptime(
            datetime_string, datetime_format_without_microseconds
        )

    formatted_date = observed_at.strftime("%B %d, %Y")
    status = row["compliance_status"]

    if status == "compliant":
        detail = "all associated resources met the required criteria"
    elif status == "non-compliant":
        detail = "no associated resources met the required criteria"
    else:
        detail = "a subset of associated resources did not meet the required criteria"

    return (
        f"Control {row['compliance_control_id']} is {status} ({row['percentage']}) "
        f"within the assessed AWS environment as of {formatted_date}. "
        f"Security controls {row['rule_id']} were evaluated and {detail}."
    )


# This function is required for generating the securityhub_nist80053_findings_summary.csv.
def create_control_summary_of_findings_data(
    clean_condensed_data: pd.DataFrame,
    securityhub_summary_csv_key: str,
):
    """
    Create a summary of findings data for each control.

    Takes the cleaned condensed findings data, bucket name, and
    S3 key for the summary CSV file. Groups the data by control,
    calculates summary stats for each control, and saves the
    results to the specified S3 location.
    """
    logger.info("Creating control summary of findings data.")
    # Group and aggregate the NIST findings
    findings_dataframe_grouped = (
        clean_condensed_data.groupby("compliance_control_id")
        .agg(
            {
                "compliance_status": [
                    determine_compliance_status,
                    calculate_percentage,
                ],
                "rule_id": lambda x: list(set(x)),  # Remove duplicates and make a list
                "lastobservedat": "first",
            }
        )
        .reset_index()
    )

    findings_dataframe_grouped.columns = [
        "compliance_control_id",
        "compliance_status",
        "percentage",
        "rule_id",
        "lastobservedat",
    ]

    # Remove the unwanted characters using replace
    logger.info("Removing unwanted characters using replace.")
    findings_dataframe_grouped["rule_id"] = (
        findings_dataframe_grouped["rule_id"]
        .astype(str)
        .str.replace("[", "")
        .str.replace("]", "")
        .str.replace("'", "")
    )

    # Natural sort so AC-2 comes before AC-17
    findings_dataframe_grouped = findings_dataframe_grouped.iloc[
        findings_dataframe_grouped["compliance_control_id"]
        .map(natural_sort_key)
        .argsort()
    ].reset_index(drop=True)

    findings_dataframe_grouped["narrative"] = findings_dataframe_grouped.apply(
        generate_narrative, axis=1
    )

    logger.info("Writing the CSV to S3.")
    put_dataframe_to_s3(findings_dataframe_grouped, securityhub_summary_csv_key)
    logger.info("%s written to S3.", securityhub_summary_csv_key)

    # Calculate the average percentage of compliance
    percentage_compliant_control_ids = (
        findings_dataframe_grouped["percentage"].str.rstrip("%").astype(float).mean()
    )
    logger.info("%s Average percentage of compliance", percentage_compliant_control_ids)

    # Create html table for use in Executive Summary
    # Make a copy of the dataframe for HTML manipulation
    html_dataframe = findings_dataframe_grouped.copy()

    # Rename columns for the HTML table
    html_dataframe.rename(
        columns={
            "compliance_control_id": "Control ID",
            "compliance_status": "Compliance Status",
            "percentage": "Percent Compliant",
            "rule_id": "Security Hub Rule ID",
            "lastobservedat": "Last Time Assessed",
            "narrative": "Compliance Narrative",
        },
        inplace=True,
    )

    # Debugging: Format the 'Last Time Assessed' column one by one to catch the error
    # Debugging: Format the 'Last Time Assessed' column one by one to catch the error
    for index, row in html_dataframe.iterrows():
        try:
            dt = pd.to_datetime(row["Last Time Assessed"], utc=True)
            html_dataframe.at[index, "Last Time Assessed"] = dt.strftime("%Y-%m-%d %H:%M:%S UTC")
        except ValueError as e:
            logger.error(
                "Error converting date string: %s - Error: %s",
                row["Last Time Assessed"],
                e,
            )

    # Convert the copied dataframe to HTML
    html_table = html_dataframe.to_html(index=False)

    # Now use the original dataframe (findings_dataframe_grouped) to create the CSV file
    # This dataframe will have the original column names and date formats
    put_dataframe_to_s3(findings_dataframe_grouped, securityhub_summary_csv_key)

    # Return only the HTML table and the average percentage of compliance
    return html_table, percentage_compliant_control_ids


# These functions are required to perform analyisis and generate reports.
# This function writes and uploads a report to S3.
def write_and_upload_report(report, key):
    """
    Write and upload a report to S3

    This function writes a given report to a temporary local file, then uploads it
    to the specified S3 bucket and key. It uses the boto3 S3 client to perform
    the upload.

    Args:
    report (str): The report content to write and upload
    bucket_name (str): The name of the S3 bucket to upload to
    key (str): The S3 object key (filename) to upload the file to

    Returns:
    None

    Raises:
    ClientError: If the upload to S3 fails
    """
    logger.info("Writing and uploading {key} to S3.")
    temp_folder = tempfile.mkdtemp()
    local_filename = key.split("/")[-1]
    path = os.path.join(temp_folder, local_filename)

    logger.info(
        "Writing report to %s and uploading to s3://%s/%s.", path, bucket_name, key
    )

    with open(path, "w", encoding="utf-8") as file:
        file.write(report)

    try:
        s3_client.upload_file(path, bucket_name, key)
        logger.info("Successfully uploaded file to s3://%s/%s", bucket_name, key)
    except ClientError as e:
        logger.error("Failed to upload file to s3://%s/%s", bucket_name, key)
        logger.error(e)
    finally:
        os.remove(path)
        os.rmdir(temp_folder)
    logger.info("{key} written and uploaded to S3.")


# def create_dataframe_from_s3_csv(bucket_name, key):
#    # Create an S3 client
#    s3_client = boto3.client('s3')

# Get the object from S3
#    response = s3_client.get_object(Bucket=bucket_name, Key=key)

# Read the CSV content into a DataFrame
#    csv_content = response['Body'].read().decode('utf-8')
#    df = pd.read_csv(StringIO(csv_content))

#    return df


# This function calculates the overall compliance status for
# the securityhub_nist80053_findings_summary.csv
def determine_compliance_status(findings: pd.Series) -> str:
    """
    Determine overall compliance status from audit findings

    This function takes in a Series of audit findings and determines
    the overall compliance status based on the values in the findings.

    Args:
        findings (pd.Series): A Series containing audit finding results

    Returns:
    str: The overall compliance status:
        - "compliant" if only "PASSED" in findings
        - "non-compliant" if only "FAILED" in findings
        - "partially compliant" if both "PASSED" and "FAILED"
        - "unknown" if neither "PASSED" nor "FAILED"
    """
    # logger.info("Determining compliance status...")
    if "PASSED" in findings.values and "FAILED" in findings.values:
        return "partially compliant"
    if "PASSED" in findings.values:
        return "compliant"
    if "FAILED" in findings.values:
        return "non-compliant"
    return "unknown"


# This function calculates the control percentages for the securityhub_nist80053_findings_summary.csv
def calculate_percentage(findings: pd.Series) -> str:
    """
    Calculate percentage of findings that passed

    This function takes in a Series of audit findings and calculates
    the percentage that passed by counting the number of "PASSED"
    findings and dividing by the total number of findings.

    Args:
        findings (pd.Series): A Series containing audit finding results

    Returns:
    str: A string representation of the percentage of findings
         that passed formatted to 2 decimal places
    """
    # logger.info("Calculating percentage...")
    passed = findings.value_counts().get("PASSED", 0)
    total = len(findings)
    # logger.info("Percentage calculated.")
    return f"{passed / total:.2%}"


# This function determines the compliance status for the securityhub_nist80053_findings_summary.csv
def determine_rule_compliance_status(findings):
    """
    Determine compliance status of a security rule from audit findings

    This function takes audit findings for a single security rule and
    determines if the rule passed or failed based on the finding results.

    Args:
        findings (list): A list containing audit finding results
                         for a single security rule

    Returns:
    str: Either "Passed" if all findings are "PASSED" or "Failed"
         if any finding is not "PASSED"
    """
    logger.info("Determining rule compliance status of findings")
    # Check if all findings for the rule are 'PASSED'
    if all(findings == "PASSED"):
        return "Passed"
    return "Failed"


# This function adds columns to the rules dataframe
def add_columns_to_rules(rules):
    """Add metrics columns to the rules DataFrame.

    This function takes the rules DataFrame and adds new columns
    calculating metrics from the existing data.

    The 'total_checks' column sums all checks per row. 'checks_passed'
    and 'checks_failed' columns extract those values.

    Percentage columns are then calculated from the counts and total.

    Logging messages indicate the columns are being added and added.

    The updated DataFrame with additional metrics columns is returned.
    """
    logger.info("Adding columns to rules dataframe")
    rules["total_checks"] = rules.sum(axis=1)
    rules["checks_passed"] = rules.get("PASSED", 0)
    rules["checks_failed"] = rules.get("FAILED", 0)
    rules["checks_passed_percentage"] = (
        rules["checks_passed"] / rules["total_checks"]
    ) * 100
    rules["checks_failed_percentage"] = (
        rules["checks_failed"] / rules["total_checks"]
    ) * 100
    logger.info("Columns added to rules dataframe")
    return rules


# This function perorms analysis of security hub findings data and generates metrics for reports
def generate_metrics_condensed_data(
    clean_condensed_data: pd.DataFrame, percentage_compliant_control_ids: float
):
    """Generate condensed metrics data from analysis results.

    This function takes the clean condensed data DataFrame and the
    percentage of compliant control IDs. It logs that it is generating
    the metrics condensed data.

    For debugging, the header and first row of the clean data is
    printed. This function would then be expected to process the
    clean data to extract metrics and return or save the metrics
    condensed data.

    The condensed metrics data provides a summary of key metrics from
    the security analysis, such as pass/fail counts and percentages.
    """
    logger.info("Generating metrics condensed data.")
    # Print header and one row of the clean condensed data for debugging
    print("Clean condensed data:")
    print(clean_condensed_data.head(1))

    # <-----------Calculate declared variables related to Accounts----------->
    # Accounts
    total_aws_account_ids = clean_condensed_data["aws_account_id"].nunique()
    print("\nTotal AWS Account IDs:", total_aws_account_ids)

    # Total records
    total_records = len(clean_condensed_data)
    print("Total Records:", total_records)

    # <-----------Calculate declared variables related to Services----------->
    # Services
    total_services = clean_condensed_data["aws_service"].nunique()
    print("Total Services:", total_services)

    # <-----------Calculate declared variables related to Resources----------->
    # Resources
    total_resource_ids = clean_condensed_data["resource_id"].nunique()
    print("Total Resource IDs:", total_resource_ids)

    # <-----------Calculate declared variables related to Rules----------->
    # Total Unique Security Hub rules
    total_rule_ids = clean_condensed_data["rule_id"].nunique()
    print("Total Rule IDs:", total_rule_ids)

    # Group by 'rule_id' and aggregate various columns
    # Columns to aggregate and their respective aggregation functions
    # Define the aggregation dictionary with the necessary columns
    aggregation_functions = {
        "compliance_status": lambda statuses: (
            "FAILED" if "FAILED" in statuses.values else "PASSED"
        ),
        "title": "first",  # Assuming 'title' is consistent within each 'rule_id'
        "description": "first",  # Keep the first 'description'
        "remediation": "first",  # Keep first 'remediation'
        "reference": "first",  # Keep first 'reference'
        "severity": "first",  # Keep the first 'severity'
    }

    # Perform the group by and aggregation
    rule_status_aggregated = (
        clean_condensed_data.groupby("rule_id").agg(aggregation_functions).reset_index()
    )

    # Drop the 'resource_id' column if it exists
    if "resource_id" in rule_status_aggregated.columns:
        rule_status_aggregated = rule_status_aggregated.drop(columns=["resource_id"])

    # Remove duplicate entries from the 'rule_status_aggregated' DataFrame based
    # on the 'rule_id' column. This ensures that each rule is represented only once,
    # creating a unique mapping of rule IDs to their respective statuses.

    unique_rule_status_mapping = rule_status_aggregated.drop_duplicates(
        subset=["rule_id"]
    )

    # Group by 'rule_id' and 'compliance_status', then count the values
    rules = (
        clean_condensed_data.groupby(["rule_id", "compliance_status"])
        .size()  # This will count the number of occurrences
        .unstack(fill_value=0)  # This will pivot 'compliance_status' to columns
    )
    print("\nRules DataFrame:")
    print(rules.head(1))

    # Group by 'rule_id' only
    all_rule_ids = clean_condensed_data.groupby(
        "rule_id"
    ).size()  # This will count the number of occurrences

    # Add columns to the 'rules' DataFrame
    rules = add_columns_to_rules(rules)
    print("\nRules DataFrame after adding columns:")
    print(rules.head(1))

    # Calculate the total number of passed and failed checks
    total_checks_passed = rules["checks_passed"].sum()
    total_checks_failed = rules["checks_failed"].sum()
    print("\nSH Rules Passed:", total_checks_passed)
    print("SH Rules Failed:", total_checks_failed)

    # Identify rules that have no failed checks
    rules_with_all_passes = rules[rules["checks_failed"] == 0]

    # Count the number of such rules to find total_rule_ids_passed
    total_rule_ids_passed = len(rules_with_all_passes)
    # Determine how many rules failed
    total_rule_ids_failed = total_rule_ids - total_rule_ids_passed

    sh_rules_percent_passed = round((total_rule_ids_passed / total_rule_ids) * 100)

    # Calculate Top 5 failed rules
    top_5_rules_failed = (
        clean_condensed_data[clean_condensed_data["compliance_status"] == "FAILED"][
            "rule_id"
        ]
        .value_counts()
        .nlargest(5)
    )

    # Calculate Security Score as the number of passed rules over the total number of unique rules
    security_score = round((total_rule_ids_passed / total_rule_ids) * 100)

    # Calculate the number of failed rules by severity
    failed_rules_by_severity = {
        severity: clean_condensed_data[
            (clean_condensed_data["compliance_status"] == "FAILED")
            & (clean_condensed_data["severity"] == severity)
        ]["rule_id"].nunique()
        for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    }

    # Sum all the failed rules to get the total count
    total_failed_rules = sum(failed_rules_by_severity.values())

    # Calculate the percentage width for each severity based on their counts
    severity_widths = {
        f"width_{severity.lower()}": (
            (count / total_failed_rules) * 100 if total_failed_rules else 0
        )
        for severity, count in failed_rules_by_severity.items()
    }

    # Calculate the percentage of failed rules for each severity
    rules_severity_percentage = {
        severity: (count / total_failed_rules) * 100
        for severity, count in failed_rules_by_severity.items()
    }

    # <-----------Calculate declared variables related to findings----------->

    # Create DataFrame
    df_for_findings = pd.DataFrame(clean_condensed_data)

    # Keep only specified columns
    df_for_findings = df_for_findings[["compliance_status", "severity", "finding_id"]]

    # Remove duplicate rows
    df_for_findings = df_for_findings.drop_duplicates()

    # Count total passed and failed findings
    # findings_pass = df_for_findings[df_for_findings['compliance_status'] == 'PASSED'].shape[0]
    findings_fail = df_for_findings[
        df_for_findings["compliance_status"] == "FAILED"
    ].shape[0]

    # Calculate percentages
    total_findings = df_for_findings.shape[0]
    # findings_pass_percent = (findings_pass / total_findings) * 100
    # findings_fail_percent = (findings_fail / total_findings) * 100

    # Count and percentage for each severity level
    severity_levels = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    severity_counts = {}
    severity_percents = {}
    findings_fail_severity = {}
    for level in severity_levels:
        count = df_for_findings[df_for_findings["severity"] == level].shape[0]
        percent = (count / total_findings) * 100
        fail_count = df_for_findings[
            (df_for_findings["severity"] == level)
            & (df_for_findings["compliance_status"] == "FAILED")
        ].shape[0]
        severity_counts[level] = count
        severity_percents[level] = percent
        findings_fail_severity[level] = fail_count

    # Calculate the number of unique failed findings for the top 5 resources with the most failures
    failed_findings_by_resource = (
        clean_condensed_data[clean_condensed_data["compliance_status"] == "FAILED"]
        .groupby("resource_id")["finding_id"]
        .nunique()
        .sort_values(ascending=False)
        .nlargest(5)
    )

    # Group findings by compliance control ID and aggregate relevant information
    findings_dataframe_grouped = (
        clean_condensed_data.groupby("compliance_control_id")
        .agg(
            {
                "compliance_status": [
                    determine_compliance_status,
                    calculate_percentage,
                ],
                "rule_id": lambda x: list(set(x)),  # Remove duplicates and make a list
                "lastobservedat": "first",
            }
        )
        .reset_index()
    )

    # Rename columns for clarity in the grouped findings DataFrame
    findings_dataframe_grouped.columns = [
        "compliance_control_id",
        "compliance_status",
        "percentage",
        "rule_id",
        "lastobservedat",
    ]

    # Calculate failed findings by resource
    failed_findings_by_resource = (
        clean_condensed_data[clean_condensed_data["compliance_status"] == "FAILED"]
        .groupby("resource_id")["finding_id"]
        .nunique()
        .sort_values(ascending=False)
        .nlargest(5)
    )

    findings_dataframe_grouped.columns = [
        "compliance_control_id",
        "compliance_status",
        "percentage",
        "rule_id",
        "lastobservedat",
    ]

    # <-----------Calculate declared variables related to controls----------->
    # Calculate the number of passed compliance controls ids
    findings_dataframe_grouped = (
        clean_condensed_data.groupby("compliance_control_id")
        .agg(
            {
                "compliance_status": [
                    determine_compliance_status,
                    calculate_percentage,
                ],
                "rule_id": lambda x: list(set(x)),  # Remove duplicates and make a list
                "lastobservedat": "first",
            }
        )
        .reset_index()
    )

    # Ensure the 'compliance_control_id' column exists
    if "compliance_control_id" not in clean_condensed_data.columns:
        raise ValueError(
            "Column 'compliance_control_id' does not exist in the DataFrame"
        )

    # Total compliance controls
    total_compliance_controls = clean_condensed_data["compliance_control_id"].nunique()
    print("Total Compliance Controls:", total_compliance_controls)

    compliance_controls = (
        clean_condensed_data.groupby("compliance_control_id")["compliance_status"]
        .value_counts()
        .unstack(fill_value=0)
    )
    # Calculate compliance percentage for NIST 800-53 controls
    compliance_controls["compliance_percentage"] = (
        compliance_controls["PASSED"]
        / (compliance_controls["PASSED"] + compliance_controls["FAILED"])
        * 100
    )

    # Determine compliance status based on the calculated fields
    compliance_controls["compliance_status"] = compliance_controls.apply(
        lambda row: (
            "compliant"
            if row["FAILED"] == 0
            else ("non-compliant" if row["PASSED"] == 0 else "partially compliant")
        ),
        axis=1,
    )

    # Calculate the mean of the compliance percentage to get overall NIST compliance
    # overall_nist_compliance = round(compliance_controls["compliance_percentage"].mean(), 2)

    overall_nist_compliance = percentage_compliant_control_ids

    # Count the number of controls in each compliance status category
    compliant_compliance_controls = len(
        compliance_controls[compliance_controls["compliance_status"] == "compliant"]
    )
    non_compliant_compliance_controls = len(
        compliance_controls[compliance_controls["compliance_status"] == "non-compliant"]
    )
    partially_compliant_compliance_controls = len(
        compliance_controls[
            compliance_controls["compliance_status"] == "partially compliant"
        ]
    )
    logger.info("Analysis and Generation of Metrics Complete.")

    return {
        # "total_finding_ids": total_finding_ids,
        # "total_failed_findings": total_failed_finding_ids,
        # "failed_findings_by_severity": failed_findings_by_severity,
        # "failed_findings_severity_percentage": failed_findings_severity_percentage
        # <-----------Pass Misc declared variables----------->
        "clean_condensed_data": clean_condensed_data,
        "total_aws_account_ids": total_aws_account_ids,
        "total_services": total_services,
        "total_resource_ids": total_resource_ids,
        "total_records": total_records,
        # <-----------Pass declared variables related to rules----------->
        "rules": rules.to_dict("index"),
        "total_rule_ids": total_rule_ids,
        "total_rule_ids_passed": total_rule_ids_passed,
        "total_rule_ids_failed": total_rule_ids_failed,
        "sh_rules_percent_passed": sh_rules_percent_passed,
        "security_score": security_score,
        "top_5_rules_failed": top_5_rules_failed,
        "fr_count_critical": failed_rules_by_severity["CRITICAL"],
        "fr_count_high": failed_rules_by_severity["HIGH"],
        "fr_count_medium": failed_rules_by_severity["MEDIUM"],
        "fr_count_low": failed_rules_by_severity["LOW"],
        "fr_total_failed_rules": total_failed_rules,
        "severity_widths": severity_widths,
        "failed_rules_by_severity": failed_rules_by_severity,
        "rules_severity_percentage": rules_severity_percentage,
        "all_rule_ids": all_rule_ids,
        "unique_rule_status_mapping": unique_rule_status_mapping,
        # <-----------Pass declared variables related to controls----------->
        "total_compliance_controls": total_compliance_controls,
        "compliant_compliance_controls": compliant_compliance_controls,
        "non_compliant_compliance_controls": non_compliant_compliance_controls,
        "partially_compliant_compliance_controls": partially_compliant_compliance_controls,
        "overall_nist_compliance": overall_nist_compliance,
        # Pass Finding related declared variables
        "failed_findings_by_resource": failed_findings_by_resource,
        "total_checks_passed": total_checks_passed,
        "total_checks_failed": total_checks_failed,
        "failed_findings_by_severity": findings_fail_severity,
        "total_failed_findings": findings_fail,
        "severity_percents": severity_percents,
    }


def create_html_sections(dataframe):
    """Create HTML sections for failed controls only."""
    sorted_data = dataframe[dataframe["compliance_status"] == "FAILED"].sort_values(by="rule_id")
    if sorted_data.empty:
        return []

    html_sections = ["""
    <div style="max-width:1200px;margin:0 auto;padding:0 20px;">
    <div class="summary-box">
        <h2 class="summary-title">Failed Security Control Details</h2>
        <p>The following security controls did not pass evaluation. Each entry includes the control description, severity, and remediation guidance.</p>
    </div>
    """]
    for _, row in sorted_data.iterrows():
        rows_html = create_rows_html(row)
        html_sections.append(
            f"""
            <details class="details" open>
                <summary>{row["rule_id"]}</summary>
                <table>
                    {rows_html}
                </table>
            </details>
        """
        )
    html_sections.append("</div>")
    return html_sections


def create_rows_html(row):
    """Generate HTML for a table row from compliance data."""
    title_html = f"<strong>Title:</strong> {row.get('title', 'N/A')}"
    severity_html = f"<strong>Severity:</strong> {row.get('severity', 'N/A')}"
    description_html = f"<strong>Description:</strong> {row.get('description', 'N/A')}"
    remediation_html = f"<strong>Remediation:</strong> {row.get('remediation', 'N/A')}"
    reference_html = (
        f"<strong>Reference:</strong> <a href='{row.get('reference', '#')}'>"
        f"{row.get('reference', 'N/A')}</a>"
    )
    combined_html = (
        f"{title_html}<br>{severity_html}<br>{description_html}<br>"
        f"{remediation_html}<br>{reference_html}"
    )
    return f"""
        <tr>
            <td>{combined_html}</td>
        </tr>
    """


# This function generates the executive summary report in html format
def generate_analysis_summary_report_html_report(
    metrics_condensed_data,
    clean_condensed_data,
    html_table,
    disabled_rules_data,
    suppressed_findings_data,
    unmapped_controls_data,
    excluded_services,
    excluded_status_count,
    excluded_service_count,
):
    """Generate an HTML report of the analysis summary.

    This function takes in condensed data from the analysis metrics,
    clean data, the generated HTML table, and data about disabled
    rules, suppressed findings, and unmapped NIST controls.

    It logs a message indicating it is generating the report in HTML
    format. This function would then be expected to generate the
    actual HTML report file using the passed in data.

    The report provides a summary of the key metrics and findings
    from the security analysis in an HTML format for easy viewing
    and sharing.
    """
    logger.info("Generating analysis summary report in html format")
    # <-----------Retrieve Misc declared values----------->
    clean_condensed_data = metrics_condensed_data["clean_condensed_data"]
    total_aws_account_ids = metrics_condensed_data["total_aws_account_ids"]
    total_services = metrics_condensed_data["total_services"]
    total_resource_ids = metrics_condensed_data["total_resource_ids"]

    # <-----------Retrieve declared variables related to rules----------->
    total_rule_ids_passed = metrics_condensed_data["total_rule_ids_passed"]
    total_rule_ids_failed = metrics_condensed_data["total_rule_ids_failed"]
    unique_rule_status_mapping = metrics_condensed_data["unique_rule_status_mapping"]
    fr_count_critical = metrics_condensed_data["fr_count_critical"]
    fr_count_high = metrics_condensed_data["fr_count_high"]
    fr_count_medium = metrics_condensed_data["fr_count_medium"]
    fr_count_low = metrics_condensed_data["fr_count_low"]
    rules_severity_percentage = metrics_condensed_data["rules_severity_percentage"]

    # <-----------Retrieve declared variables related to controls----------->
    total_compliance_controls = metrics_condensed_data["total_compliance_controls"]
    compliant_compliance_controls = metrics_condensed_data[
        "compliant_compliance_controls"
    ]
    non_compliant_compliance_controls = metrics_condensed_data[
        "non_compliant_compliance_controls"
    ]
    partially_compliant_compliance_controls = metrics_condensed_data[
        "partially_compliant_compliance_controls"
    ]
    overall_nist_compliance = metrics_condensed_data["overall_nist_compliance"]

    # <-----------Retrieve declared variables related to findings----------->
    total_rule_ids = metrics_condensed_data["total_rule_ids"]
    failed_findings_by_resource = metrics_condensed_data["failed_findings_by_resource"]
    top_5_rules_failed = metrics_condensed_data["top_5_rules_failed"]
    sh_rules_percent_passed = metrics_condensed_data["sh_rules_percent_passed"]

    # <-----------Misc Calculations----------->
    # Get the unique account IDs
    unique_account_ids = clean_condensed_data["aws_account_id"].unique()

    # Format each account ID with dashes and join them into a comma-separated string
    # Format each account ID into groups of four digits separated by dashes
    account_ids_list = ", ".join(
        "-".join([account_id.zfill(12)[i : i + 4] for i in range(0, 12, 4)])
        for account_id in map(str, unique_account_ids)
    )

    # <-----------Rules Calculations----------->
    failed_findings_by_resource = metrics_condensed_data["failed_findings_by_resource"]
    top_5_rules_failed = metrics_condensed_data["top_5_rules_failed"]

    total_rule_ids_passed = metrics_condensed_data["total_rule_ids_passed"]
    total_rule_ids_failed = metrics_condensed_data["total_rule_ids_failed"]
    total_rule_ids = total_rule_ids_passed + total_rule_ids_failed

    # Calculate percentages
    total_rules_pass_percentage = (total_rule_ids_passed / total_rule_ids) * 100
    total_rules_fail_percentage = (total_rule_ids_failed / total_rule_ids) * 100

    # Initialize the variables
    disabled_rules_count = 0
    disabled_rules_list = ""

    # Check if the disabled_rules_data DataFrame is empty
    if not disabled_rules_data.empty:
        # Count the number of disabled rules
        disabled_rules_count = len(disabled_rules_data)

        # Create a list of disabled rule IDs from the DataFrame if there are any disabled rules
        if disabled_rules_count > 0:
            disabled_rules_list = ", ".join(
                disabled_rules_data["disabled_control_id"].tolist()
            )

    logger.info("%sDisabled rules count:", disabled_rules_count)
    logger.info("%sDisabled rules list:", disabled_rules_list)

    # <-----------Control Calculations----------->
    overall_nist_compliance_string = overall_nist_compliance
    overall_nist_compliance_string = f"{overall_nist_compliance_string:.2f}%"
    # overall_nist_compliance_string = "{:.2f}%".format(overall_nist_compliance_string)

    overall_nist_compliance_failed = 100 - overall_nist_compliance
    overall_nist_compliance_failed_string = f"{overall_nist_compliance_failed:.2f}%"
    # overall_nist_compliance_failed_string = "{:.2f}%".format(
    #    overall_nist_compliance_failed
    # )

    # Determine the compliance descriptor based on the overall_nist_compliance value
    if overall_nist_compliance >= 95:
        compliance_descriptor = "Fully Compliant - Exemplary"
    elif 90 <= overall_nist_compliance < 95:
        compliance_descriptor = "Fully Compliant - Strong"
    elif 80 <= overall_nist_compliance < 90:
        compliance_descriptor = "Substantially Compliant - Strong"
    elif 70 <= overall_nist_compliance < 80:
        compliance_descriptor = "Partially Compliant - Good"
    elif 60 <= overall_nist_compliance < 70:
        compliance_descriptor = "Partially Compliant - Satisfactory"
    elif 50 <= overall_nist_compliance < 60:
        compliance_descriptor = "Partially Compliant - Fair"
    elif 40 <= overall_nist_compliance < 50:
        compliance_descriptor = "Non-Compliant - Poor"
    elif 30 <= overall_nist_compliance < 40:
        compliance_descriptor = "Non-Compliant - Weak"
    else:
        compliance_descriptor = "Non-Compliant - Inadequate"

    # <-----------Findings Calculations----------->
    # FIX: Use total_records (all checks) instead of only failed findings
    total_findings = metrics_condensed_data["total_records"]
    failed_findings_by_resource = metrics_condensed_data["failed_findings_by_resource"]

    # Add total_findings to metrics_condensed_data
    metrics_condensed_data["total_findings"] = total_findings

    # Initialize the variables
    suppressed_findings_count = 0
    suppressed_findings_list = ""

    # Check if the suppressed_findings_data DataFrame is empty
    if not suppressed_findings_data.empty:
        # Count the number of suppressed findings
        suppressed_findings_count = len(suppressed_findings_data)

        # Create a list of suppressed finding IDs from the DataFrame
        # if there are any suppressed findings

        if suppressed_findings_count > 0:
            suppressed_findings_list = ", ".join(
                suppressed_findings_data["finding_id"].tolist()
            )

    logger.info("%sSuppressed findings count:", suppressed_findings_count)
    logger.info("%sSuppressed findings list:", suppressed_findings_list)

    # Unmapped NIST controls
    # <-----------Excluded Services Section----------->
    excluded_services_list = ", ".join(excluded_services) if excluded_services else "None"
    excluded_services_count = len(excluded_services)

    unmapped_controls_count = 0
    unmapped_controls_list = ""
    if not unmapped_controls_data.empty:
        unmapped_controls_count = len(unmapped_controls_data)
        unmapped_controls_list = ", ".join(
            unmapped_controls_data["control_id"].tolist()
        )
    logger.info("Unmapped NIST controls: %d - %s", unmapped_controls_count, unmapped_controls_list)

    # <-----------Report Genderation and Calculations----------->
    logger.info("Generating prioritized actions report")
    # Generate report
    report = "\n"

    # 1. Prioritize Remediation of Failed Rule Checks by Severity
    report += "1. Prioritize Remediation of Failed Rule Checks by Severity\n"
    for severity in ["CRITICAL", "HIGH"]:
        if severity in clean_condensed_data["severity"].unique():
            rules_failed = clean_condensed_data[
                clean_condensed_data["severity"] == severity
            ]["rule_id"].unique()
            report += f"\n  - {severity}\n"
            for rule_id in rules_failed:
                report += f"    - Rule: {rule_id}\n"
    # The 'report' variable accumulates the report content.
    # It is used later for output or further processing.

    # 2. Address Top 5 Resources with the Most Failed Compliance Checks
    report += "\n2. Address Top 5 Resources with the Most Failed Compliance Checks\n"
    for resource_id, count in failed_findings_by_resource.items():
        report += f"\n  - Resource: {resource_id} (Unique Failed Findings: {count})\n"

    # 3. Focus on Top 5 Rules with the Highest Number of Failed Checks
    report += "\n3. Focus on Top 5 Rules with the Highest Number of Failed Checks\n"
    for rule_id, count in top_5_rules_failed.items():
        report += f"\n  - Rule: {rule_id} (Failed Checks: {count})\n"
    logger.info("Prioritized actions report generated")

    # <-----------HTML Report Generation----------->
    # Score color logic
    if overall_nist_compliance >= 80:
        score_color = "var(--pass-green)"
    elif overall_nist_compliance >= 60:
        score_color = "#b8860b"
    elif overall_nist_compliance >= 40:
        score_color = "var(--high)"
    else:
        score_color = "var(--critical)"

    nist_pass_width = overall_nist_compliance
    nist_fail_width = 100 - overall_nist_compliance

    # Deduplicated finding counts for the overview tile
    df_findings_deduped = clean_condensed_data.drop_duplicates(subset=["finding_id"]) if "finding_id" in clean_condensed_data.columns else clean_condensed_data
    total_findings_deduped = len(df_findings_deduped)
    failed_findings_deduped = len(df_findings_deduped[df_findings_deduped["compliance_status"] == "FAILED"])
    passed_findings_deduped = total_findings_deduped - failed_findings_deduped
    findings_pass_pct = (passed_findings_deduped / total_findings_deduped * 100) if total_findings_deduped else 0
    findings_fail_pct = 100 - findings_pass_pct

    # Build prioritized actions as structured HTML
    action_html = ""
    crit_high_rows = ""
    for severity in ["CRITICAL", "HIGH"]:
        if severity in clean_condensed_data["severity"].unique():
            for rule_id in clean_condensed_data[clean_condensed_data["severity"] == severity]["rule_id"].unique():
                sev_color = "var(--critical)" if severity == "CRITICAL" else "var(--high)"
                crit_high_rows += f"<tr><td><strong style=\"color:{sev_color};\">{severity}</strong></td><td><code>{rule_id}</code></td></tr>"
    if crit_high_rows:
        action_html += f"""<h3 style="font-size:0.95rem;margin-bottom:8px;">1. Remediate Failed Security Controls by Severity</h3>
            <table><tr><th>Severity</th><th>Security Control</th></tr>{crit_high_rows}</table>"""

    resource_rows = ""
    for resource_id, count in failed_findings_by_resource.items():
        resource_rows += f"<tr><td><code style=\"font-size:0.8rem;word-break:break-all;\">{resource_id}</code></td><td><strong>{count}</strong></td></tr>"
    if resource_rows:
        action_html += f"""<h3 style="font-size:0.95rem;margin:16px 0 8px;">2. Top Resources with Most Failed Checks</h3>
            <table><tr><th>Resource</th><th>Failed Findings</th></tr>{resource_rows}</table>"""

    control_rows = ""
    for rule_id, count in top_5_rules_failed.items():
        control_rows += f"<tr><td><code>{rule_id}</code></td><td><strong>{count:,}</strong></td></tr>"
    if control_rows:
        action_html += f"""<h3 style="font-size:0.95rem;margin:16px 0 8px;">3. Top Security Controls with Most Failed Checks</h3>
            <table><tr><th>Security Control</th><th>Failed Checks</th></tr>{control_rows}</table>"""

    # Build Out of Scope table
    oos_table = f"""<table>
                <tr><th>Exclusion Type</th><th>Count</th><th>Details</th></tr>
                <tr><td><strong>Disabled Rules</strong></td><td>{disabled_rules_count}</td><td>{disabled_rules_list}</td></tr>
                <tr><td><strong>Suppressed Findings</strong></td><td>{suppressed_findings_count}</td><td><code style="font-size:0.8rem;">{suppressed_findings_list}</code></td></tr>
                <tr><td><strong>Non-Actionable Statuses</strong></td><td>{excluded_status_count}</td><td>Findings with NOT_AVAILABLE or WARNING status</td></tr>
                <tr><td><strong>Services Not In Use</strong></td><td>{excluded_services_count}</td><td style="font-size:0.85rem;">{excluded_services_list}</td></tr>
            </table>"""

    unmapped_html = ""
    if unmapped_controls_count > 0:
        unmapped_html = f"""<p style="margin-top:12px;"><strong>Unmapped Security Controls ({unmapped_controls_count}):</strong> The following security controls are included in the NIST SP 800-53 Rev. 5 standard in Security Hub but lack specific NIST control mappings in the findings data. These controls cannot be associated with NIST requirements and are excluded from this report: {unmapped_controls_list}</p>"""

    # Failed findings severity for the overview tile
    total_failed_findings = metrics_condensed_data["total_failed_findings"]
    ff_critical = metrics_condensed_data["failed_findings_by_severity"]["CRITICAL"]
    ff_high = metrics_condensed_data["failed_findings_by_severity"]["HIGH"]
    ff_medium = metrics_condensed_data["failed_findings_by_severity"]["MEDIUM"]
    ff_low = metrics_condensed_data["failed_findings_by_severity"]["LOW"]

    html_report = f"""
<html>
<head>
    <meta charset="UTF-8">
    <style>
        :root {{
            --aws-dark: #232f3e;
            --aws-orange: #ff9900;
            --pass-green: #1b8a2d;
            --fail-red: #d13212;
            --bg-light: #fafafa;
            --bg-card: #ffffff;
            --border: #e8e8e8;
            --text-primary: #16191f;
            --text-secondary: #545b64;
            --critical: #860000;
            --high: #d13212;
            --medium: #f2a900;
            --low: #0073bb;
            --font-body: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Amazon Ember', sans-serif;
            --font-mono: 'SFMono-Regular', Consolas, 'Liberation Mono', Menlo, monospace;
        }}
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{ font-family: var(--font-body); color: var(--text-primary); background: var(--bg-light); line-height: 1.6; -webkit-font-smoothing: antialiased; }}
        .header {{ background: linear-gradient(135deg, var(--aws-dark) 0%, #37475a 100%); color: #fff; text-align: center; padding: 40px 20px; position: relative; }}
        .header h1 {{ font-size: 1.75rem; font-weight: 600; letter-spacing: -0.02em; }}
        .header::after {{ content: ''; position: absolute; bottom: 0; left: 0; right: 0; height: 3px; background: var(--aws-orange); }}
        .container {{ max-width: 1200px; margin: 0 auto; padding: 24px 20px; }}
        .summary-box {{ background: var(--bg-card); border-radius: 8px; margin-bottom: 16px; padding: 24px; border: 1px solid var(--border); border-left: 4px solid var(--aws-dark); box-shadow: 0 1px 3px rgba(0,0,0,0.04); }}
        .summary-box:hover {{ box-shadow: 0 2px 8px rgba(0,0,0,0.08); }}
        .summary-title {{ color: var(--aws-dark); font-size: 1.15rem; font-weight: 600; margin: 0 0 16px 0; padding-bottom: 12px; border-bottom: 1px solid var(--border); }}
        .summary-box p {{ color: var(--text-secondary); font-size: 0.925rem; margin-bottom: 10px; }}
        .bar-container {{ display: flex; background-color: #eaeded; border-radius: 20px; overflow: hidden; margin: 16px 0; height: 32px; box-shadow: inset 0 1px 2px rgba(0,0,0,0.06); }}
        .bar {{ height: 100%; display: flex; align-items: center; justify-content: center; color: white; padding: 0 12px; font-size: 0.8rem; font-weight: 600; white-space: nowrap; }}
        .bar.passed {{ background-color: var(--pass-green); }}
        .bar.failed {{ background-color: var(--fail-red); }}
        .bar.critical {{ background-color: var(--critical); }}
        .bar.high {{ background-color: var(--high); }}
        .bar.medium {{ background-color: var(--medium); color: var(--text-primary); }}
        .bar.low {{ background-color: var(--low); }}
        .bar-text {{ text-shadow: 0 1px 1px rgba(0,0,0,0.2); }}
        table {{ width: 100%; border-collapse: separate; border-spacing: 0; background: var(--bg-card); border-radius: 6px; overflow: hidden; border: 1px solid var(--border); font-size: 0.875rem; margin-top: 12px; }}
        th {{ background: var(--aws-dark); color: #fff; padding: 12px 14px; text-align: left; font-weight: 600; font-size: 0.8rem; text-transform: uppercase; letter-spacing: 0.04em; position: sticky; top: 0; }}
        td {{ padding: 12px 14px; border-bottom: 1px solid var(--border); vertical-align: top; }}
        tr:last-child td {{ border-bottom: none; }}
        tr:nth-child(even) {{ background: var(--bg-light); }}
        tr:hover {{ background: #f0f4f8; }}
        tr.fail {{ background: #fdf3f0 !important; border-left: 3px solid var(--fail-red); }}
        tr.fail td {{ color: var(--text-primary); }}
        tr.pass {{ background: #f1f8f1 !important; border-left: 3px solid var(--pass-green); }}
        tr.pass td {{ color: var(--text-primary); }}
        .result {{ text-transform: uppercase; font-weight: 700; font-size: 0.7rem; padding: 3px 10px; border-radius: 12px; display: inline-block; line-height: 1.2; margin-top: 8px; }}
        tr.fail .result {{ background: var(--fail-red); color: #fff; }}
        tr.pass .result {{ background: var(--pass-green); color: #fff; }}
        .badge {{ padding: 2px 8px; border-radius: 10px; font-size: 0.75rem; font-weight: 600; display: inline-block; }}
        .badge-pass {{ background: #1b8a2d; color: #fff; }}
        .badge-fail {{ background: #d13212; color: #fff; }}
        .badge-partial {{ background: #f2a900; color: #16191f; }}
        details {{ border: 1px solid var(--border); border-radius: 6px; overflow: hidden; margin-bottom: 6px; }}
        details summary {{ font-weight: 600; font-size: 0.9rem; padding: 10px 16px; background: var(--bg-light); cursor: pointer; border-radius: 6px; list-style: none; }}
        details summary::-webkit-details-marker {{ display: none; }}
        details summary::before {{ content: none; }}
        details[open] summary::before {{ content: none; }}
        details[open] summary {{ background: var(--aws-dark); color: #fff; border-radius: 6px 6px 0 0; }}
        details summary:hover {{ background: #eaeded; }}
        details[open] summary:hover {{ background: #37475a; }}
        code {{ background: #f0f2f4; padding: 2px 6px; border-radius: 3px; font-family: var(--font-mono); font-size: 0.85rem; color: var(--aws-dark); }}
        h3 {{ font-weight: 600; }}
        @media print {{
            body {{ background: #fff; }}
            .summary-box {{ break-inside: avoid; box-shadow: none; border: 1px solid #ccc; }}
            .header {{ background: var(--aws-dark) !important; -webkit-print-color-adjust: exact; print-color-adjust: exact; }}
        }}
        @media (max-width: 768px) {{
            .container {{ padding: 12px; }}
            .summary-box {{ padding: 16px; }}
            .header h1 {{ font-size: 1.3rem; }}
            table {{ font-size: 0.8rem; }}
            th, td {{ padding: 8px 10px; }}
        }}
    </style>
</head>
<body>
    <div class="header">
        <h1>Security Hub Compliance Analyzer (SHCA) Summary Report</h1>
    </div>

    <div class="container">

        <!-- Overview Tiles -->
        <div style="display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-bottom:16px;">
            <div class="summary-box" style="padding:28px;">
                <div style="color:var(--text-secondary);font-size:0.8rem;text-transform:uppercase;letter-spacing:0.05em;">NIST SP 800-53 Rev. 5 Compliance</div>
                <div style="font-size:3.5rem;font-weight:700;color:{score_color};line-height:1.1;">{overall_nist_compliance_string}</div>
                <div style="color:var(--text-secondary);font-size:0.9rem;margin-bottom:12px;">{total_compliance_controls} controls evaluated</div>
                <div class="bar-container" style="height:24px;margin:8px 0 16px;">
                    <div class="bar passed" style="width:{nist_pass_width:.1f}%;background:var(--pass-green);font-size:0.7rem;">{overall_nist_compliance_string} Passed</div>
                    <div class="bar failed" style="width:{nist_fail_width:.1f}%;background:var(--fail-red);font-size:0.7rem;">{overall_nist_compliance_failed_string} Failed</div>
                </div>
                <div style="display:flex;gap:12px;text-align:center;">
                    <div style="flex:1;background:var(--bg-light);padding:8px;border-radius:6px;">
                        <div style="font-size:1.3rem;font-weight:700;color:#1b8a2d;">{compliant_compliance_controls}</div>
                        <div style="font-size:0.7rem;color:var(--text-secondary);text-transform:uppercase;">Compliant</div>
                    </div>
                    <div style="flex:1;background:var(--bg-light);padding:8px;border-radius:6px;">
                        <div style="font-size:1.3rem;font-weight:700;color:#d13212;">{non_compliant_compliance_controls}</div>
                        <div style="font-size:0.7rem;color:var(--text-secondary);text-transform:uppercase;">Non-Compliant</div>
                    </div>
                    <div style="flex:1;background:var(--bg-light);padding:8px;border-radius:6px;">
                        <div style="font-size:1.3rem;font-weight:700;color:#b8860b;">{partially_compliant_compliance_controls}</div>
                        <div style="font-size:0.7rem;color:var(--text-secondary);text-transform:uppercase;">Partial</div>
                    </div>
                </div>
            </div>
            <div class="summary-box" style="padding:28px;">
                <div style="color:var(--text-secondary);font-size:0.8rem;text-transform:uppercase;letter-spacing:0.05em;">AWS Security Hub CSPM Security Checks</div>
                <div style="font-size:3.5rem;font-weight:700;color:var(--pass-green);line-height:1.1;">{findings_pass_pct:.2f}%</div>
                <div style="color:var(--text-secondary);font-size:0.9rem;margin-bottom:12px;">{total_findings_deduped:,} security checks performed</div>
                <div class="bar-container" style="height:24px;margin:8px 0 16px;">
                    <div class="bar passed" style="width:{findings_pass_pct:.1f}%;background:var(--pass-green);font-size:0.7rem;">{passed_findings_deduped:,} Passed</div>
                    <div class="bar failed" style="width:{findings_fail_pct:.1f}%;background:var(--fail-red);font-size:0.7rem;">{failed_findings_deduped:,} Failed</div>
                </div>
                <div style="display:flex;gap:12px;text-align:center;">
                    <div style="flex:1;background:var(--bg-light);padding:8px;border-radius:6px;">
                        <div style="font-size:1.3rem;font-weight:700;color:#860000;">{ff_critical}</div>
                        <div style="font-size:0.7rem;color:var(--text-secondary);text-transform:uppercase;">Critical</div>
                    </div>
                    <div style="flex:1;background:var(--bg-light);padding:8px;border-radius:6px;">
                        <div style="font-size:1.3rem;font-weight:700;color:#d13212;">{ff_high}</div>
                        <div style="font-size:0.7rem;color:var(--text-secondary);text-transform:uppercase;">High</div>
                    </div>
                    <div style="flex:1;background:var(--bg-light);padding:8px;border-radius:6px;">
                        <div style="font-size:1.3rem;font-weight:700;color:#b8860b;">{ff_medium}</div>
                        <div style="font-size:0.7rem;color:var(--text-secondary);text-transform:uppercase;">Medium</div>
                    </div>
                    <div style="flex:1;background:var(--bg-light);padding:8px;border-radius:6px;">
                        <div style="font-size:1.3rem;font-weight:700;color:#0073bb;">{ff_low}</div>
                        <div style="font-size:0.7rem;color:var(--text-secondary);text-transform:uppercase;">Low</div>
                    </div>
                </div>
            </div>
        </div>

        <div class="summary-box">
            <h2 class="summary-title">Monitoring Summary</h2>
            <p>This assessment evaluated <strong>{total_aws_account_ids} AWS account(s)</strong> ({account_ids_list}) encompassing <strong>{total_resource_ids:,} unique resources</strong> across <strong>{total_services} AWS services</strong>. A total of <strong>{total_findings_deduped:,} security checks</strong> were performed against those resources, each evaluating a Security Hub security control against a unique resource. These checks map to <strong>{total_compliance_controls} NIST SP 800-53 Rev. 5 controls</strong>, resulting in <strong>{total_findings:,} control-level evaluations</strong>.</p>
            <p><em><strong>Note:</strong> This report excludes services with no deployed resources and non-actionable finding statuses. Scores may differ from the Security Hub console, which includes all services and uses binary pass/fail per control.</em></p>
        </div>

        <div class="summary-box">
            <h2 class="summary-title">Out of Scope</h2>
            <p>The following items were excluded from this assessment and are not reflected in the compliance scores or findings below.</p>
            {oos_table}
            <p style="margin-top:12px;"><em>Disabled rules prevent Security Hub from evaluating associated resources. Suppressed findings hide FAILED results for specific resources. Services not in use were auto-detected via AWS Config and excluded because no applicable resources exist.</em></p>
            {unmapped_html}
        </div>

        <div class="summary-box">
            <h2 class="summary-title">Prioritized Action List</h2>
            <p>Based on our findings, we recommend the following actions:</p>
            {action_html}
        </div>

        <div class="summary-box">
            <h2 class="summary-title">Compliance Controls Table</h2>
            {html_table}
        </div>

    </div>
</body>
</html>
"""

    html_sections = create_html_sections(unique_rule_status_mapping)
    html_report += "".join(html_sections)

    return html_report





