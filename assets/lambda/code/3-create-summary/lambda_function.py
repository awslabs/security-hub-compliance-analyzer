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


def lambda_handler(event, context):
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
    #bucket_name = os.environ["BUCKET_NAME"]
    securityhub_findings_csv_key = "shca/condensed_findings/nist80053_findings_condensed.csv"
    securityhub_summary_csv_key = "shca/control_summary_of_findings/nist80053_findings_summary.csv"
    analysis_summary_html_key = "shca/analysis_summary_in_html/nist80053_analysis_summary.html"
    securityhub_disabled_rules_key = "shca/disabled_rules/disabled_rules.csv"
    securityhub_suppressed_findings_key = "shca/suppressed_findings/suppressed_findings.csv"

    condensed_data = get_dataframe_from_s3(securityhub_findings_csv_key)
    clean_condensed_data = process_whitespace(condensed_data)

    # Retrieve and process disabled rules data
    disabled_rules_data = get_dataframe_from_s3(securityhub_disabled_rules_key)

    # Retrieve and process supressed findings data
    suppressed_findings_data = get_dataframe_from_s3(securityhub_suppressed_findings_key)

    # Creates securityhub_nist80053_findings_summary.csv for post analysis
    create_control_summary_of_findings_data(
        clean_condensed_data, securityhub_summary_csv_key
    )

    # Generate the HTML table
    html_table, percentage_compliant_control_ids = (
        create_control_summary_of_findings_data(
            clean_condensed_data, securityhub_summary_csv_key
        )
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
    )

    write_and_upload_report(
        analysis_summary_html, analysis_summary_html_key
    )

    logger.info("Lambda handler completed")
    return {"statusCode": 200, "body": "Files saved to :" + securityhub_summary_csv_key}


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
    #s3_client = boto3.client("s3")
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
    """
    Generates a narrative string describing a compliance assessment row.

    It tries parsing the datetime from the 'lastobservedat' column using two
    formats with and without microseconds.

    Then it creates a narrative for the respective NIST 800-53 Control.
    """
    logger.info("Generating narrative string from DataFrame row.")
    datetime_format_with_microseconds = "%Y-%m-%d %H:%M:%S.%f%z"
    datetime_format_without_microseconds = "%Y-%m-%d %H:%M:%S%z"
    datetime_string = row["lastobservedat"]

    try:
        logger.info("Trying to parse datetime with microseconds: %s", datetime_string)
        observed_at = datetime.strptime(datetime_string, datetime_format_with_microseconds)
    except ValueError as e:
        logger.info("Microseconds not present, trying without them: %s", e)
        observed_at = datetime.strptime(datetime_string, datetime_format_without_microseconds)

    formatted_observed_at = observed_at.strftime("%B %d, %Y at %I:%M %p %Z")
    narrative = (
        f"As of the most recent evaluation on {formatted_observed_at}, "
        f"our Amazon Web Services (AWS) environment has been assessed as "
        f"{row['compliance_status']} with {row['compliance_control_id']}, "
        f"according to NIST 800-53 rev 5 "
        f"Operational Best Practices. This assessment utilized AWS Security Hub rules "
        f"{row['rule_id']} and identified a {row['percentage']} compliance rate for "
        f"{row['compliance_control_id']}, which indicates a {row['compliance_status']} "
        f"implementation of this control."
    )
    logger.info("Narrative string generated from DataFrame row.")
    return narrative


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

    findings_dataframe_grouped["narrative"] = findings_dataframe_grouped.apply(
        generate_narrative, axis=1
    )

    logger.info("Writing the CSV to S3.")
    put_dataframe_to_s3(
        findings_dataframe_grouped, securityhub_summary_csv_key
    )
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
            # Attempt to convert each date string by inferring the datetime format
            html_dataframe.at[index, "Last Time Assessed"] = pd.to_datetime(
                row["Last Time Assessed"], utc=True
            )
        except ValueError as e:
            # Log the error and the problematic date string
            logger.error(
                "Error converting date string: %s - Error: %s", row['Last Time Assessed'], e
            )

    # Convert the copied dataframe to HTML
    html_table = html_dataframe.to_html(index=False)

    # Now use the original dataframe (findings_dataframe_grouped) to create the CSV file
    # This dataframe will have the original column names and date formats
    put_dataframe_to_s3(
        findings_dataframe_grouped, securityhub_summary_csv_key
    )

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
    elif "PASSED" in findings.values:
        return "compliant"
    elif "FAILED" in findings.values:
        return "non-compliant"
    else:
        return "unknown"


# This function caculates the control percentages for the securityhub_nist80053_findings_summary.csv
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
    else:
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
    """Create HTML sections from compliance data.

    This function takes in a dataframe containing compliance data and 
    generates HTML sections to display the results. It sorts the data 
    by rule ID, then iterates through each row to create a <details> 
    element for that section. 

    The section title is pulled from the 'rule_id' column. A 'fail' or 
    'pass' class is set based on the 'compliance_status'. HTML rows 
    are generated from each row data. 

    The <details> tag is conditionally opened if the status is 
    'FAILED'. Finally, all sections are appended to an HTML list and
    returned.
    """
    sorted_data = dataframe.sort_values(by="rule_id")

    html_sections = []
    for _, row in sorted_data.iterrows():
        severity_class = "fail" if row["compliance_status"] == "FAILED" else "pass"
        section_title = row["rule_id"]  # Use 'rule_id' as the section title
        rows_html = create_rows_html(row)

        # Note that the <details> tag should be open if 'compliance_status' is 'FAILED'
        html_sections.append(
            f"""
            <details class='details' {'open' if severity_class == 'fail' else ''}>
                <summary>{section_title}</summary>
                <table>
                    <tr>
                        <th>Title</th>
                        <th>Result</th>
                    </tr>
                    {rows_html}
                </table>
            </details>
        """
        )

    return html_sections


# Helper function to create HTML rows for each rule
def create_rows_html(row):
    """Generate HTML for a table row from compliance data.

    This function takes a row of compliance data and generates the 
    HTML needed to display it in a table. It determines the row 
    class based on the compliance status. 

    HTML strings are created for each data field, with field names 
    bolded. These are combined with line breaks for a stacked 
    appearance. 

    The formatted data and result are returned within <tr> tags to 
    define a single row. This HTML can then be included in the 
    overall compliance report table.
    """
    # Define the class for the row based on compliance status
    severity_class = "fail" if row["compliance_status"] == "FAILED" else "pass"

    # Construct the HTML for each data cell
    title_html = f"<strong>Title:</strong> {row.get('title', 'N/A')}"
    severity_html = f"<strong>Severity:</strong> {row.get('severity', 'N/A')}"
    description_html = f"<strong>Description:</strong> {row.get('description', 'N/A')}"
    remediation_html = f"<strong>Remediation:</strong> {row.get('remediation', 'N/A')}"
    reference_html = (
        f"<strong>Reference:</strong> <a href='{row.get('reference', '#')}'>"
        f"{row.get('reference', 'N/A')}</a>"
    )
    # Combine the HTML strings with line breaks for a stacked appearance
    combined_html = (
        f"{title_html}<br>"
        f"{severity_html}<br>"
        f"{description_html}<br>"
        f"{remediation_html}<br>"
        f"{reference_html}"
    )
    # Return the formatted HTML for the row
    return f"""
        <tr class='{severity_class}'>
            <td>
                {combined_html}
            </td>
            <td class='result'>{row['compliance_status'].capitalize()}</td>
        </tr>
    """


# This function generates the executive summary report in html format
def generate_analysis_summary_report_html_report(
    metrics_condensed_data,
    clean_condensed_data,
    html_table,
    disabled_rules_data,
    suppressed_findings_data,
):
    """Generate an HTML report of the analysis summary.

    This function takes in condensed data from the analysis metrics,
    clean data, the generated HTML table, and data about disabled
    rules and suppressed findings. 

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
    #overall_nist_compliance_string = "{:.2f}%".format(overall_nist_compliance_string)

    overall_nist_compliance_failed = 100 - overall_nist_compliance
    overall_nist_compliance_failed_string = f"{overall_nist_compliance_failed:.2f}%"
    #overall_nist_compliance_failed_string = "{:.2f}%".format(
    #    overall_nist_compliance_failed
    #)

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
    total_findings = sum(metrics_condensed_data["failed_findings_by_severity"].values())
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
    report # The 'report' variable accumulates the report content.
    #It is used later for output or further processing.

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
    html_report = f"""
<html>
<head>
    <style>
        /* Base styles */
        body {{
            font-family: Amazon Ember;
            color: #333;
        }}

        /* Header styles */
        .header {{
            background-color: #232f3e;
            color: #ffffff;
            text-align: center;
            padding: 20px 0;
        }}

        /* Container styles */
        .container {{
            padding: 20px;
            background-color: #ffffff;
        }}

        /* Summary box styles */
        .summary-box {{
            padding: 10px;
            background-color: #f7f7f7;
            border-radius: 5px;
            margin-bottom: 10px;
            border-left: 5px solid #232f3e;
        }}

        .summary-title {{
            margin: 0;
            color: #232f3e;
            padding-bottom: 10px;
        }}

        /* Bar styles */
        .bar-container {{
            display: flex;
            background-color: #e1e1e1;
            border-radius: 5px;
            overflow: hidden;
            margin-top: 10px;
        }}

        .bar {{
            height: 20px;
            display: flex;
            align-items: center;
            justify-content: center;
            color: white;
            padding: 0 10px;
        }}

        .bar.passed {{
            background-color: #3c763d;
            width: 80%;
        }}

        .bar.failed {{
            background-color: #a94442;
            width: 20%;
        }}

        .bar.critical {{ background-color: #8B0000; }}
        .bar.high {{ background-color: #FF0000; }}
        .bar.medium {{ background-color: #FFA500; }}
        .bar.low {{ background-color: #ADD8E6; }}

        /* Details styles */
        .details {{
            margin-bottom: 10px;
        }}

        details summary {{
            font-weight: bold;
            padding: 5px;
            background-color: #ddd;
            border-radius: 5px;
            cursor: pointer;
        }}

        /* Table styles */
        table {{
            width: 100%;
            border-collapse: collapse;
            background-color: #ffffff;
        }}

        th, td {{
            padding: 8px;
            text-align: left;
            border: 1px solid #ddd;
        }}

        tr.fail {{
            background-color: #a94442;
            color: white;
        }}

        tr.pass {{
            background-color: #3c763d;
            color: white;
        }}

        /* Result styles */
        .result {{
            text-transform: uppercase;
            font-weight: bold;
        }}

        /* Preformatted text styles */
        .preformatted-text {{
            white-space: pre-wrap;
            font-family: Amazon Ember; 
            font-size: 16px; 
        }}
    </style>
</head>
<body>
    <div class="header">
        <h1>Security Hub Compliance Analyzer (SHCA) Summary Report</h1>
    </div>

    <!-- Security Hub Rule Results -->
    <div class="container"> <!-- OPEN CONTAINER-->
        
        <!-- Monitoring Summary -->
        <div class="summary-box"> <!-- OPEN -->
            <h2 class="summary-title">Monitoring Summary</h2>
            <p>The scope of our checks, which involve running Security Hub rules against individual AWS resources, extended to {total_aws_account_ids} AWS Account(s), {total_resource_ids} unique AWS resources, and {total_services} distinct services, thereby covering a significant portion of our cloud environment. The AWS Accounts included in this analysis are: {account_ids_list}. The assessment performed a total of {total_findings} automated security checks, each matching a Security Hub rule against a unique resource for compliance with {total_compliance_controls} NIST SP 800-53 r5 controls. These checks culminated in a security score of {sh_rules_percent_passed}%.</p>
        </div> <!-- CLOSE -->

        <div class="summary-box"> <!-- OPEN -->
            <h2 class="summary-title">Out of Scope</h2>
            <p>We identified {disabled_rules_count} disabled rules and {suppressed_findings_count} suppressed findings. </p>
            
            <p>Disabled rules exclude all associated resources from being evaluated by the Security Hub rule. Suppressed findings prevent FAILED results from being reported by the Security Hub for a given resource.</p>
            
            <p>These exclusions will not be included in the analysis or within the scope of this report. A further review may be necessary for complete risk assessment and management.</p>
            
            <p>Suppressed Findings:</p>
            <p>{suppressed_findings_list}</p>
            
            <p>Disabled Rules:</p>
            <p>{disabled_rules_list}</p>
        </div> <!-- CLOSE -->


        
        <div class="summary-box"> <!-- OPEN -->
            <h2 class="summary-title">Security Hub Rule Results</h2>
            <div class="bar-container">
                <div class="bar passed" style="width: {total_rules_pass_percentage}%; background-color: #4CAF50;">
                    <span class="bar-text">{total_rule_ids_passed} Passed</span>
                </div>
                <div class="bar failed" style="width: {total_rules_fail_percentage}%; background-color: #f44336;">
                    <span class="bar-text">{total_rule_ids_failed} Failed</span>
                </div>
            </div>
            <p>Out of the {total_rule_ids} Security Hub rules assessed, {total_rule_ids_passed} passed and {total_rule_ids_failed} failed. A rule is deemed 'passed' if it successfully meets the criteria across all unique resources. Conversely, a rule is marked as 'failed' if it does not meet the criteria on any unique resource.</p>
        </div> <!-- CLOSE -->

        <!-- Severity of Failed Security Hub Rules -->
        <div class="summary-box"> 
            <h2 class="summary-title">Severity of Failed Security Hub Rules</h2>
            <div class="bar-container">
                <div class="bar low" style="flex-grow: {rules_severity_percentage['LOW']};">{fr_count_low} Low</div>
                <div class="bar medium" style="flex-grow: {rules_severity_percentage['MEDIUM']};">{fr_count_medium} Medium</div>
                <div class="bar high" style="flex-grow: {rules_severity_percentage['HIGH']};">{fr_count_high} High</div>
                <div class="bar critical" style="flex-grow: {rules_severity_percentage['CRITICAL']};">{fr_count_critical} Critical</div>
            </div>
                <p>Out of the {total_rule_ids_failed} failed Security Hub rules there were {fr_count_low} Low, {fr_count_medium} Medium, {fr_count_high} High, and {fr_count_critical} Critical.</p>    
        </div> <!-- CLOSE -->
      
        <!-- Finding Summary -->
        <div class="summary-box"> <!-- OPEN -->
            <h2 class="summary-title">Finding Summary</h2>
                <div class="bar-container">
                <div class="bar low" style="flex-grow: {metrics_condensed_data['severity_percents']['LOW']};">{metrics_condensed_data['failed_findings_by_severity']['LOW']} Low</div>
                <div class="bar medium" style="flex-grow: {metrics_condensed_data['severity_percents']['MEDIUM']};">{metrics_condensed_data['failed_findings_by_severity']['MEDIUM']} Medium</div>
                <div class="bar high" style="flex-grow: {metrics_condensed_data['severity_percents']['HIGH']};">{metrics_condensed_data['failed_findings_by_severity']['HIGH']} High</div>
                <div class="bar critical" style="flex-grow: {metrics_condensed_data['severity_percents']['CRITICAL']};">{metrics_condensed_data['failed_findings_by_severity']['CRITICAL']} Critical</div>
            </div>
            <p>During the assessment, {metrics_condensed_data['total_failed_findings']} findings were recorded, each representing a failure of a security rule check against a unique resource. Findings are categorized based on the severity of the rule that was violated. The severity distribution of these findings is as follows:</p>
            <ul>
                {''.join(f"<li>{level.capitalize()}: {count}</li>" for level, count in metrics_condensed_data['failed_findings_by_severity'].items())}
            </ul>
        </div> <!-- CLOSE -->

        <!-- Compliance Summary -->

        <!-- Percentage of Compliant NIST 800-53 Controls -->
        <div class="summary-box">  <!-- OPEN -->
            <h2 class="summary-title">Percentage of Compliant NIST 800-53 Controls</h2>
            <div class="bar-container">
                <div class="bar passed" style="width: {overall_nist_compliance}%; background-color: #4CAF50;">
                    <span class="bar-text">{overall_nist_compliance_string} Passed</span>
                </div>
                <div class="bar passed" style="width: {overall_nist_compliance_failed}%; background-color: #f44336;">
                    <span class="bar-text">{overall_nist_compliance_failed_string} Failed</span>
                </div>
            </div>
            <p>In line with NIST SP 800-53 standards, we managed {total_compliance_controls} controls. The compliance distribution is:</p>
            <ul>
                <li>Compliant: {compliant_compliance_controls}</li>
                <li>Non-Compliant: {non_compliant_compliance_controls}</li>
                <li>Partially Compliant: {partially_compliant_compliance_controls}</li>
            </ul>
            <p>Overall NIST Compliance stands at {overall_nist_compliance_string}, indicating a {compliance_descriptor} commitment to security and regulatory adherence.</p>
        </div> <!-- CLOSE -->
        
        <!-- Prioritized Action List --> <!-- OPEN -->
        <div class="summary-box">
            <h2 class="summary-title">Prioritized Action List</h2>
            <p>Based on our findings, we recommend the following actions:</p>
            <pre style="white-space: pre-wrap; font-family: 'Amazon Ember';">
                {report}
            </pre>

        </div> <!-- CLOSE -->
        <!-- End of Prioritized Action List -->
        
        <!-- Compliance Controls Table -->
        <div class="summary-box"> <!-- OPEN -->
            <h2 class="summary-title">Compliance Controls Table</h2>
            {html_table}
        </div> <!-- CLOSE -->
        <!-- End of Compliance Controls Table -->

    </div> <!-- CLOSE CONTAINER-->
</body>
</html>
"""

    #    try:
    #        metrics_condensed_data = generate_metrics_condensed_data(clean_condensed_data)
    #    except Exception as e:
    #        pass

    # Generate HTML for the rules table using the dataframe
    html_sections = create_html_sections(unique_rule_status_mapping)

    # Append the HTML sections to your main HTML report
    html_report += "".join(html_sections)

    # Return the final HTML report
    return html_report
