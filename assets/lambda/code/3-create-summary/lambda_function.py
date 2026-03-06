"""
This Lambda function analyzes results from previous runs stored in an S3 bucket
and creates a consolidated CSV file with a summary. It first connects to the
specified S3 bucket to retrieve relevant files with results in CSV format.
These files are read and their data is merged into a single Pandas DataFrame.
Basic analysis is then performed on the consolidated data, such as counting
records and values for each column. Finally, the analyzed data is written out
to a new CSV file and uploaded back to the S3 bucket under a specified key
for later consumption.
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


def lambda_handler(event, context):  # pylint: disable=unused-argument
    """
    Lambda function that processes SecurityHub findings data.

    Retrieves condensed findings data, summary data, and other related files
    from S3. Performs initial data cleaning on the condensed findings.

    Args:
        event: The event data that triggered the Lambda function. It is required
            by AWS Lambda, even if it's not used in this function.
        context: The runtime information provided by AWS Lambda. It is required
            by AWS Lambda, even if it's not used in this function.
    """
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
            [],  # No excluded services for per-account reports
            0,   # No excluded status count for per-account reports
            0,   # No excluded service count for per-account reports
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
        key (str): S3 object key.

    Returns:
        pd.DataFrame: DataFrame populated from the CSV data.
    """
    logger.info("Retrieving data from S3.")
    response = s3_client.get_object(Bucket=bucket_name, Key=key)
    csv_string = response["Body"].read().decode("utf-8")
    df = pd.read_csv(StringIO(csv_string))
    logger.info("Data retrieved from S3.")
    return df


def put_dataframe_to_s3(df: pd.DataFrame, key: str) -> None:
    """
    Uploads a Pandas DataFrame to an S3 bucket as a CSV.

    Args:
        df (pd.DataFrame): The DataFrame to upload.
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
        pd.DataFrame: A copy of the DataFrame with whitespace stripped
        from object columns.
    """
    logger.info("Removing leading and trailing whitespace from DataFrame columns.")
    cleaned_data = df.apply(
        lambda col: col.str.strip() if col.dtype == "object" else col
    )
    logger.info("Leading and trailing whitespace removed from DataFrame columns.")
    return cleaned_data


def generate_narrative(row: pd.Series) -> str:
    """
    Generates a narrative string describing a compliance assessment row.
    """
    logger.info("Generating narrative string from DataFrame row.")
    datetime_format_with_microseconds = "%Y-%m-%d %H:%M:%S.%f%z"
    datetime_format_without_microseconds = "%Y-%m-%d %H:%M:%S%z"
    datetime_string = row["lastobservedat"]

    try:
        logger.info("Trying to parse datetime with microseconds: %s", datetime_string)
        observed_at = datetime.strptime(
            datetime_string, datetime_format_with_microseconds
        )
    except ValueError as e:
        logger.info("Microseconds not present, trying without them: %s", e)
        observed_at = datetime.strptime(
            datetime_string, datetime_format_without_microseconds
        )

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


def create_control_summary_of_findings_data(
    clean_condensed_data: pd.DataFrame,
    securityhub_summary_csv_key: str,
):
    """
    Create a summary of findings data for each control.
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
                "rule_id": lambda x: list(set(x)),
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
    put_dataframe_to_s3(findings_dataframe_grouped, securityhub_summary_csv_key)
    logger.info("%s written to S3.", securityhub_summary_csv_key)

    # Calculate the average percentage of compliance
    percentage_compliant_control_ids = (
        findings_dataframe_grouped["percentage"].str.rstrip("%").astype(float).mean()
    )
    logger.info("%s Average percentage of compliance", percentage_compliant_control_ids)

    # Create html table for use in Executive Summary
    html_dataframe = findings_dataframe_grouped.copy()

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

    for index, row in html_dataframe.iterrows():
        try:
            html_dataframe.at[index, "Last Time Assessed"] = pd.to_datetime(
                row["Last Time Assessed"], utc=True
            ).strftime("%B %d, %Y at %I:%M %p %Z")
        except ValueError as e:
            logger.error(
                "Error converting date string: %s - Error: %s",
                row["Last Time Assessed"],
                e,
            )

    html_table = html_dataframe.to_html(index=False)

    put_dataframe_to_s3(findings_dataframe_grouped, securityhub_summary_csv_key)

    return html_table, percentage_compliant_control_ids


def write_and_upload_report(report, key):
    """
    Write and upload a report to S3.
    """
    logger.info("Writing and uploading %s to S3.", key)
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
    logger.info("%s written and uploaded to S3.", key)


def determine_compliance_status(findings: pd.Series) -> str:
    """
    Determine overall compliance status from audit findings.

    Since NOT_AVAILABLE and WARNING are filtered out upstream,
    findings will only contain PASSED and/or FAILED.

    Returns:
        str: "compliant", "non-compliant", "partially compliant", or "unknown"
    """
    if "PASSED" in findings.values and "FAILED" in findings.values:
        return "partially compliant"
    if "PASSED" in findings.values:
        return "compliant"
    if "FAILED" in findings.values:
        return "non-compliant"
    return "unknown"


def calculate_percentage(findings: pd.Series) -> str:
    """
    Calculate percentage of findings that passed.
    """
    passed = findings.value_counts().get("PASSED", 0)
    total = len(findings)
    return f"{passed / total:.2%}"


def determine_rule_compliance_status(findings):
    """
    Determine compliance status of a security rule from audit findings.
    """
    logger.info("Determining rule compliance status of findings")
    if all(findings == "PASSED"):
        return "Passed"
    return "Failed"


def add_columns_to_rules(rules):
    """Add metrics columns to the rules DataFrame."""
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


def generate_metrics_condensed_data(
    clean_condensed_data: pd.DataFrame, percentage_compliant_control_ids: float
):
    """Generate condensed metrics data from analysis results."""
    logger.info("Generating metrics condensed data.")

    print("Clean condensed data:")
    print(clean_condensed_data.head(1))

    # <-----------Calculate declared variables related to Accounts----------->
    total_aws_account_ids = clean_condensed_data["aws_account_id"].nunique()
    print("\nTotal AWS Account IDs:", total_aws_account_ids)

    total_records = len(clean_condensed_data)
    print("Total Records:", total_records)

    # <-----------Calculate declared variables related to Services----------->
    total_services = clean_condensed_data["aws_service"].nunique()
    print("Total Services:", total_services)

    # <-----------Calculate declared variables related to Resources----------->
    total_resource_ids = clean_condensed_data["resource_id"].nunique()
    print("Total Resource IDs:", total_resource_ids)

    # <-----------Calculate declared variables related to Rules----------->
    total_rule_ids = clean_condensed_data["rule_id"].nunique()
    print("Total Rule IDs:", total_rule_ids)

    aggregation_functions = {
        "compliance_status": lambda statuses: (
            "FAILED" if "FAILED" in statuses.values else "PASSED"
        ),
        "title": "first",
        "description": "first",
        "remediation": "first",
        "reference": "first",
        "severity": "first",
    }

    rule_status_aggregated = (
        clean_condensed_data.groupby("rule_id").agg(aggregation_functions).reset_index()
    )

    if "resource_id" in rule_status_aggregated.columns:
        rule_status_aggregated = rule_status_aggregated.drop(columns=["resource_id"])

    unique_rule_status_mapping = rule_status_aggregated.drop_duplicates(
        subset=["rule_id"]
    )

    rules = (
        clean_condensed_data.groupby(["rule_id", "compliance_status"])
        .size()
        .unstack(fill_value=0)
    )

    print("\nRules DataFrame:")
    print(rules.head(1))

    all_rule_ids = clean_condensed_data.groupby("rule_id").size()

    rules = add_columns_to_rules(rules)
    print("\nRules DataFrame after adding columns:")
    print(rules.head(1))

    total_checks_passed = rules["checks_passed"].sum()
    total_checks_failed = rules["checks_failed"].sum()
    print("\nSH Rules Passed:", total_checks_passed)
    print("SH Rules Failed:", total_checks_failed)

    rules_with_all_passes = rules[rules["checks_failed"] == 0]
    total_rule_ids_passed = len(rules_with_all_passes)
    total_rule_ids_failed = total_rule_ids - total_rule_ids_passed

    sh_rules_percent_passed = round((total_rule_ids_passed / total_rule_ids) * 100)

    top_5_rules_failed = (
        clean_condensed_data[clean_condensed_data["compliance_status"] == "FAILED"][
            "rule_id"
        ]
        .value_counts()
        .nlargest(5)
    )

    security_score = round((total_rule_ids_passed / total_rule_ids) * 100)

    failed_rules_by_severity = {
        severity: clean_condensed_data[
            (clean_condensed_data["compliance_status"] == "FAILED")
            & (clean_condensed_data["severity"] == severity)
        ]["rule_id"].nunique()
        for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    }

    total_failed_rules = sum(failed_rules_by_severity.values())

    severity_widths = {
        f"width_{severity.lower()}": (
            (count / total_failed_rules) * 100 if total_failed_rules else 0
        )
        for severity, count in failed_rules_by_severity.items()
    }

    rules_severity_percentage = {
        severity: (count / total_failed_rules) * 100 if total_failed_rules else 0
        for severity, count in failed_rules_by_severity.items()
    }

    # <-----------Calculate declared variables related to findings----------->
    df_for_findings = pd.DataFrame(clean_condensed_data)
    df_for_findings = df_for_findings[["compliance_status", "severity", "finding_id"]]
    df_for_findings = df_for_findings.drop_duplicates()

    findings_fail = df_for_findings[
        df_for_findings["compliance_status"] == "FAILED"
    ].shape[0]

    total_findings = df_for_findings.shape[0]

    severity_levels = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    severity_counts = {}
    severity_percents = {}
    findings_fail_severity = {}

    for level in severity_levels:
        count = df_for_findings[df_for_findings["severity"] == level].shape[0]
        percent = (count / total_findings) * 100 if total_findings else 0
        fail_count = df_for_findings[
            (df_for_findings["severity"] == level)
            & (df_for_findings["compliance_status"] == "FAILED")
        ].shape[0]
        severity_counts[level] = count
        severity_percents[level] = percent
        findings_fail_severity[level] = fail_count

    failed_findings_by_resource = (
        clean_condensed_data[clean_condensed_data["compliance_status"] == "FAILED"]
        .groupby("resource_id")["finding_id"]
        .nunique()
        .sort_values(ascending=False)
        .nlargest(5)
    )

    # <-----------Calculate declared variables related to controls----------->
    if "compliance_control_id" not in clean_condensed_data.columns:
        raise ValueError(
            "Column 'compliance_control_id' does not exist in the DataFrame"
        )

    total_compliance_controls = clean_condensed_data["compliance_control_id"].nunique()
    print("Total Compliance Controls:", total_compliance_controls)

    compliance_controls = (
        clean_condensed_data.groupby("compliance_control_id")["compliance_status"]
        .value_counts()
        .unstack(fill_value=0)
    )

    compliance_controls["compliance_percentage"] = (
        compliance_controls.get("PASSED", 0)
        / (compliance_controls.get("PASSED", 0) + compliance_controls.get("FAILED", 0))
        * 100
    )

    compliance_controls["compliance_status"] = compliance_controls.apply(
        lambda row: (
            "compliant"
            if row.get("FAILED", 0) == 0
            else ("non-compliant" if row.get("PASSED", 0) == 0 else "partially compliant")
        ),
        axis=1,
    )

    overall_nist_compliance = percentage_compliant_control_ids

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
        "clean_condensed_data": clean_condensed_data,
        "total_aws_account_ids": total_aws_account_ids,
        "total_services": total_services,
        "total_resource_ids": total_resource_ids,
        "total_records": total_records,
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
        "total_compliance_controls": total_compliance_controls,
        "compliant_compliance_controls": compliant_compliance_controls,
        "non_compliant_compliance_controls": non_compliant_compliance_controls,
        "partially_compliant_compliance_controls": partially_compliant_compliance_controls,
        "overall_nist_compliance": overall_nist_compliance,
        "failed_findings_by_resource": failed_findings_by_resource,
        "total_checks_passed": total_checks_passed,
        "total_checks_failed": total_checks_failed,
        "failed_findings_by_severity": findings_fail_severity,
        "total_failed_findings": findings_fail,
        "severity_percents": severity_percents,
    }


def create_html_sections(dataframe):
    """Create HTML sections from compliance data."""
    sorted_data = dataframe.sort_values(by="rule_id")
    html_sections = []

    for _, row in sorted_data.iterrows():
        severity_class = "fail" if row["compliance_status"] == "FAILED" else "pass"
        section_title = row["rule_id"]
        rows_html = create_rows_html(row)

        html_sections.append(
            f"""
            <details class='details' {"open" if row["compliance_status"] == "FAILED" else ""}>
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


def create_rows_html(row):
    """Generate HTML for a table row from compliance data."""
    severity_class = "fail" if row["compliance_status"] == "FAILED" else "pass"

    title_html = f"<strong>Title:</strong> {row.get('title', 'N/A')}"
    severity_html = f"<strong>Severity:</strong> {row.get('severity', 'N/A')}"
    description_html = f"<strong>Description:</strong> {row.get('description', 'N/A')}"
    remediation_html = f"<strong>Remediation:</strong> {row.get('remediation', 'N/A')}"
    reference_html = (
        f"<strong>Reference:</strong> <a href='"
        f"{row.get('reference', 'N/A')}'>"
        f"{row.get('reference', 'N/A')}</a>"
    )

    combined_html = (
        f"{title_html}<br>"
        f"{severity_html}<br>"
        f"{description_html}<br>"
        f"{remediation_html}<br>"
        f"{reference_html}"
    )

    return f"""
        <tr class='{severity_class}'>
            <td>
                {combined_html}
            </td>
            <td class='result'>{row['compliance_status'].capitalize()}</td>
        </tr>
    """


def generate_analysis_summary_report_html_report(
    metrics_condensed_data,
    clean_condensed_data,
    html_table,
    disabled_rules_data,
    suppressed_findings_data,
    excluded_services,
    excluded_status_count,
    excluded_service_count,
):
    """Generate an HTML report of the analysis summary."""
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
    unique_account_ids = clean_condensed_data["aws_account_id"].unique()
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

    total_rules_pass_percentage = (total_rule_ids_passed / total_rule_ids) * 100
    total_rules_fail_percentage = (total_rule_ids_failed / total_rule_ids) * 100

    # Initialize the variables
    disabled_rules_count = 0
    disabled_rules_list = ""

    if not disabled_rules_data.empty:
        disabled_rules_count = len(disabled_rules_data)
        if disabled_rules_count > 0:
            disabled_rules_list = ", ".join(
                disabled_rules_data["disabled_control_id"].tolist()
            )

    logger.info("%sDisabled rules count:", disabled_rules_count)
    logger.info("%sDisabled rules list:", disabled_rules_list)

    # <-----------Control Calculations----------->
    overall_nist_compliance_string = f"{overall_nist_compliance:.2f}%"
    overall_nist_compliance_failed = 100 - overall_nist_compliance
    overall_nist_compliance_failed_string = f"{overall_nist_compliance_failed:.2f}%"

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

    metrics_condensed_data["total_findings"] = total_findings

    # Initialize the variables
    suppressed_findings_count = 0
    suppressed_findings_list = ""

    if not suppressed_findings_data.empty:
        suppressed_findings_count = len(suppressed_findings_data)
        if suppressed_findings_count > 0:
            suppressed_findings_list = ", ".join(
                suppressed_findings_data["finding_id"].tolist()
            )

    logger.info("%sSuppressed findings count:", suppressed_findings_count)
    logger.info("%sSuppressed findings list:", suppressed_findings_list)

    # <-----------Excluded Services Section----------->
    excluded_services_list = ", ".join(excluded_services) if excluded_services else "None"
    excluded_services_count = len(excluded_services)

    # <-----------Report Generation and Calculations----------->
    logger.info("Generating prioritized actions report")

    report = "\n"
    report += "1. Prioritize Remediation of Failed Rule Checks by Severity\n"
    for severity in ["CRITICAL", "HIGH"]:
        if severity in clean_condensed_data["severity"].unique():
            rules_failed = clean_condensed_data[
                clean_condensed_data["severity"] == severity
            ]["rule_id"].unique()
            report += f"\n  - {severity}\n"
            for rule_id in rules_failed:
                report += f"    - Rule: {rule_id}\n"

    report += "\n2. Address Top 5 Resources with the Most Failed Compliance Checks\n"
    for resource_id, count in failed_findings_by_resource.items():
        report += f"\n  - Resource: {resource_id} (Unique Failed Findings: {count})\n"

    report += "\n3. Focus on Top 5 Rules with the Highest Number of Failed Checks\n"
    for rule_id, count in top_5_rules_failed.items():
        report += f"\n  - Rule: {rule_id} (Failed Checks: {count})\n"

    logger.info("Prioritized actions report generated")

    # <-----------HTML Report Generation----------->
    html_report = f"""
<html>
<head>
    <style>
        body {{ font-family: Amazon Ember; color: #333; }}
        .header {{ background-color: #232f3e; color: #ffffff; text-align: center; padding: 20px 0; }}
        .container {{ padding: 20px; background-color: #ffffff; }}
        .summary-box {{ padding: 10px; background-color: #f7f7f7; border-radius: 5px; margin-bottom: 10px; border-left: 5px solid #232f3e; }}
        .summary-title {{ margin: 0; color: #232f3e; padding-bottom: 10px; }}
        .bar-container {{ display: flex; background-color: #e1e1e1; border-radius: 5px; overflow: hidden; margin-top: 10px; }}
        .bar {{ height: 20px; display: flex; align-items: center; justify-content: center; color: white; padding: 0 10px; }}
        .bar.passed {{ background-color: #3c763d; width: 80%; }}
        .bar.failed {{ background-color: #a94442; width: 20%; }}
        .bar.critical {{ background-color: #8B0000; }}
        .bar.high {{ background-color: #FF0000; }}
        .bar.medium {{ background-color: #FFA500; }}
        .bar.low {{ background-color: #ADD8E6; }}
        .details {{ margin-bottom: 10px; }}
        details summary {{ font-weight: bold; padding: 5px; background-color: #ddd; border-radius: 5px; cursor: pointer; }}
        table {{ width: 100%; border-collapse: collapse; background-color: #ffffff; }}
        th, td {{ padding: 8px; text-align: left; border: 1px solid #ddd; }}
        td:first-child {{ white-space: nowrap; }}
        tr.fail {{ background-color: #a94442; color: white; }}
        tr.pass {{ background-color: #3c763d; color: white; }}
        .result {{ text-transform: uppercase; font-weight: bold; }}
        .preformatted-text {{ white-space: pre-wrap; font-family: Amazon Ember; font-size: 16px; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>Security Hub Compliance Analyzer (SHCA) Summary Report</h1>
    </div>

    <div class="container">

        <div class="summary-box">
            <h2 class="summary-title">Monitoring Summary</h2>
            <p>The scope of our checks, which involve running Security Hub rules against individual AWS resources, extended to {total_aws_account_ids} AWS Account(s), {total_resource_ids} unique AWS resources, and {total_services} distinct services, thereby covering a significant portion of our cloud environment. The AWS Accounts included in this analysis are: {account_ids_list}. The assessment performed a total of {total_findings} automated security checks, each matching a Security Hub rule against a unique resource for compliance with {total_compliance_controls} NIST SP 800-53 r5 controls. These checks culminated in a security score of {sh_rules_percent_passed}%.</p>
        </div>

        <div class="summary-box">
            <h2 class="summary-title">Out of Scope</h2>
            <p>We identified {disabled_rules_count} disabled rules, {suppressed_findings_count} suppressed findings, and {excluded_services_count} excluded service(s).</p>

            <p>Disabled rules exclude all associated resources from being evaluated by the Security Hub rule. Suppressed findings prevent FAILED results from being reported by the Security Hub for a given resource. Excluded services are services not currently in use that have been removed from the scope of this analysis.</p>

            <p>Additionally, {excluded_status_count} findings with NOT_AVAILABLE or WARNING status were excluded as they do not represent actionable compliance results.</p>

            <p>These exclusions will not be included in the analysis or within the scope of this report. A further review may be necessary for complete risk assessment and management.</p>

            <p>Suppressed Findings:</p>
            <p>{suppressed_findings_list}</p>

            <p>Disabled Rules:</p>
            <p>{disabled_rules_list}</p>

            <p>Excluded Services:</p>
            <p>{excluded_services_list}</p>
        </div>

        <div class="summary-box">
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
        </div>

        <div class="summary-box">
            <h2 class="summary-title">Severity of Failed Security Hub Rules</h2>
            <div class="bar-container">
                <div class="bar low" style="flex-grow: {rules_severity_percentage.get('LOW', 0)};">{fr_count_low} Low</div>
                <div class="bar medium" style="flex-grow: {rules_severity_percentage.get('MEDIUM', 0)};">{fr_count_medium} Medium</div>
                <div class="bar high" style="flex-grow: {rules_severity_percentage.get('HIGH', 0)};">{fr_count_high} High</div>
                <div class="bar critical" style="flex-grow: {rules_severity_percentage.get('CRITICAL', 0)};">{fr_count_critical} Critical</div>
            </div>
                <p>Out of the {total_rule_ids_failed} failed Security Hub rules there were {fr_count_low} Low, {fr_count_medium} Medium, {fr_count_high} High, and {fr_count_critical} Critical.</p>
        </div>

        <div class="summary-box">
            <h2 class="summary-title">Finding Summary</h2>
                <div class="bar-container">
                <div class="bar low" style="flex-grow: {metrics_condensed_data['failed_findings_by_severity']['LOW']};">{metrics_condensed_data['failed_findings_by_severity']['LOW']} Low</div>
                <div class="bar medium" style="flex-grow: {metrics_condensed_data['failed_findings_by_severity']['MEDIUM']};">{metrics_condensed_data['failed_findings_by_severity']['MEDIUM']} Medium</div>
                <div class="bar high" style="flex-grow: {metrics_condensed_data['failed_findings_by_severity']['HIGH']};">{metrics_condensed_data['failed_findings_by_severity']['HIGH']} High</div>
                <div class="bar critical" style="flex-grow: {metrics_condensed_data['failed_findings_by_severity']['CRITICAL']};">{metrics_condensed_data['failed_findings_by_severity']['CRITICAL']} Critical</div>
            </div>
            <p>During the assessment, {metrics_condensed_data['total_failed_findings']} findings were recorded, each representing a failure of a security rule check against a unique resource. Findings are categorized based on the severity of the rule that was violated. The severity distribution of these findings is as follows:</p>
            <ul>
                {''.join(f"<li>{level.capitalize()}: {count}</li>" for level, count in metrics_condensed_data['failed_findings_by_severity'].items())}
            </ul>
        </div>

        <div class="summary-box">
            <h2 class="summary-title">Percentage of Compliant NIST 800-53 Controls</h2>
            <div class="bar-container">
                <div class="bar passed" style="width: {overall_nist_compliance:.2f}%; background-color: #4CAF50;">
                    <span class="bar-text">{overall_nist_compliance_string} Passed</span>
                </div>
                <div class="bar passed" style="width: {overall_nist_compliance_failed:.2f}%; background-color: #f44336;">
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
        </div>

        <div class="summary-box">
            <h2 class="summary-title">Prioritized Action List</h2>
            <p>Based on our findings, we recommend the following actions:</p>
            <pre style="white-space: pre-wrap; font-family: 'Amazon Ember';">
                {report}
            </pre>
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
