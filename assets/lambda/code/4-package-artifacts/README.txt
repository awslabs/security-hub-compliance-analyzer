This readme file is intended to help the reader understand how these artifacts are generated, what the folders and files contained therein are, and how they can be used to help prove the compliance of AWS resources by utilizing Security Hub NIST SP 800-53 automated security checks.

Information regarding AWS Security Hub findings from https://docs.aws.amazon.com/securityhub/latest/userguide/controls-overall-status.html
The Compliance.Status for each finding is assigned one of the following values.

    PASSED – Automatically sets the Security Hub Workflow.Status to RESOLVED.
    FAILED – Indicates that the control did not pass the security check for this finding.
    WARNING – Indicates that the check was completed, but Security Hub cannot determine whether the resource is in a PASSED or FAILED state.
    NOT_AVAILABLE – Indicates that the check cannot be completed because a server failed, the resource was deleted, or the result of the AWS Config evaluation was NOT_APPLICABLE.

Step 0. AWS Security Hub NIST SP 800-53r5 Reference
Information regarding the Security Hub SecurityControlID's, its associated AWS Config rule name, and related NIST SP 800-53r5 controls and other details is pulled down from the AWS Security Hub User Guide Security Hub Controls Reference at https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-controls-reference.html has extracted and used as a dataframe.

Step 1. AWS Security Hub Findings Extraction
All findings within AWS Security Hub are extracted and saved in a json.

Step 2. AWS Security Hub Findings Condense and Convert
The most recent finding from each control/resource id in the json is written to a csv file for better analysis and readability

Step 3.AWS Security Hub summary
A summary of all controls is created from the csv file following the following methodology
    1. compliant = all findings for the control have a value of PASSED or have a combination of PASSED and NOT_AVAILABLE
    2. non-compliant = all findings for the control have a value of FAILED or a have a combination of FAILED and NOT_AVAILABLE
    3. partially compliant = findings for the control have at least one FAILED finding and at least one PASSED finding and possibly findings of NOT_AVAILABLE

Step 4. Artifact Generation and Zip
This step creates a file for each NIST SP 800-53 control based on that control's status and stores them in two folders:

    1. controls_ready_to_import_into_rmf_tool
        - Contains controls which have only PASSED findings
    2. controls_which_require_attention
        - Contains controls which have FAILED findings

Additionally, this step retrieves and includes various files from an S3 bucket. The folders and their contents are:

    1. aws/ato_next_securityhub_rules_nist_800_53_rev_5
        - Contains aws_securityhub_controls.csv, the file provides reference for AWS Security Hub SecurityControlID's, associated AWS Config rule names, and related NIST SP 800-53r5 controls.
    2. original_findings_from_securityhub_in_json
        - Contains the original json files (securityhub_original_findings_asff.json, securityhub_original_findings_ocsf.json, and securityhub_original_findings_oscal.json ) after querying the AWS Security Hub database.
    3. condensed_findings_from_securityhub_in_csv
        - Contains a condensed version of the original findings in a csv format (securityhub_nist80053_findings_condensed.csv), with only the latest observed finding for each control/resource.
    4. control_summary_of_findings_from_securityhub_in_csv
        - Contains a summary of the compliance status of all controls, by control, in the securityhub_nist80053_findings_summary.csv file.

These files provide comprehensive data about the security state of AWS resources, based on AWS Security Hub's NIST SP 800-53 automated security checks.