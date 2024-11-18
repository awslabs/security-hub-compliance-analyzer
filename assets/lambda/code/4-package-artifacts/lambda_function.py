"""
lambda_function.py

This module contains the lambda handler function for a AWS Lambda function.

The lambda_handler function is invoked when the Lambda function is triggered. 
It creates a zip file containing artifacts and configuration information to 
demonstrate AWS resource compliance.

The function retrieves the S3 bucket name from an environment variable and uses the
Boto3 SDK to connect to S3 with the configured AWS Region. 
It then zips files in the local filesystem and uploads the archive to the S3 bucket.

This file defines:

lambda_handler(event, context): Handles Lambda function invocation. Zips files and uploads to S3. 
"""
import logging
import os
from typing import List
import datetime
import fnmatch
import zipfile
import tempfile
import shutil
from pathlib import Path
import pandas as pd
import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
region = os.environ["AWS_REGION"]
bucket_name = os.environ["BUCKET_NAME"]


def lambda_handler(event, context):  # pylint: disable=unused-argument
    """
    This function will create a zip file containing all of the required artifacts
    and information a validator will need to articulate how AWS cloud resources or
    services have been configured to meet compliance objectives.
    """
    max_used_storage_mb = 0  # Initialize max storage used
    logger.info("Clearing the /tmp directory before starting the job")
    clean_tmp_directory()
    max_used_storage_mb = max(max_used_storage_mb, log_disk_usage("at start"))
    try:
        with tempfile.TemporaryDirectory() as tmp_dir:
            logger.info("Creating tmp directories and copying files.")
            shutil.copy("README.txt", tmp_dir)

            exclude_prefixes = [
                "*findings_by_security_control_id",
                "*artifacts*.zip",
                "*.zip",
                "*original_findings_in_ocsf",
                "*original_findings_in_oscal",
            ]
            download_s3_files(
                bucket=bucket_name,
                local_dir=tmp_dir,
                start_prefix="shca/",
                exclude_prefixes=exclude_prefixes,
            )
            max_used_storage_mb = max(
                max_used_storage_mb, log_disk_usage("after downloads")
            )
            logger.info("Creating additional directories.")
            compliant_csv_path = (
                Path(tmp_dir) / "controls_ready_to_import_into_rmf_tool"
            )
            non_compliant_csv_path = Path(tmp_dir) / "controls_which_require_attention"
            os.makedirs(compliant_csv_path, exist_ok=True)
            os.makedirs(non_compliant_csv_path, exist_ok=True)

            timestamp = datetime.datetime.now().strftime("%d%b%Y%H%M%S")
            control_findings = pd.read_csv(
                (Path(tmp_dir) / "condensed_findings/nist80053_findings_condensed.csv")
            )
            control_summary = pd.read_csv(
                (
                    Path(tmp_dir)
                    / "control_summary_of_findings/nist80053_findings_summary.csv"
                )
            )
            logger.info("Creating evidence artifacts zip files")
            for _, row in control_summary.iterrows():
                control = row["compliance_control_id"].replace("/", "_")
                status = row["compliance_status"].replace(" ", "")  # removing spaces
                findings = control_findings[
                    control_findings["compliance_control_id"] == control
                ]
            for _, row in control_summary.iterrows():
                control = row["compliance_control_id"]
                status = row["compliance_status"].replace(" ", "")  # removing spaces
                findings = control_findings[
                    control_findings["compliance_control_id"] == control
                ]
                if status.lower() == "compliant":
                    findings.to_csv(
                        os.path.join(
                            compliant_csv_path, f"{control}_{status}_{timestamp}.csv"
                        ),
                        index=False,
                    )
                else:
                    findings.to_csv(
                        os.path.join(
                            non_compliant_csv_path,
                            f"{control}_{status}_{timestamp}.csv",
                        ),
                        index=False,
                    )
            # Zipping artifacts
            logger.info("Zipping files and directories to create artifacts zip")
            artifacts_zip_path = os.path.join(tmp_dir, f"artifacts_{timestamp}.zip")
            with zipfile.ZipFile(artifacts_zip_path, "w") as zipf:
                for root, dirs, files in os.walk(tmp_dir):
                    for file in files:
                        file_path = os.path.join(root, file)
                        if valid_file(file_path):
                            zipf.write(
                                file_path, arcname=os.path.relpath(file_path, tmp_dir)
                            )
            # Uploading zip file to s3
            logger.info("Uploading zip file to s3")

            # Extract the file name from the artifacts_zip_path
            zip_file_name_with_timestamp = os.path.basename(artifacts_zip_path)

            # Define the S3 object name with the correct path and
            # the dynamically generated file name
            s3_object_name = f"shca/{zip_file_name_with_timestamp}"

            upload_to_s3(artifacts_zip_path, bucket_name, s3_object_name)

            log_disk_usage("before final clear")
            print(
                (
                    "Artifacts created and zipped successfully as ",
                    f"{zip_file_name_with_timestamp}. Status code: 200",
                )
            )
            return {
                "message": "Artifacts created and zipped successfully"
                f" as {zip_file_name_with_timestamp}."
            }

    finally:
        clean_tmp_directory()
        max_used_storage_mb = max(
            max_used_storage_mb, log_disk_usage("after final cleanup")
        )

    return {
        "message": f"Artifacts created and zipped successfully as artifacts_{timestamp}.zip",
        "max_used_storage_mb": max_used_storage_mb,
        "max_memory_allocated_mb": context.memory_limit_in_mb,
    }


def log_disk_usage(phase):
    """Logs disk usage statistics to the logger.
    Args:
        phase (str): A label for the disk usage phase
    """
    try:
        with tempfile.TemporaryDirectory() as tmp_dir:
            total, used, free = shutil.disk_usage(tmp_dir)
            total_mb = total // 1024 // 1024
            used_mb = used // 1024 // 1024
            free_mb = free // 1024 // 1024
            logger.info(
                "Disk usage %s: Total: %d MB, Used: %d MB, Free: %d MB",
                phase,
                total_mb,
                used_mb,
                free_mb,
            )
            return used_mb
    except (IOError, OSError) as e:
        logger.error("%sFailed to get disk usage:", e)
        return 0  # Return 0 MB if there is an error retrieving disk usage


def valid_file(file_path: str) -> bool:
    """
    Check if a file is valid based on its extension.

    Args:
        file (str): The filename to check

    Returns:
        bool: True if the file has a valid extension, False otherwise

    This function checks if the file extension is one of the
    allowed types. It extracts the extension from the filename
    and compares it against a list of valid extensions.

    Currently it only checks the extension, additional validation
    could be added to check the file contents/type.
    """
    valid_extensions: List[str] = [".csv", ".json", ".txt", ".html"]

    file_ext = os.path.splitext(file_path)[1].lower()

    return file_ext in valid_extensions


def clean_tmp_directory():
    """Remove all files and directories in the specified temporary directory."""

    try:
        # Get a safe, system-dependent temporary directory.
        tmp_dir = tempfile.gettempdir()

        for item in os.listdir(tmp_dir):
            item_path = os.path.join(tmp_dir, item)
            if os.path.isfile(item_path) or os.path.islink(item_path):
                os.remove(item_path)
            elif os.path.isdir(item_path):
                shutil.rmtree(item_path)

    except Exception as e:
        logger.error("Error cleaning temporary directory: %s", e)


def upload_to_s3(file_name, bucket, object_name=None):
    """Upload a file to an S3 bucket

    :param file_name: File to upload
    :param bucket: Bucket to upload to
    :param object_name: S3 object name. If not specified then file_name is used
    :return: True if file was uploaded, else False
    """

    # If S3 object_name was not specified, use file_name
    if object_name is None:
        object_name = os.path.basename(file_name)

    # Upload the file
    s3_client = boto3.client("s3", region_name=region)
    s3_client.upload_file(file_name, bucket, object_name)


def download_s3_files(
    bucket: str, local_dir: str, start_prefix: str, exclude_prefixes: List[str] = None
) -> None:
    """
    Download files from an S3 bucket to a local directory.

    This function downloads files recursively from an S3 bucket to a local
    directory on disk. It supports excluding certain file prefixes from
    being downloaded.

    Parameters:
      bucket (str): Name of the S3 bucket to download files from.
      local_dir (str): Path to the local directory to download files to.
      exclude_prefixes (list, optional): List of prefixes to exclude. Files
        starting with these prefixes will be skipped.

    Returns:
      None
    """
    s3_client = boto3.client("s3")

    paginator = s3_client.get_paginator("list_objects_v2")

    for result in paginator.paginate(Bucket=bucket, Delimiter="", Prefix=start_prefix):
        for obj in result.get("Contents", []):
            key = obj["Key"]

            if any(fnmatch.fnmatch(key, p) for p in exclude_prefixes):
                logger.info("Skipping excluded file: %s", key)
                continue

            parts = key.split("/")
            filename = parts[-1]

            parent_folder = parts[-2]
            download_path = Path(local_dir) / parent_folder / filename
            download_path.parent.mkdir(parents=True, exist_ok=True)

            try:
                s3_client.download_file(bucket, key, str(download_path))
                logger.info("Downloaded %s to %s", key, download_path)
            except ClientError as e:
                logger.error("Error downloading %s: %s", key, e)
