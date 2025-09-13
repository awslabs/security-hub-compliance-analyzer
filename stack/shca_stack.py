"""
Security Hub Compliance Analyzer CDK Stack

This CDK stack defines the necessary AWS resources to run Security Hub
findings analysis using Lambda and Step Functions.

The stack defines:

An IAM role for the Lambda functions to assume
A KMS key for encrypting secrets
A Lambda layer containing the awswrangler library
A Step Functions state machine that orchestrates the analysis workflow
Lambda functions for each step in the workflow
Logs and metrics for monitoring the analysis jobs
The stack is parameterized to allow configuration via CDK context for
the target AWS account and region.
"""

from typing import List
import os
import cdk_nag as cdknag
from aws_cdk import aws_ec2 as ec2
from aws_cdk import aws_events as events
from aws_cdk import aws_events_targets as targets
from aws_cdk import aws_iam as iam
from aws_cdk import aws_kms as kms
from aws_cdk import aws_logs as logs
from aws_cdk import aws_lambda as lambda_
from aws_cdk import aws_s3 as s3
from aws_cdk import aws_sns as sns
from aws_cdk import aws_sns_subscriptions as subscriptions
from aws_cdk import aws_sqs as sqs
from aws_cdk import aws_stepfunctions as stepfunctions
from aws_cdk import aws_stepfunctions_tasks as stepfunctions_tasks
from aws_cdk import CfnOutput
from aws_cdk import Duration
from aws_cdk import RemovalPolicy
from aws_cdk import Stack
from aws_cdk import Size
from aws_cdk import Tags
from constructs import Construct


class ShcaStack(Stack):
    """
    Security Hub Compliance Analyzer CDK Stack

    This class defines a CDK stack to deploy the necessary AWS resources
    for the Security Hub Analysis Generator application. It creates the
    VPC, S3 bucket, Lambda functions, Step Functions state machine,
    IAM roles and policies, and other supporting resources.
    """

    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        """
        Constructor method for the ShcaStack class.

        Parameters:
            scope (Construct): The CDK scope
            construct_id (str): Unique id for the construct
            **kwargs: Additional arguments passed to parent construct
        """
        super().__init__(scope, construct_id, **kwargs)

        # pylint: disable=line-too-long
        # fmt: off
        self.aws_wrangler_layer = "assets/lambda/layers/awswrangler/awswrangler-layer-3.8.0-py3.11.zip"

        # Set variables from cdk context
        self.stack_env = self.node.try_get_context("environment")
        self.vpc_cidr = self.node.try_get_context("vpc_cidr")
        self.cidr_mask = self.node.try_get_context("cidr_mask")

        # Validate that the cidr_mask value is present
        if self.cidr_mask is None:
            raise ValueError("cidr_mask value not found in cdk.json")

        self.schedule_frequency_days = self.node.try_get_context(
            "schedule_frequency_days"
        )

        self.artifact_replicas_to_retain = self.node.try_get_context(
            "artifact_replicas_to_retain"
        )

        self.send_failure_notification_email = self.node.try_get_context(
            "send_failure_notification_email"
        )

        self.failure_notification_email = self.node.try_get_context(
            "failure_notification_email"
        )

        self.openscap_amazonlinux_image_version = self.node.try_get_context(
            "openscap_amazonlinux_image_version"
        )

        self.openscap_amazonlinux_image_version_hash = self.node.try_get_context(
            "openscap_amazonlinux_image_version_hash"
        )

        # Function calls to create resources
        self.__create_kms_key()
        self.__create_vpc_flow_log_group()
        self.__create_vpc()
        self.__create_vpc_endpoints()
        self.__create_s3_buckets()
        self.__create_lambda_security_group()
        self.__create_aws_sdk_for_pandas_layer()
        self.__create_sns_topic()
        self.__create_dead_letter_queue()
        self.__create_managed_policies()
        self.__create_1_config_rules_scrape_function()
        self.__create_2_parse_nist_controls_function()
        self.__create_3_create_summary_function()
        self.__create_4_package_artifacts_function()
        self.__create_5_create_ocsf_function()
        self.__create_6_create_oscal_function()
        #self.__create_7_openscap_scan_fargate()
        self.__create_step_function_log_group()
        self.__create_states_managed_policy()
        self.__create_state_machine()
        self.__create_cloudwatch_event_rule_for_state_machine()
        self.__cdk_output_variables()

    def __create_kms_key(self) -> kms.Key:
        self.kms_key = kms.Key(
            self,
            id=self.stack_env + "-kms-key",
            alias="alias/" + self.stack_env + "-kms-key",
            description=self.stack_env + "-KMS-Key",
            enable_key_rotation=True,
        )

        self.kms_key.grant_encrypt_decrypt(
            iam.ServicePrincipal("logs.amazonaws.com"),
        )

        self.kms_key.grant_encrypt_decrypt(
            iam.ServicePrincipal("s3.amazonaws.com"),
        )

    def __create_vpc_flow_log_group(self) -> None:
        self.vpc_flow_log_group = logs.LogGroup(
            self,
            self.stack_env + "-vpc-flow-log-group",
            retention=logs.RetentionDays.ONE_YEAR,
            log_group_name=self.stack_env + "-Vpc-Flow-Logs",
            removal_policy=RemovalPolicy.DESTROY,
            encryption_key=self.kms_key,
        )

    def __create_vpc(self) -> ec2.Vpc:
        self.vpc_flow_log_group_policy = iam.ManagedPolicy(
            self,
            self.stack_env + "-vpc-flow-log-group-policy",
            managed_policy_name=self.stack_env + "-Vpc-Flow-Log-Group-Policy",
            statements=[
                iam.PolicyStatement(
                    actions=[
                        "logs:CreateLogStream",
                        "logs:DescribeLogStreams",
                        "logs:PutLogEvents",
                    ],
                    resources=[self.vpc_flow_log_group.log_group_arn],
                    effect=iam.Effect.ALLOW,
                    sid="VpcFlowLogGroupPolicy",
                )
            ],
        )

        self.vpc_flow_log_group_role = iam.Role(
            self,
            self.stack_env + "-vpc-flow-log-group-role",
            role_name=self.stack_env + "-Vpc-Flow-Log-Group-Role",
            description="",
            assumed_by=iam.ServicePrincipal("vpc-flow-logs.amazonaws.com"),
            managed_policies=[
                iam.ManagedPolicy.from_managed_policy_arn(
                    self,
                    self.stack_env + "-vpc-flow-log-group-policy-arn",
                    managed_policy_arn=self.vpc_flow_log_group_policy.managed_policy_arn,
                ),
            ],
        ).without_policy_updates()

        self.vpc = ec2.Vpc(
            self,
            self.stack_env + "-vpc",
            max_azs=2,
            ip_addresses=ec2.IpAddresses.cidr(self.vpc_cidr),
            subnet_configuration=[
                ec2.SubnetConfiguration(
                    subnet_type=ec2.SubnetType.PRIVATE_ISOLATED,
                    name="Private Isolated",
                    cidr_mask=self.cidr_mask,
                ),
            ],
            flow_logs={
                "default": ec2.FlowLogOptions(
                    destination=ec2.FlowLogDestination.to_cloud_watch_logs(
                        log_group=self.vpc_flow_log_group,
                        iam_role=self.vpc_flow_log_group_role,
                    ),
                    traffic_type=ec2.FlowLogTrafficType.ALL,
                )
            },
            restrict_default_security_group=True,
        )

    def __create_vpc_endpoints(self) -> None:
        self.vpc_endpoint_security_group = ec2.SecurityGroup(
            self,
            self.stack_env + "-vpc-endpoint-security-group",
            vpc=self.vpc,
            description="Security Group for VPC Endpoint",
            allow_all_outbound=False,
        )

        self.vpc_endpoint_security_group.add_ingress_rule(
            peer=ec2.Peer.ipv4(self.vpc.vpc_cidr_block),
            connection=ec2.Port.tcp(443),
            description="Allow HTTPS from VPC CIDR Block",
        )

        self.vpc.add_gateway_endpoint(
            self.stack_env + "-S3GatewayEndpoint",
            service=ec2.GatewayVpcEndpointAwsService.S3,
        )

        if self.partition != "aws-iso-b":
            self.vpc.add_interface_endpoint(
                self.stack_env + "-SecurityHubEndpoint",
                service=ec2.InterfaceVpcEndpointAwsService.SECURITYHUB,
                private_dns_enabled=True,
                security_groups=[self.vpc_endpoint_security_group],
            )

    def __create_s3_buckets(self):
        self.s3_access_logs_bucket = s3.Bucket(
            self,
            self.stack_env + "-access-logs",
            bucket_name=self.stack_env + "-access-logs-" + self.account,
            encryption=s3.BucketEncryption.KMS,
            encryption_key=self.kms_key,
            bucket_key_enabled=True,
            block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
            removal_policy=RemovalPolicy.DESTROY,
            enforce_ssl=True,
            minimum_tls_version=1.2,
            versioned=True,
            # Commented out, as adding lifecycle rules directly to the bucket does not work as expected
            # lifecycle_rules=[
            #     dict(
            #         enabled=True,
            #         expiration=Duration.days(365),
            #         noncurrent_version_expiration=Duration.days(180),
            #     ),
            #     dict(
            #         enabled=True,
            #         expired_object_delete_marker=True,
            #     )
            # ]
        )

        self.s3_access_logs_bucket.add_lifecycle_rule(
            id="DeleteAfter365Days",
            enabled=True,
            expiration=Duration.days(365),
            noncurrent_version_expiration=Duration.days(180),
        )

        self.s3_access_logs_bucket.add_lifecycle_rule(
            id="ExpiredObjectDeleteMarkerLifecycleRule",
            enabled=True,
            expired_object_delete_marker=True,
        )

        cdknag.NagSuppressions.add_resource_suppressions(
            construct=self.s3_access_logs_bucket,
            suppressions=[
                {
                    "id": "NIST.800.53.R5-S3BucketLoggingEnabled",
                    "reason": "Access logs bucket itself should not have server access logging enabled.",
                },
                {
                    "id": "NIST.800.53.R5-S3BucketReplicationEnabled",
                    "reason": "Operationally not required.",
                },
            ],
        )

        self.s3_resource_bucket = s3.Bucket(
            self,
            self.stack_env + "-resources",
            bucket_name=self.stack_env + "-resources-" + self.account,
            encryption=s3.BucketEncryption.KMS,
            encryption_key=self.kms_key,
            bucket_key_enabled=True,
            block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
            removal_policy=RemovalPolicy.DESTROY,
            enforce_ssl=True,
            versioned=True,
            server_access_logs_bucket=self.s3_access_logs_bucket,
            auto_delete_objects=False,
        )

        self.s3_resource_bucket.add_lifecycle_rule(
            enabled=True,
            id="retain-artifact-replicas",
            noncurrent_version_expiration=Duration.days(self.artifact_replicas_to_retain * 7),  # Assuming weekly backups
        )


        cdknag.NagSuppressions.add_resource_suppressions(
            construct=self.s3_resource_bucket,
            suppressions=[
                {
                    "id": "NIST.800.53.R5-S3BucketReplicationEnabled",
                    "reason": "Operationally not required.",
                },
            ],
        )

    def __create_lambda_security_group(self) -> ec2.SecurityGroup:
        """Create a security group for Lambda functions"""
        self.lambda_security_group = ec2.SecurityGroup(
            self,
            self.stack_env + "-lambda-security-group",
            vpc=self.vpc,
            description=self.stack_env + "-Lambda-Security-Group",
            security_group_name=self.stack_env + "-Lambda-Security-Group",
            allow_all_outbound=False,
        )

        s3_prefix_list = ec2.PrefixList.from_lookup(
            self,
            self.stack_env + "-s3-prefix-list",
            prefix_list_name=f"com.amazonaws.{self.region}.s3"
        )

        self.lambda_security_group.add_egress_rule(
            peer=ec2.Peer.prefix_list(s3_prefix_list.prefix_list_id),
            connection=ec2.Port.tcp(443),
            description="Allow HTTPS to S3 prefix list",
        )

        # For VPC endpoints
        self.lambda_security_group.add_egress_rule(
            peer=ec2.Peer.ipv4(self.vpc.vpc_cidr_block),
            connection=ec2.Port.tcp(443),
            description="Allow HTTPS to VPC CIDR Block",
        )

    def __create_aws_sdk_for_pandas_layer(self) -> lambda_.LayerVersion:
        """Creates the AWS SDK for Pandas layer"""
        self.aws_sdk_for_pandas_layer = lambda_.LayerVersion(
            self,
            self.stack_env + "-aws-sdk-for-pandas-layer",
            code=lambda_.AssetCode(self.aws_wrangler_layer),
            compatible_runtimes=[lambda_.Runtime.PYTHON_3_11],
        )

    def __create_sns_topic(self) -> sns.Topic:
        """Creates SNS topic for failure notifications"""
        self.sns_topic = sns.Topic(
            self,
            self.stack_env + "-sns-topic",
            topic_name=self.stack_env + "-SNS-Topic",
            display_name=self.stack_env + " - StepFunction Failure Notification",
            master_key=self.kms_key,
        )

        if self.send_failure_notification_email:
            self.sns_topic.add_subscription(
                subscriptions.EmailSubscription(self.failure_notification_email)
            )

    def __create_dead_letter_queue(self) -> sqs.Queue:
        """Creates SQS dead letter queue"""
        self.dead_letter_queue = sqs.Queue(
            self,
            self.stack_env + "-dead-letter-queue",
            queue_name=self.stack_env + "-Dead-Letter-Queue",
            visibility_timeout=Duration.seconds(30),
            retention_period=Duration.days(7),
            encryption=sqs.QueueEncryption.KMS_MANAGED,
        )

    def __create_managed_policies(self) -> List[iam.ManagedPolicy]:
        """
        Creates IAM managed policies required by the application.

        This method defines several IAM managed policies for Lambda
        function execution roles, including policies for Security Hub, KMS,
        S3, SQS and SNS. The policies are returned as a list.
        """
        # Construct S3 bucket ARN
        s3_bucket_arn = self.s3_resource_bucket.bucket_arn

        # Account ID
        account_id = os.environ["CDK_DEFAULT_ACCOUNT"]

        # Determine the partition dynamically
        region = os.environ["CDK_DEFAULT_REGION"]
        if region.startswith("us-gov-"):
            partition = "aws-us-gov"
        elif region.startswith("cn-"):
            partition = "aws-cn"
        else:
            partition = "aws"

        self.security_hub_lambda_policy = iam.ManagedPolicy(
            self,
            self.stack_env + "-security-hub-lambda-policy",
            managed_policy_name=self.stack_env + "-Security-Hub-Lambda-Policy",
            statements=[
                iam.PolicyStatement(
                    actions=[
                        "securityhub:GetFindings",
                        "securityhub:BatchImportFindings",
                        "securityhub:GetEnabledStandards",
                        "securityhub:DescribeStandardsControls",
                    ],
                    resources=[
                        f"arn:{partition}:securityhub:{region}:{account_id}:hub/default",
                        f"arn:{partition}:securityhub:{region}:{account_id}:product/*",
                    ],
                    effect=iam.Effect.ALLOW,
                    sid="SecurityHubLambdaPolicy",
                ),
                iam.PolicyStatement(
                    actions=[
                        "s3:GetObject",
                        "s3:PutObject",
                        "s3:ListBucket",
                        "s3:DeleteObject",
                    ],
                    resources=[s3_bucket_arn, f"{s3_bucket_arn}/*"],
                    effect=iam.Effect.ALLOW,
                    sid="S3AccessPolicy",
                ),
            ],
        )

        self.kms_policy = iam.ManagedPolicy(
            self,
            self.stack_env + "-kms-policy",
            managed_policy_name=self.stack_env + "-KMS-Policy",
            statements=[
                iam.PolicyStatement(
                    actions=[
                        "kms:Decrypt",
                        "kms:GenerateDataKey",
                    ],
                    effect=iam.Effect.ALLOW,
                    resources=[self.kms_key.key_arn],
                    sid="KMSLambdaPolicy",
                )
            ],
        )

        self.s3_lambda_policy = iam.ManagedPolicy(
            self,
            self.stack_env + "-s3-lambda-policy",
            managed_policy_name=self.stack_env + "-S3-Lambda-Policy",
            statements=[
                iam.PolicyStatement(
                    actions=[
                        "s3:GetObject",
                        "s3:GetObjectVersion",
                        "s3:PutObject",
                        "s3:PutObjectAcl",
                        "s3:ListBucket",
                        "s3:ListBucketVersions",
                    ],
                    effect=iam.Effect.ALLOW,
                    resources=[self.s3_resource_bucket.bucket_arn + "/*"],
                    sid="S3LambdaPolicy",
                ),
                iam.PolicyStatement(
                    actions=[
                        "s3:ListBucket",
                    ],
                    effect=iam.Effect.ALLOW,
                    resources=[self.s3_resource_bucket.bucket_arn],
                    sid="BucketPolicy",
                ),
            ],
        )

        self.sqs_policy = iam.ManagedPolicy(
            self,
            self.stack_env + "-sqs-policy",
            managed_policy_name=self.stack_env + "-SQS-Policy",
            statements=[
                iam.PolicyStatement(
                    actions=[
                        "sqs:SendMessage",
                    ],
                    effect=iam.Effect.ALLOW,
                    resources=[self.dead_letter_queue.queue_arn],
                    sid="SQSPolicy",
                )
            ],
        )

        self.sns_policy = iam.ManagedPolicy(
            self,
            self.stack_env + "-sns-policy",
            managed_policy_name=self.stack_env + "-SNS-Policy",
            statements=[
                iam.PolicyStatement(
                    actions=[
                        "sns:Publish",
                    ],
                    effect=iam.Effect.ALLOW,
                    resources=[self.sns_topic.topic_arn],
                    sid="SNSPolicy",
                )
            ],
        )

        # self.step_function_policy = iam.ManagedPolicy(
        #     self,
        #     self.stack_env + "-step-function-policy",
        #     managed_policy_name=self.stack_env + "-Step-Function-Policy",
        #     statements=[
        #         iam.PolicyStatement(
        #             actions=[
        #                 "states:SendTaskSuccess",
        #             ],
        #             effect=iam.Effect.ALLOW,
        #             resources=["*"],
        #             sid="StepFunctionPolicy",
        #         )
        #     ],
        # )

    def __create_1_config_rules_scrape_function(self) -> lambda_.Function:
        """
        Creates a Lambda function responsible for making API calls to Security Hub
        to retrieve the latest active compliance findings and disabled rules.

        Additionally, communications between Lambda and Amazon S3 are encrypted in
        transit for enhanced security.
        """

        self.config_rules_scrape_function_role = iam.Role(
            self,
            self.stack_env + "-config-rules-scrape-function-role",
            role_name=self.stack_env + "-Config-Rules-Scrape-Function-Role",
            description="",
            assumed_by=iam.ServicePrincipal("lambda.amazonaws.com"),
            managed_policies=[
                iam.ManagedPolicy.from_aws_managed_policy_name(
                    "service-role/AWSLambdaBasicExecutionRole"
                ),
                iam.ManagedPolicy.from_aws_managed_policy_name(
                    "service-role/AWSLambdaVPCAccessExecutionRole"
                ),
                iam.ManagedPolicy.from_managed_policy_arn(
                    self,
                    self.stack_env + "-1-sqs-policy-arn",
                    managed_policy_arn=self.sqs_policy.managed_policy_arn,
                ),
                iam.ManagedPolicy.from_managed_policy_arn(
                    self,
                    self.stack_env + "-1-kms-policy-arn",
                    managed_policy_arn=self.kms_policy.managed_policy_arn,
                ),
                iam.ManagedPolicy.from_managed_policy_arn(
                    self,
                    self.stack_env + "-1-s3-policy-arn",
                    managed_policy_arn=self.s3_lambda_policy.managed_policy_arn,
                ),
                iam.ManagedPolicy.from_managed_policy_arn(
                    self,
                    self.stack_env + "-1-security-hub-policy-arn",
                    managed_policy_arn=self.security_hub_lambda_policy.managed_policy_arn,
                ),
            ],
        ).without_policy_updates()

        func_kwargs = dict(
            function_name=self.stack_env + "-Config-Rules-Scrape",
            description="1-Retrieve data from AWS Security Hub and export ASFF format.",
            runtime=lambda_.Runtime.PYTHON_3_11,
            code=lambda_.Code.from_asset("assets/lambda/code/1-config-rules-scrape"),
            handler="lambda_function.lambda_handler",
            timeout=Duration.minutes(10),
            memory_size=4096,
            ephemeral_storage_size=Size.mebibytes(4096),
            allow_public_subnet=False,
            retry_attempts=0,
            environment={"BUCKET_NAME": self.s3_resource_bucket.bucket_name},
            reserved_concurrent_executions=1,
            dead_letter_queue_enabled=True,
            dead_letter_queue=self.dead_letter_queue,
            role=self.config_rules_scrape_function_role,
            environment_encryption=self.kms_key,
        )

        if self.partition != "aws-iso-b":
            func_kwargs.update(
                vpc=self.vpc,
                vpc_subnets=ec2.SubnetSelection(subnet_type=ec2.SubnetType.PRIVATE_ISOLATED),
                security_groups=[self.lambda_security_group],
            )

        self.config_rules_scrape_function = lambda_.Function(
            self,
            self.stack_env + "-config-rules-scrape-function",
            **func_kwargs
        )

        if self.partition == "aws-iso-b":
            cdknag.NagSuppressions.add_resource_suppressions(
                construct=self.config_rules_scrape_function,
                suppressions=[
                    {
                        "id": "NIST.800.53.R5-LambdaInsideVPC",
                        "reason": "VPC Endpoint for Security Hub not available",
                    },
                ],
            )

    def __create_2_parse_nist_controls_function(self) -> lambda_.Function:
        """
        Creates the Lambda function that parses NIST controls.

        This method defines the IAM execution role and Lambda function
        that will parse findings scraped from AWS Security Hub and export them
        by resource ID and NIST control ID to CSV format.

        Additionally, communications between Lambda and Amazon S3 are encrypted in
        transit for enhanced security.
        """
        self.parse_nist_controls_function_role = iam.Role(
            self,
            self.stack_env + "-parse-nist-controls-function-role",
            role_name=self.stack_env + "-Parse-Nist-Controls-Function-Role",
            description="",
            assumed_by=iam.ServicePrincipal("lambda.amazonaws.com"),
            managed_policies=[
                iam.ManagedPolicy.from_aws_managed_policy_name(
                    "service-role/AWSLambdaBasicExecutionRole"
                ),
                iam.ManagedPolicy.from_aws_managed_policy_name(
                    "service-role/AWSLambdaVPCAccessExecutionRole"
                ),
                iam.ManagedPolicy.from_managed_policy_arn(
                    self,
                    self.stack_env + "-2-sqs-policy-arn",
                    managed_policy_arn=self.sqs_policy.managed_policy_arn,
                ),
                iam.ManagedPolicy.from_managed_policy_arn(
                    self,
                    self.stack_env + "-2-kms-policy-arn",
                    managed_policy_arn=self.kms_policy.managed_policy_arn,
                ),
                iam.ManagedPolicy.from_managed_policy_arn(
                    self,
                    self.stack_env + "-2-s3-policy-arn",
                    managed_policy_arn=self.s3_lambda_policy.managed_policy_arn,
                ),
            ],
        ).without_policy_updates()

        self.parse_nist_controls_function = lambda_.Function(
            self,
            self.stack_env + "-parse-nist-controls-function",
            function_name=self.stack_env + "-Parse-NIST-Controls",
            description="2-Extract findings by resource/security control id, save as CSV.",
            runtime=lambda_.Runtime.PYTHON_3_11,
            code=lambda_.Code.from_asset("assets/lambda/code/2-parse-nist-controls"),
            handler="lambda_function.lambda_handler",
            timeout=Duration.minutes(10),
            memory_size=4096,
            ephemeral_storage_size=Size.mebibytes(4096),
            vpc=self.vpc,
            vpc_subnets=ec2.SubnetSelection(
                subnet_type=ec2.SubnetType.PRIVATE_ISOLATED,
            ),
            security_groups=[self.lambda_security_group],
            allow_public_subnet=False,
            retry_attempts=0,
            environment={"BUCKET_NAME": self.s3_resource_bucket.bucket_name},
            layers=[self.aws_sdk_for_pandas_layer],
            reserved_concurrent_executions=1,
            dead_letter_queue_enabled=True,
            dead_letter_queue=self.dead_letter_queue,
            role=self.parse_nist_controls_function_role,
            environment_encryption=self.kms_key,
        )

    def __create_3_create_summary_function(self) -> lambda_.Function:
        """
        Creates the Lambda function that generates a summary.

        This method defines the IAM execution role and Lambda function
        that will aggregate findings parsed by the previous function
        and generate a summary report.

        Additionally, communications between Lambda and Amazon S3 are encrypted in
        transit for enhanced security.
        """
        self.create_summary_function_role = iam.Role(
            self,
            self.stack_env + "-create-summary-function-role",
            role_name=self.stack_env + "-Create-Summary-Function-Role",
            description="",
            assumed_by=iam.ServicePrincipal("lambda.amazonaws.com"),
            managed_policies=[
                iam.ManagedPolicy.from_aws_managed_policy_name(
                    "service-role/AWSLambdaBasicExecutionRole"
                ),
                iam.ManagedPolicy.from_aws_managed_policy_name(
                    "service-role/AWSLambdaVPCAccessExecutionRole"
                ),
                iam.ManagedPolicy.from_managed_policy_arn(
                    self,
                    self.stack_env + "-3-sqs-policy-arn",
                    managed_policy_arn=self.sqs_policy.managed_policy_arn,
                ),
                iam.ManagedPolicy.from_managed_policy_arn(
                    self,
                    self.stack_env + "-3-kms-policy-arn",
                    managed_policy_arn=self.kms_policy.managed_policy_arn,
                ),
                iam.ManagedPolicy.from_managed_policy_arn(
                    self,
                    self.stack_env + "-3-s3-policy-arn",
                    managed_policy_arn=self.s3_lambda_policy.managed_policy_arn,
                ),
            ],
        ).without_policy_updates()

        self.create_summary_function = lambda_.Function(
            self,
            self.stack_env + "-create-summary-function",
            function_name=self.stack_env + "-Create-Summary",
            description="3-Analyze prior results and create a summary CSV.",
            runtime=lambda_.Runtime.PYTHON_3_11,
            code=lambda_.Code.from_asset("assets/lambda/code/3-create-summary"),
            handler="lambda_function.lambda_handler",
            timeout=Duration.minutes(10),
            memory_size=4096,
            ephemeral_storage_size=Size.mebibytes(4096),
            vpc=self.vpc,
            vpc_subnets=ec2.SubnetSelection(
                subnet_type=ec2.SubnetType.PRIVATE_ISOLATED,
            ),
            security_groups=[self.lambda_security_group],
            allow_public_subnet=False,
            retry_attempts=0,
            environment={"BUCKET_NAME": self.s3_resource_bucket.bucket_name},
            layers=[self.aws_sdk_for_pandas_layer],
            reserved_concurrent_executions=1,
            dead_letter_queue_enabled=True,
            dead_letter_queue=self.dead_letter_queue,
            role=self.create_summary_function_role,
            environment_encryption=self.kms_key,
        )

    def __create_4_package_artifacts_function(self) -> lambda_.Function:
        """
        Creates the Lambda function that packages artifacts.

        This method defines the IAM execution role and Lambda function
        that will package the outputs from the previous functions into a
        single zip file.

        Additionally, communications between Lambda and Amazon S3 are encrypted in
        transit for enhanced security.
        """

        self.create_package_artifacts_function_role = iam.Role(
            self,
            self.stack_env + "-create-package-artifacts-function-role",
            role_name=self.stack_env + "-Package-Artifacts-Function-Role",
            assumed_by=iam.ServicePrincipal("lambda.amazonaws.com"),
            managed_policies=[
                iam.ManagedPolicy.from_aws_managed_policy_name(
                    "service-role/AWSLambdaBasicExecutionRole"
                ),
                iam.ManagedPolicy.from_aws_managed_policy_name(
                    "service-role/AWSLambdaVPCAccessExecutionRole"
                ),
                iam.ManagedPolicy.from_managed_policy_arn(
                    self,
                    self.stack_env + "-4-sqs-policy-arn",
                    managed_policy_arn=self.sqs_policy.managed_policy_arn,
                ),
                iam.ManagedPolicy.from_managed_policy_arn(
                    self,
                    self.stack_env + "-4-kms-policy-arn",
                    managed_policy_arn=self.kms_policy.managed_policy_arn,
                ),
                iam.ManagedPolicy.from_managed_policy_arn(
                    self,
                    self.stack_env + "-4-s3-policy-arn",
                    managed_policy_arn=self.s3_lambda_policy.managed_policy_arn,
                ),
            ],
        ).without_policy_updates()

        self.create_package_artifacts_function = lambda_.Function(
            self,
            self.stack_env + "-package-artifacts-function",
            function_name=self.stack_env + "-Package-Artifacts",
            description="4-Package artifacts into .zip file.",
            runtime=lambda_.Runtime.PYTHON_3_11,
            code=lambda_.Code.from_asset("assets/lambda/code/4-package-artifacts"),
            handler="lambda_function.lambda_handler",
            timeout=Duration.minutes(10),
            memory_size=4096,
            ephemeral_storage_size=Size.mebibytes(4096),
            vpc=self.vpc,
            vpc_subnets=ec2.SubnetSelection(
                subnet_type=ec2.SubnetType.PRIVATE_ISOLATED,
            ),
            security_groups=[self.lambda_security_group],
            allow_public_subnet=False,
            retry_attempts=0,
            environment={"BUCKET_NAME": self.s3_resource_bucket.bucket_name},
            layers=[self.aws_sdk_for_pandas_layer],
            reserved_concurrent_executions=1,
            dead_letter_queue_enabled=True,
            dead_letter_queue=self.dead_letter_queue,
            role=self.create_package_artifacts_function_role,
            environment_encryption=self.kms_key,
        )

    def __create_5_create_ocsf_function(self):
        """
        Creates an AWS Lambda function to generate an OCSF version of the results.

        The Lambda function is configured with the necessary permissions, VPC settings,
        and other parameters to securely process the data and store the results.

        Note: 
        AWS Lambda encrypts all environment variables at rest using a service-managed key.
        Additionally, communications between Lambda and Amazon S3 are 
        encrypted in transit for enhanced security.
        """

        self.create_ocsf_function_role = iam.Role(
            self,
            self.stack_env + "-create-ocsf-function-function-role",
            role_name=self.stack_env + "-Create-OCSF-Function-Role",
            assumed_by=iam.ServicePrincipal("lambda.amazonaws.com"),
            managed_policies=[
                iam.ManagedPolicy.from_aws_managed_policy_name(
                    "service-role/AWSLambdaBasicExecutionRole"
                ),
                iam.ManagedPolicy.from_aws_managed_policy_name(
                    "service-role/AWSLambdaVPCAccessExecutionRole"
                ),
                iam.ManagedPolicy.from_managed_policy_arn(
                    self,
                    self.stack_env + "-5-sqs-policy-arn",
                    managed_policy_arn=self.sqs_policy.managed_policy_arn,
                ),
                iam.ManagedPolicy.from_managed_policy_arn(
                    self,
                    self.stack_env + "-5-kms-policy-arn",
                    managed_policy_arn=self.kms_policy.managed_policy_arn,
                ),
                iam.ManagedPolicy.from_managed_policy_arn(
                    self,
                    self.stack_env + "-5-s3-policy-arn",
                    managed_policy_arn=self.s3_lambda_policy.managed_policy_arn,
                ),
            ],
        ).without_policy_updates()

        self.create_ocsf_function = lambda_.Function(
            self,
            self.stack_env + "-create-ocsf-function",
            function_name=self.stack_env + "-Create-OCSF",
            description="5-Create ocsf version of results.",
            runtime=lambda_.Runtime.PYTHON_3_11,
            code=lambda_.Code.from_asset("assets/lambda/code/5-create-ocsf"),
            handler="lambda_function.lambda_handler",
            timeout=Duration.minutes(10),
            memory_size=4096,
            ephemeral_storage_size=Size.mebibytes(4096),
            vpc=self.vpc,
            vpc_subnets=ec2.SubnetSelection(
                subnet_type=ec2.SubnetType.PRIVATE_ISOLATED,
            ),
            security_groups=[self.lambda_security_group],
            allow_public_subnet=False,
            retry_attempts=0,
            environment={"BUCKET_NAME": self.s3_resource_bucket.bucket_name},
            layers=[self.aws_sdk_for_pandas_layer],
            reserved_concurrent_executions=1,
            dead_letter_queue_enabled=True,
            dead_letter_queue=self.dead_letter_queue,
            role=self.create_ocsf_function_role,
            environment_encryption=self.kms_key,
        )

    def __create_6_create_oscal_function(self):
        """
        Creates an AWS Lambda function to generate an OCSF (Open Cybersecurity Schema
        Framework) version of the results. Note: By default, AWS Lambda encrypts all
        environment variables at rest using a service-managed key.
        Additionally, communications between Lambda and Amazon S3 are encrypted in
        transit for enhanced security.
        """
        self.create_oscal_function_role = iam.Role(
            self,
            self.stack_env + "-create-oscal-function-function-role",
            role_name=self.stack_env + "-Create-OSCAL-Function-Role",
            assumed_by=iam.ServicePrincipal("lambda.amazonaws.com"),
            managed_policies=[
                iam.ManagedPolicy.from_aws_managed_policy_name(
                    "service-role/AWSLambdaBasicExecutionRole"
                ),
                iam.ManagedPolicy.from_aws_managed_policy_name(
                    "service-role/AWSLambdaVPCAccessExecutionRole"
                ),
                iam.ManagedPolicy.from_managed_policy_arn(
                    self,
                    self.stack_env + "-6-sqs-policy-arn",
                    managed_policy_arn=self.sqs_policy.managed_policy_arn,
                ),
                iam.ManagedPolicy.from_managed_policy_arn(
                    self,
                    self.stack_env + "-6-kms-policy-arn",
                    managed_policy_arn=self.kms_policy.managed_policy_arn,
                ),
                iam.ManagedPolicy.from_managed_policy_arn(
                    self,
                    self.stack_env + "-6-s3-policy-arn",
                    managed_policy_arn=self.s3_lambda_policy.managed_policy_arn,
                ),
            ],
        ).without_policy_updates()

        self.create_oscal_function = lambda_.Function(
            self,
            self.stack_env + "-create-oscal-function",
            function_name=self.stack_env + "-Create-OSCAL",
            description="6-Create oscal version of results.",
            runtime=lambda_.Runtime.PYTHON_3_11,
            code=lambda_.Code.from_asset("assets/lambda/code/6-create-oscal"),
            handler="lambda_function.lambda_handler",
            timeout=Duration.minutes(10),
            memory_size=4096,
            ephemeral_storage_size=Size.mebibytes(4096),
            vpc=self.vpc,
            vpc_subnets=ec2.SubnetSelection(
                subnet_type=ec2.SubnetType.PRIVATE_ISOLATED,
            ),
            security_groups=[self.lambda_security_group],
            allow_public_subnet=False,
            retry_attempts=0,
            environment={"BUCKET_NAME": self.s3_resource_bucket.bucket_name},
            layers=[self.aws_sdk_for_pandas_layer],
            reserved_concurrent_executions=1,
            dead_letter_queue_enabled=True,
            dead_letter_queue=self.dead_letter_queue,
            role=self.create_oscal_function_role,
            environment_encryption=self.kms_key,
        )

    def __create_step_function_log_group(self):
        """Creates the log group for Step Functions execution history."""
        self.step_function_log_group = logs.LogGroup(
            self,
            self.stack_env + "-step-function-log-group",
            retention=logs.RetentionDays.ONE_YEAR,
            log_group_name=self.stack_env + "-Step-Function-Logs",
            removal_policy=RemovalPolicy.DESTROY,
            encryption_key=self.kms_key,
        )

    def __create_states_managed_policy(self):
        """Creates a managed policy for Step Functions IAM role."""
        self.states_policy = iam.ManagedPolicy(
            self,
            self.stack_env + "-states-policy",
            managed_policy_name=self.stack_env + "-States-Policy",
            statements=[
                iam.PolicyStatement(
                    actions=[
                        "logs:CreateLogDelivery",
                        "logs:DeleteLogDelivery",
                        "logs:DescribeLogGroups",
                        "logs:DescribeResourcePolicies",
                        "logs:GetLogDelivery",
                        "logs:ListLogDeliveries",
                        "logs:PutResourcePolicy",
                        "logs:UpdateLogDelivery",
                        "logs:PutLogEvents",
                    ],
                    effect=iam.Effect.ALLOW,
                    resources=[self.step_function_log_group.log_group_arn],
                    sid="LogsPolicy",
                ),
                iam.PolicyStatement(
                    actions=[
                        "lambda:InvokeFunction",
                    ],
                    effect=iam.Effect.ALLOW,
                    resources=[
                        self.config_rules_scrape_function.function_arn,
                        self.parse_nist_controls_function.function_arn,
                        self.create_summary_function.function_arn,
                        self.create_package_artifacts_function.function_arn,
                        self.create_ocsf_function.function_arn,
                        self.create_oscal_function.function_arn,
                    ],
                    sid="LambdaInvokePolicy",
                ),
            ],
        )

    def __create_state_machine(self):
        """Creates the Step Functions state machine."""
        self.state_machine_role = iam.Role(
            self,
            self.stack_env + "-state-machine-role",
            role_name=self.stack_env + "-State-Machine-Role",
            description="",
            assumed_by=iam.ServicePrincipal("states.amazonaws.com"),
            managed_policies=[
                iam.ManagedPolicy.from_managed_policy_arn(
                    self,
                    self.stack_env + "-states-policy-arn",
                    managed_policy_arn=self.states_policy.managed_policy_arn,
                ),
                iam.ManagedPolicy.from_managed_policy_arn(
                    self,
                    self.stack_env + "-states-kms-policy-arn",
                    managed_policy_arn=self.kms_policy.managed_policy_arn,
                ),
                iam.ManagedPolicy.from_managed_policy_arn(
                    self,
                    self.stack_env + "-states-sns-policy-arn",
                    managed_policy_arn=self.sns_policy.managed_policy_arn,
                ),
            ],
        )

        # Step functions Definition
        step_1_job = stepfunctions_tasks.LambdaInvoke(
            self,
            self.stack_env + "-1-config-rules-scrape",
            lambda_function=self.config_rules_scrape_function,
        )

        step_2_job = stepfunctions_tasks.LambdaInvoke(
            self,
            self.stack_env + "-2-parse-nist-controls",
            lambda_function=self.parse_nist_controls_function,
        )

        step_3_job = stepfunctions_tasks.LambdaInvoke(
            self,
            self.stack_env + "-3-create-summary",
            lambda_function=self.create_summary_function,
        )

        step_4_job = stepfunctions_tasks.LambdaInvoke(
            self,
            self.stack_env + "-4-package-artifacts",
            lambda_function=self.create_package_artifacts_function,
        )
        step_5_job = stepfunctions_tasks.LambdaInvoke(
            self,
            self.stack_env + "-5-create-ocsf",
            lambda_function=self.create_ocsf_function,
        )
        step_6_job = stepfunctions_tasks.LambdaInvoke(
            self,
            self.stack_env + "-6-create-oscal",
            lambda_function=self.create_oscal_function,
        )

        # Add a Fail state
        fail_state = stepfunctions.Fail(
            self,
            self.stack_env + "-failure-state",
            cause="Task Failed",
            error="TaskFailed"
        )

        # Modify the fail task to chain to the Fail state
        fail_task = stepfunctions_tasks.SnsPublish(
            self,
            self.stack_env + "-fail-task",
            topic=self.sns_topic,
            subject="Job Failed",
            message=stepfunctions.TaskInput.from_json_path_at("$.taskresult"),
        ).next(fail_state)  # Chain the Fail state after SNS notification

        step_1_job.add_catch(fail_task, result_path="$.taskresult")
        step_2_job.add_catch(
            fail_task,
            result_path="$.taskresult",
        )
        step_3_job.add_catch(
            fail_task,
            result_path="$.taskresult",
        )
        step_4_job.add_catch(
            fail_task,
            result_path="$.taskresult",
        )
        step_5_job.add_catch(
            fail_task,
            result_path="$.taskresult",
        )
        step_6_job.add_catch(
            fail_task,
            result_path="$.taskresult",
        )

        # Create Step Functions Chain
        chain = (
            stepfunctions.Chain.start(step_1_job)
            .next(step_2_job)
            .next(step_3_job)
            .next(step_4_job)
            .next(step_5_job)
            .next(step_6_job)
            # .next(step_7_job)
        )

        # Create state machine
        self.shca_state_machine = stepfunctions.StateMachine(
            self,
            self.stack_env + "-state-machine",
            state_machine_name=self.stack_env + "-State-Machine",
            definition_body=stepfunctions.DefinitionBody.from_chainable(chain),
            timeout=Duration.minutes(15),
            logs=stepfunctions.LogOptions(
                destination=self.step_function_log_group,
                include_execution_data=True,
                level=stepfunctions.LogLevel.ALL,
            ),
            role=self.state_machine_role,
        )

    def __create_cloudwatch_event_rule_for_state_machine(self):
        """
        Creates a CloudWatch Events rule for the state machine.

        This method defines a rule in CloudWatch Events that will trigger
        the state machine execution whenever a relevant event occurs, such
        as a Lambda function invocation.
        """
        self.events_policy = iam.ManagedPolicy(
            self,
            self.stack_env + "-events-policy",
            managed_policy_name=self.stack_env + "-Events-Policy",
            statements=[
                iam.PolicyStatement(
                    actions=[
                        "states:StartExecution",
                    ],
                    effect=iam.Effect.ALLOW,
                    resources=[self.shca_state_machine.state_machine_arn],
                    sid="EventsPolicy",
                ),
            ],
        )
        self.event_role = iam.Role(
            self,
            self.stack_env + "-event-role",
            role_name=self.stack_env + "-Event-Role",
            description="",
            assumed_by=iam.ServicePrincipal("events.amazonaws.com"),
            managed_policies=[
                iam.ManagedPolicy.from_managed_policy_arn(
                    self,
                    self.stack_env + "-events-policy-arn",
                    managed_policy_arn=self.events_policy.managed_policy_arn,
                ),
            ],
        ).without_policy_updates()

        self.shca_event_rule = events.Rule(
            self,
            self.stack_env + "-event-rule",
            rule_name=self.stack_env + "-event-rule",
            schedule=events.Schedule.rate(Duration.days(self.schedule_frequency_days)),
        )

        self.shca_event_rule.add_target(
            targets.SfnStateMachine(
                machine=self.shca_state_machine, role=self.event_role
            ),
        )

        if self.partition == "aws-us-gov":
            Tags.of(self.shca_event_rule).remove("Application")

    # ------------------------------------------------------------------------------------
    def __cdk_output_variables(self):
        """Defines CDK output variables for stack resources."""
        CfnOutput(
            self,
            "bucket-name",
            description=self.stack_env + " S3 Bucket Name",
            value=self.s3_resource_bucket.bucket_name,
        )

        cdknag.NagSuppressions.add_resource_suppressions(
            construct=self.state_machine_role,
            apply_to_children=True,
            suppressions=[
                {
                    "id": "NIST.800.53.R5-IAMNoInlinePolicy",
                    "reason": "Temporarily required because of CDK Deploy Order of Operations.",
                },
            ],
        )
