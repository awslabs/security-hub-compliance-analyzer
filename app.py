"""Security Hub Compliance Analyzer (SHCA)"""
import os
import cdk_nag as cdknag
import aws_cdk as cdk
from stack.shca_stack import ShcaStack

app = cdk.App()
stack_env = app.node.try_get_context("environment")

shca_stack = ShcaStack(
    app,
    stack_env + "-app-stack",
    description="Security Hub Compliance Analyzer Application Stack (uksb-mq8bedrw3a)",
    env=cdk.Environment(
        region=os.environ["CDK_DEFAULT_REGION"],
        account=os.environ["CDK_DEFAULT_ACCOUNT"],
    ),
)

cdk.Tags.of(shca_stack).add(
    key="Application",
    value="SHCA",
)

# Use NIST80053R5Checks instead of AwsSolutionsChecks
cdk.Aspects.of(app).add(cdknag.NIST80053R5Checks(verbose=True)) # AwsSolutionsChecks

app.synth()
