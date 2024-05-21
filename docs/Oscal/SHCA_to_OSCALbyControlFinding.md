# Purpose
The purpose of this mapping is to assist customers in transforming Security Hub compliance findings from SHCA format (securityhub_findings_csv_key) into OSCAL.

## SHCA to OSCAL Mapping Reference
|-----------------------|---------------------------------|------------------------------------------|----------------------------------------------------------------------------------------------------------------|
| SHCA                  | OSCAL Field                     | Description                              | Sample Data                                                                                                    |
|-----------------------|---------------------------------|------------------------------------------|----------------------------------------------------------------------------------------------------------------|
| resource_id           | component.uuid                  | Unique identifier for the component      | arn:aws:lambda:us-east-1:623902929189:function:lambda_report                                                   |
| rule_id               | rule.id                         | Identifier for the rule                  | Lambda.1                                                                                                       |
| aws_account_id        | component.props.aws_account_id  | AWS account ID                           | 623902929189                                                                                                   |
| aws_service           | component.type                  | Type of AWS service                      | lambda                                                                                                         |
| compliance_status     | result.status                   | Compliance status                        | PASSED                                                                                                         |
| lastobservedat        | result.observation_timestamp    | Timestamp of the last observation        | 2024-02-14 19:38:30.389000+00:00                                                                               |
| severity              | result.severity                 | Severity of the finding                  | INFORMATIONAL                                                                                                  |
| description           | control.description             | Description of the control               | This control checks whether the AWS Lambda function policy attached to the Lambda resource prohibits public access. If the Lambda function policy allows public access, the control fails. |
| remediation           | result.remediation              | Suggested remediation steps              | For information on how to correct this issue, consult the AWS Security Hub controls documentation.             |
| remediationreference  | result.remediation_reference    | Reference for the remediation steps      | [AWS Security Hub Documentation](https://docs.aws.amazon.com/console/securityhub/Lambda.1/remediation)         |
| related_requirements  | control.related_requirements    | Related requirements or standards        | PCI DSS v3.2.1/1.2.1                                                                                           |
| finding_id            | result.finding_id               | Unique identifier for the finding        | 00455b21-6a03-4838-a4f3-b1f8c6df1c08                                                                           |
| url                   | result.url                      | URL for more information                 | [AWS Security Hub Finding URL](https://us-east-1.console.aws.amazon.com/securityhub/home?region=us-east-1#/findings?search=Title%3D%255Coperator%255C%253AEQUALS%255C%253ALambda%2520function%2520policies%2520should%2520prohibit%2520public%2520access%26ResourceId%3D%255Coperator%255C%253AEQUALS%255C%253Aarn%3Aaws%3Alambda%3Aus-east-1%3A623902929189%3Afunction%3Alambda_report%26ComplianceSecurityControlId%3D%255Coperator%255C%253AEQUALS%255C%253ALambda.1) |
| workflow_state        | result.workflow_state           | State of the workflow                    | NEW                                                                                                            |
| status                | result.status                   | Status of the result                     | RESOLVED                                                                                                       |
| record_state          | result.record_state             | State of the record                      | ACTIVE                                                                                                         |
| product_name          | component.title                 | Name of the product                      | Security Hub                                                                                                   |
| product_vendor_name   | component.vendor                | Name of the product vendor               | AWS                                                                                                            |
| compliance_standard_id| control.compliance_standard_id  | Identifier for the compliance standard   | PCI DSS v3.2.1                                                                                                 |
| compliance_control_id | control.id                      | Identifier for the compliance control    | 1.2.1                                                                                                          |
| compliance_layer      | component.layer                 | Layer of compliance                      | cloud_resource                                                                                                 |
|-----------------------|---------------------------------|------------------------------------------|----------------------------------------------------------------------------------------------------------------|

## Sample Mapping
```bash
mapping = {
    'resource_id': 'component.uuid',
    'rule_id': 'rule_id',
    'aws_account_id': 'component.props.aws_account_id',
    'aws_service': 'component.type',
    'compliance_status': 'result.status',
    'lastobservedat': 'result.observation_timestamp',
    'severity': 'result.severity',
    'description': 'control.description',
    'remediation': 'result.remediation',
    'remediationreference': 'result.remediation_reference',
    'related_requirements': 'control.related_requirements',
    'finding_id': 'result.finding_id',
    'url': 'result.url',
    'workflow_state': 'result.workflow_state',
    'status': 'result.status',
    'record_state': 'result.record_state',
    'product_name': 'component.title',
    'product_vendor_name': 'component.vendor',
    'compliance_standard_id': 'control.compliance_standard_id',
    'compliance_control_id': 'control.id',
    'compliance_layer': 'component.layer'
}
```
## Sample Transormed Data
```bash
{
    "component.uuid": "arn:aws:lambda:us-east-1:623902929189:function:lambda_report",
    "rule.id": "Lambda.1",
    "component.props.aws_account_id": "623902929189",
    "component.type": "lambda",
    "result.status": "ACTIVE",
    "result.observation_timestamp": "2024-02-14 19:38:30.389000+00:00",
    "result.severity": "INFORMATIONAL",
    "control.description": "This control checks whether the AWS Lambda function policy attached to the Lambda resource prohibits public access. If the Lambda function policy allows public access, the control fails.",
    "result.remediation": "For information on how to correct this issue, consult the AWS Security Hub controls documentation.",
    "result.remediation_reference": "https://docs.aws.amazon.com/console/securityhub/Lambda.1/remediation",
    "control.related_requirements": "PCI DSS v3.2.1/1.2.1",
    "result.finding_id": "00455b21-6a03-4838-a4f3-b1f8c6df1c08",
    "result.url": "https://us-east-1.console.aws.amazon.com/securityhub/home?region=us-east-1#/findings?search=Title%3D%255Coperator%255C%253AEQUALS%255C%253ALambda%2520function%2520policies%2520should%2520prohibit%2520public%2520access%26ResourceId%3D%255Coperator%255C%253AEQUALS%255C%253Aarn%3Aaws%3Alambda%3Aus-east-1%3A623902929189%3Afunction%3Alambda_report%26ComplianceSecurityControlId%3D%255Coperator%255C%253AEQUALS%255C%253ALambda.1",
    "result.workflow_state": "NEW",
    "component.title": "Security Hub",
    "component.vendor": "AWS",
    "control.compliance_standard_id": "PCI DSS v3.2.1",
    "control_id": "1.2.1",
    "component.layer": "cloud_resource"
}
```

## Sample Function
```python
def convert_to_oscal(finding):
    """
    Convert an AWS Security Hub finding to the OSCAL format.

    This function extracts the relevant fields from an AWS Security Hub finding and maps
    them to the OSCAL format, based on a predefined mapping.

    Parameters:
        finding (dict): A transformed AWS Security Hub finding dictionary

    Returns:
        oscal_finding (dict): The finding converted to the OSCAL format
    """
    # Initialize the OSCAL finding with basic structure
    oscal_finding = {
        "uuid": finding.get("component.uuid"),
        "title": finding.get("component.title"),
        "description": finding.get("control.description"),
        "published": finding.get("result.observation_timestamp"),
        "last-modified": finding.get("result.observation_timestamp"),  
        "assessment-plan-uuid": finding.get("rule_id"),  
        "subjects": [{
            "subject-uuid": finding.get("component.props.aws_account_id"),
            "subject-type": "aws_service",
            "description": finding.get("component.type"),
        }],
        "results": [{
            "uuid": finding.get("result.finding_id"),
            "title": "Assessment Result",
            "description": finding.get("control.description"),
            "status": finding.get("result.status"),
            "observation-type": finding.get("aws_service"),  
            "observations": [{
                "observation-uuid": finding.get("result.finding_id"),
                "methods": ["Automated Analysis"],
                "collected": finding.get("result.observation_timestamp"),
                "observation-type": finding.get("aws_service"),  
                "related-requirements": finding.get("control.related_requirements"),
                "service-name": finding.get("component.title"),
                "severity": finding.get("result.severity"),
                "remediation": finding.get("result.remediation"),
                "remediation-url": finding.get("result.remediation_reference"),
                "product-fields": {  # Assuming custom structure
                    "product_name": finding.get("component.title"),
                    "product_vendor_name": finding.get("component.vendor"),
                },
                "resources": [],  
            }],
        }],
    }
    return oscal_finding

```