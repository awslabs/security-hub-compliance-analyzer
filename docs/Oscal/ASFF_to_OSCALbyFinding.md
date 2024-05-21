# Purpose
The purpose of this mapping is to assist customers in transforming Security Hub compliance findings in ASFF format (securityhub_findings_json_key) into OSCAL.


## ASFF to OSCAL Mapping Reference

| ASFF                  | OSCAL Field                     | Description                              | Sample Data                                                                                                    |
|-----------------------|---------------------------------|------------------------------------------|----------------------------------------------------------------------------------------------------------------|
| Id                    | component.uuid                  | Unique identifier for the component      | arn:aws:securityhub:us-east-1:623902929189:security-control/ECR.1/finding/053b9697-a831-4172-9c87-00c87813de97  |
| GeneratorId           | rule.id                         | Identifier for the rule                  | ECR.1                                                                                                          |
| AwsAccountId          | component.props.aws_account_id  | AWS account ID                           | 623902929189                                                                                                   |
| ProductName           | component.type                  | Type of AWS service                      | Security Hub                                                                                                   |
| Compliance.Status     | result.status                   | Compliance status                        | PASSED                                                                                                         |
| LastObservedAt        | result.observation_timestamp    | Timestamp of the last observation        | 2024-02-14T19:52:38.670Z                                                                                        |
| Severity.Label        | result.severity                 | Severity of the finding                  | INFORMATIONAL                                                                                                  |
| Description           | control.description             | Description of the control               | This control checks whether a private ECR repository has image scanning configured. This control fails if a private ECR repository doesn’t have image scanning configured. |
| Remediation.Text      | result.remediation              | Suggested remediation steps              | For information on how to correct this issue, consult the AWS Security Hub controls documentation.             |
| Remediation.Url       | result.remediation_reference    | Reference for the remediation steps      | https://docs.aws.amazon.com/console/securityhub/ECR.1/remediation                                               |
| Compliance.RelatedRequirements[0] | control.compliance_standard_id | Identifier for the compliance standard   | NIST.800-53.r5                                                                                                 |
| Compliance.RelatedRequirements[1] | control.id                      | Identifier for the compliance control    | RA-5                                                                                                           |
| WorkflowState         | result.workflow_state           | State of the workflow                    | NEW                                                                                                            |
| Workflow.Status       | result.status                   | Status of the result                     | RESOLVED                                                                                                       |
| RecordState           | result.record_state             | State of the record                      | ACTIVE                                                                                                         |
| ProductName           | component.title                 | Name of the product                      | Security Hub                                                                                                   |
| CompanyName           | component.vendor                | Name of the product vendor               | AWS                                                                                                            |
| Resources[0].Type     | component.layer                 | Layer of compliance                      | AwsEcrRepository                                                                                               |
|-----------------------|---------------------------------|------------------------------------------|----------------------------------------------------------------------------------------------------------------|


## Sample Mapping
```python
mapping = {
    'Id': 'component.uuid',
    'GeneratorId': 'rule.id',
    'AwsAccountId': 'component.props.aws_account_id',
    'ProductName': 'component.type',
    'Compliance.Status': 'result.status',
    'LastObservedAt': 'result.observation_timestamp',
    'Severity.Label': 'result.severity',
    'Description': 'control.description',
    'Remediation.Text': 'result.remediation',
    'Remediation.Url': 'result.remediation_reference',
    'Compliance.RelatedRequirements[0]': 'control.compliance_standard_id',
    'Compliance.RelatedRequirements[1]': 'control.id',
    'WorkflowState': 'result.workflow_state',
    'Workflow.Status': 'result.status',
    'RecordState': 'result.record_state',
    'ProductName': 'component.title',
    'CompanyName': 'component.vendor',
    'Resources[0].Type': 'component.layer'
}
```
## Sample Transformed Data
```bash
{
    "component.uuid": "arn:aws:securityhub:us-east-1:623902929189:security-control/ECR.1/finding/053b9697-a831-4172-9c87-00c87813de97",
    "rule.id": "ECR.1",
    "component.props.aws_account_id": "623902929189",
    "component.type": "Security Hub",
    "result.status": "ACTIVE",
    "result.observation_timestamp": "2024-02-14T19:52:38.670Z",
    "result.severity": "INFORMATIONAL",
    "control.description": "This control checks whether a private ECR repository has image scanning configured. This control fails if a private ECR repository doesn’t have image scanning configured.",
    "result.remediation": "For information on how to correct this issue, consult the AWS Security Hub controls documentation.",
    "result.remediation_reference": "https://docs.aws.amazon.com/console/securityhub/ECR.1/remediation",
    "control.compliance_standard_id": "NIST.800-53.r5",
    "control.id": "RA-5",
    "result.workflow_state": "NEW",
    "component.title": "Security Hub",
    "component.vendor": "AWS",
    "component.layer": "AwsEcrRepository"
}
```


