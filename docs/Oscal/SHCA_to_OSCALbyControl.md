# Purpose
The purpose of this mapping is to assist customers in transforming Security Hub compliance controls from SHCA format (securityhub_summary_csv_key) into OSCAL.


# SHCA to OSCAL Mapping Reference

The purpose of this mapping is to assist customers in transforming Security Hub compliance controls from SHCA format (securityhub_summary_csv_key) into OSCAL.

## Mapping Reference

| SHCA Control Summary   | OSCAL Field                     | Description                                               | Sample Data                                   |
|------------------------|---------------------------------|-----------------------------------------------------------|-----------------------------------------------|
| Compliance Control ID  | `control.id`                    | Identifier for the compliance control                     | `AC-17(2)`                                    |
| Compliance Status      | `result.status`                 | Compliance status                                         | `Partially Compliant`                         |
| Percentage             | `result.percentage`             | Compliance percentage                                     | `63.89%`                                      |
| Rule ID                | `rule.id`                       | Identifiers for the rules                                 | `ELB.1, ElastiCache.5, ES.8, CloudFront.7, ...`|
| Last Observed At       | `result.observation_timestamp`  | Timestamp of the last observation                         | `2024-02-14 13:38:35`                         |
| Narrative              | `implementation statement`      | Description of the controls implementation status         | As of the most recent evaluation on 2024-02...|

## Sample Mapping

```python
mapping = {
    'compliance_control_id': 'control.id',
    'compliance_status': 'result.status',
    'percentage': 'result.percentage',
    'rule_id': 'rule.id',
    'lastobservedat': 'result.observation_timestamp',
    'narrative': 'implementation statement'
}

## Sample Mapping
```python
mapping = {
    'compliance_control_id': 'control.id',
    'compliance_status': 'result.status',
    'percentage': 'result.percentage',
    'rule_id': 'rule.id',
    'lastobservedat': 'result.observation_timestamp',
    'narrative': 'implementation statement'
}
```
## Sample Transformed Data
```bash
{
    "control.id": "AC-17(2)",
    "result.status": "Partially Compliant",
    "result.percentage": "63.89%",
    "rule.id": ["ELB.1", "ElastiCache.5", "ES.8", "CloudFront.7", "ELB.3", "Opensearch.8", "ELB.8", "CloudFront.9", "APIGateway.2", "ELB.2", "CloudFront.3", "CloudFront.10", "S3.5"],
    "result.observation_timestamp": "2024-02-14 13:38:35.268000+00:00",
    "implementation statement": "As of the most recent evaluation on 2024-02-14 13:38:35.268000+00:00UTC, our Amazon Web Services (AWS) environment has been assessed as partially compliant with AC-17(2), according to NIST 800-53 rev 5 Operational Best Practices. This assessment utilized AWS Security Hub controls (including ELB.1, ElastiCache.5, ES.8, CloudFront.7, ELB.3, Opensearch.8, ELB.8, CloudFront.9, APIGateway.2, ELB.2, CloudFront.3, CloudFront.10, S3.5), and identified a 63.89% compliance rate for AC-17(2), which is evidence of a partially compliant implementation of this control."
}
```
## Sample Function
```python
def convert_to_oscal(csv_data):
    """
    Convert an AWS Security Hub Control Summary to the OSCAL format.
    """
    oscal_data = []

    reader = csv.DictReader(csv_data.splitlines())
    for row in reader:
        status = row["compliance_status"]
        if status.lower() == "partially compliant":
            status = "non-compliant"

        oscal_entry = {
            "control": {
                "id": row["compliance_control_id"],
                "description": row["narrative"]
            },
            "result": {
                "status": status,
                "percentage": row["percentage"],
                "observation_timestamp": row["lastobservedat"]
            },
            "rule": {
                "id": row["rule_id"].split(", ")
            }
        }
        oscal_data.append(oscal_entry)

    return oscal_data
    ```