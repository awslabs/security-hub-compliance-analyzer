"""
DoD Zero Trust Activity to AWS Security Hub CSPM Control Mapping

This mapping is NOT prescriptive. It represents a proposed crosswalk between
DoD Zero Trust Capability Execution Roadmap activities and AWS Security Hub
CSPM security controls, based on the NIST SP 800-53 Rev. 5 requirements that
each control evaluates.

Organizations should review and accept or modify these mappings based on their
specific environment, risk posture, and authorization boundary.

The mapping rationale for each entry explains why the Security Hub control
provides evidence for the Zero Trust activity.
"""

import csv
import json
import io

# Format: {
#   "rule_id": {
#       "zt_activities": ["Activity.X.Y", ...],
#       "rationale": "Why this control supports these ZT activities"
#   }
# }
# Only controls with a clear, defensible link are mapped.

SH_TO_ZT_MAPPING = {
    # === IAM / Identity Controls ===
    "IAM.1": {
        "zt_activities": ["User.2.1"],
        "rationale": "Verifies no wildcard administrative privileges exist in IAM policies, enforcing least privilege access."
    },
    "IAM.2": {
        "zt_activities": ["User.2.1"],
        "rationale": "Ensures IAM users inherit permissions from groups/roles rather than direct policy attachment, supporting role-based access control."
    },
    "IAM.3": {
        "zt_activities": ["User.1.3"],
        "rationale": "Validates access key rotation within 90 days, ensuring credential lifecycle management."
    },
    "IAM.4": {
        "zt_activities": ["User.1.2", "User.5.1"],
        "rationale": "Confirms no root user access key exists, protecting the highest-privilege identity."
    },
    "IAM.5": {
        "zt_activities": ["User.1.1", "User.1.2"],
        "rationale": "Verifies MFA is enabled for IAM users with console passwords, enforcing multi-factor authentication."
    },
    "IAM.7": {
        "zt_activities": ["User.1.3"],
        "rationale": "Validates password policy strength (length, complexity, rotation), supporting credential management."
    },
    "IAM.8": {
        "zt_activities": ["User.1.3"],
        "rationale": "Identifies unused IAM credentials for removal, reducing the attack surface for credential compromise."
    },
    "IAM.9": {
        "zt_activities": ["User.2.1"],
        "rationale": "Ensures IAM users have no inline policies, enforcing centralized access management."
    },
    "IAM.19": {
        "zt_activities": ["User.1.1"],
        "rationale": "Verifies MFA is enabled for all IAM users, enforcing enterprise-wide multi-factor authentication."
    },

    # === KMS Controls ===
    "KMS.1": {
        "zt_activities": ["User.2.1", "Data.5.1"],
        "rationale": "Prevents overly permissive KMS decryption policies, enforcing least privilege on cryptographic operations."
    },
    "KMS.2": {
        "zt_activities": ["User.2.1", "Data.5.1"],
        "rationale": "Ensures IAM inline policies don't allow broad KMS decryption, supporting least privilege."
    },
    "KMS.3": {
        "zt_activities": ["Data.5.1"],
        "rationale": "Prevents unintended KMS key deletion, protecting cryptographic key availability."
    },
    "KMS.4": {
        "zt_activities": ["Data.5.1"],
        "rationale": "Validates KMS key rotation is enabled, ensuring cryptographic key lifecycle management."
    },

    # === EC2 / Network Controls ===
    "EC2.1": {
        "zt_activities": ["Net.3.1", "Data.2.1"],
        "rationale": "Ensures EBS snapshots are not publicly restorable, preventing unauthorized data exposure."
    },
    "EC2.2": {
        "zt_activities": ["Net.1.1", "Net.1.2"],
        "rationale": "Verifies default VPC security groups block all traffic, enforcing deny-by-default network policy."
    },
    "EC2.3": {
        "zt_activities": ["Data.1.1"],
        "rationale": "Validates attached EBS volumes are encrypted at rest."
    },
    "EC2.6": {
        "zt_activities": ["Net.2.1", "VA.1.1"],
        "rationale": "Ensures VPC flow logging is enabled for network traffic monitoring and analysis."
    },
    "EC2.7": {
        "zt_activities": ["Data.1.1"],
        "rationale": "Validates EBS default encryption is enabled, ensuring all new volumes are encrypted."
    },
    "EC2.8": {
        "zt_activities": ["Device.5.1"],
        "rationale": "Enforces IMDSv2 on EC2 instances, hardening instance metadata access against SSRF attacks."
    },
    "EC2.9": {
        "zt_activities": ["Net.3.1"],
        "rationale": "Ensures EC2 instances do not have public IPv4 addresses, restricting public exposure."
    },
    "EC2.13": {
        "zt_activities": ["Net.1.1"],
        "rationale": "Verifies security groups do not allow unrestricted SSH access, enforcing micro-segmentation."
    },
    "EC2.15": {
        "zt_activities": ["Net.3.1"],
        "rationale": "Ensures subnets do not auto-assign public IPs, restricting public network exposure."
    },
    "EC2.18": {
        "zt_activities": ["Net.1.1"],
        "rationale": "Validates security groups only allow authorized ports, enforcing network micro-segmentation."
    },
    "EC2.19": {
        "zt_activities": ["Net.1.1", "Device.4.1"],
        "rationale": "Ensures security groups block high-risk ports, reducing attack surface."
    },

    # === S3 Controls ===
    "S3.1": {
        "zt_activities": ["Net.3.1", "Data.2.1"],
        "rationale": "Validates S3 block public access at account level, preventing unauthorized data exposure."
    },
    "S3.2": {
        "zt_activities": ["Data.2.1"],
        "rationale": "Ensures S3 buckets block public read access."
    },
    "S3.3": {
        "zt_activities": ["Data.2.1"],
        "rationale": "Ensures S3 buckets block public write access."
    },
    "S3.5": {
        "zt_activities": ["Net.1.3", "Data.1.2"],
        "rationale": "Validates S3 buckets require SSL for requests, enforcing encrypted data in transit."
    },
    "S3.7": {
        "zt_activities": ["Data.3.1"],
        "rationale": "Ensures S3 cross-region replication for data backup and recovery."
    },
    "S3.8": {
        "zt_activities": ["Data.2.1"],
        "rationale": "Validates S3 bucket-level block public access settings."
    },
    "S3.9": {
        "zt_activities": ["VA.1.1"],
        "rationale": "Ensures S3 server access logging is enabled for audit trail."
    },
    "S3.14": {
        "zt_activities": ["Data.3.1"],
        "rationale": "Validates S3 versioning for data recovery capability."
    },
    "S3.17": {
        "zt_activities": ["Data.1.1"],
        "rationale": "Ensures S3 buckets are encrypted with KMS keys."
    },

    # === RDS Controls ===
    "RDS.2": {
        "zt_activities": ["Net.3.1"],
        "rationale": "Ensures RDS instances are not publicly accessible."
    },
    "RDS.3": {
        "zt_activities": ["Data.1.1"],
        "rationale": "Validates RDS encryption at rest."
    },
    "RDS.5": {
        "zt_activities": ["Data.3.2"],
        "rationale": "Ensures RDS Multi-AZ for data resilience."
    },
    "RDS.7": {
        "zt_activities": ["AO.5.1"],
        "rationale": "Validates RDS cluster deletion protection."
    },
    "RDS.8": {
        "zt_activities": ["AO.5.1"],
        "rationale": "Validates RDS instance deletion protection."
    },
    "RDS.10": {
        "zt_activities": ["User.4.1"],
        "rationale": "Ensures IAM authentication on RDS instances, supporting identity-based database access."
    },
    "RDS.11": {
        "zt_activities": ["Data.3.1"],
        "rationale": "Validates RDS automated backups are enabled."
    },
    "RDS.13": {
        "zt_activities": ["AO.2.1", "Device.1.2"],
        "rationale": "Ensures RDS auto minor version upgrades for automated patching."
    },

    # === ELB Controls ===
    "ELB.1": {
        "zt_activities": ["Net.1.3"],
        "rationale": "Validates ALB HTTP-to-HTTPS redirect, enforcing encrypted connections."
    },
    "ELB.3": {
        "zt_activities": ["Net.1.3"],
        "rationale": "Ensures Classic LB listeners use HTTPS/TLS termination."
    },
    "ELB.5": {
        "zt_activities": ["VA.1.1"],
        "rationale": "Validates load balancer access logging for security monitoring."
    },
    "ELB.6": {
        "zt_activities": ["AO.5.1"],
        "rationale": "Ensures load balancer deletion protection."
    },
    "ELB.17": {
        "zt_activities": ["Net.5.2"],
        "rationale": "Validates ALB/NLB use recommended TLS security policies."
    },

    # === CloudTrail Controls ===
    "CloudTrail.1": {
        "zt_activities": ["VA.1.1"],
        "rationale": "Ensures multi-region CloudTrail is enabled for centralized security logging."
    },
    "CloudTrail.2": {
        "zt_activities": ["VA.1.2", "Data.1.1"],
        "rationale": "Validates CloudTrail encryption at rest, protecting log integrity."
    },
    "CloudTrail.4": {
        "zt_activities": ["VA.1.2", "Data.4.1"],
        "rationale": "Ensures CloudTrail log file validation for log integrity verification."
    },
    "CloudTrail.5": {
        "zt_activities": ["VA.1.1", "VA.2.1"],
        "rationale": "Validates CloudTrail integration with CloudWatch Logs for real-time monitoring."
    },

    # === CloudWatch Controls ===
    "CloudWatch.15": {
        "zt_activities": ["VA.3.1"],
        "rationale": "Ensures CloudWatch alarms have actions configured for automated alerting."
    },
    "CloudWatch.16": {
        "zt_activities": ["VA.1.3"],
        "rationale": "Validates CloudWatch log group retention for log archival compliance."
    },

    # === GuardDuty ===
    "GuardDuty.1": {
        "zt_activities": ["VA.4.1", "VA.2.1", "Device.3.1"],
        "rationale": "Ensures GuardDuty is enabled for threat detection, continuous monitoring, and endpoint detection."
    },

    # === Config ===
    "Config.1": {
        "zt_activities": ["AO.1.1", "AO.4.1", "Device.1.1"],
        "rationale": "Validates AWS Config is enabled for automated compliance assessment, configuration drift detection, and device inventory."
    },

    # === SSM Controls ===
    "SSM.1": {
        "zt_activities": ["Device.1.1", "Device.2.1"],
        "rationale": "Ensures EC2 instances are managed by Systems Manager for device inventory and health assessment."
    },
    "SSM.2": {
        "zt_activities": ["AO.2.1", "Device.1.2"],
        "rationale": "Validates patch compliance status for automated vulnerability remediation."
    },
    "SSM.3": {
        "zt_activities": ["Device.2.1"],
        "rationale": "Ensures Systems Manager association compliance for device posture assessment."
    },

    # === Container/Serverless Controls ===
    "ECS.2": {
        "zt_activities": ["Net.3.1", "App.2.1"],
        "rationale": "Ensures ECS services don't auto-assign public IPs, supporting workload isolation."
    },
    "ECS.17": {
        "zt_activities": ["App.2.1", "User.2.1"],
        "rationale": "Validates ECS task definitions don't use host network mode, enforcing container isolation."
    },
    "EKS.1": {
        "zt_activities": ["Net.3.1", "App.1.1"],
        "rationale": "Ensures EKS cluster endpoints are not publicly accessible."
    },
    "EKS.3": {
        "zt_activities": ["Data.1.1", "App.2.1"],
        "rationale": "Validates EKS uses encrypted Kubernetes secrets."
    },
    "Lambda.1": {
        "zt_activities": ["Net.3.1", "App.1.1"],
        "rationale": "Ensures Lambda function policies prohibit public access."
    },
    "Lambda.2": {
        "zt_activities": ["AO.2.1", "App.4.1"],
        "rationale": "Validates Lambda functions use supported runtimes for vulnerability management."
    },
    "Lambda.3": {
        "zt_activities": ["Net.1.1", "App.2.1"],
        "rationale": "Ensures Lambda functions are in a VPC for network isolation."
    },

    # === API Gateway Controls ===
    "APIGateway.1": {
        "zt_activities": ["VA.1.1", "App.1.2"],
        "rationale": "Validates API Gateway execution logging for API security monitoring."
    },
    "APIGateway.2": {
        "zt_activities": ["Net.1.3", "App.1.2"],
        "rationale": "Ensures API Gateway uses SSL certificates for backend authentication."
    },
    "APIGateway.4": {
        "zt_activities": ["Net.4.1"],
        "rationale": "Validates API Gateway is associated with a WAF Web ACL for application protection."
    },
    "APIGateway.5": {
        "zt_activities": ["Data.1.1"],
        "rationale": "Ensures API Gateway cache data is encrypted at rest."
    },
    "APIGateway.8": {
        "zt_activities": ["App.1.1"],
        "rationale": "Validates API Gateway routes specify an authorization type, enforcing access control."
    },

    # === Encryption Controls ===
    "ES.1": {
        "zt_activities": ["Data.1.1"],
        "rationale": "Validates Elasticsearch encryption at rest."
    },
    "ES.3": {
        "zt_activities": ["Data.1.2", "Net.1.3"],
        "rationale": "Ensures Elasticsearch node-to-node encryption for data in transit."
    },
    "ES.8": {
        "zt_activities": ["Net.5.2"],
        "rationale": "Validates Elasticsearch uses latest TLS security policy."
    },
    "EFS.1": {
        "zt_activities": ["Data.1.1"],
        "rationale": "Ensures EFS encryption at rest with KMS."
    },
    "SNS.1": {
        "zt_activities": ["Data.1.1"],
        "rationale": "Validates SNS topic encryption at rest with KMS."
    },
    "SQS.1": {
        "zt_activities": ["Data.1.1"],
        "rationale": "Ensures SQS queue encryption at rest."
    },
    "Redshift.1": {
        "zt_activities": ["Net.3.1"],
        "rationale": "Ensures Redshift clusters are not publicly accessible."
    },
    "Redshift.2": {
        "zt_activities": ["Net.1.3", "Data.1.2"],
        "rationale": "Validates Redshift connections use encryption in transit."
    },
    "Redshift.6": {
        "zt_activities": ["AO.2.1"],
        "rationale": "Ensures Redshift automatic major version upgrades for patching."
    },
    "DMS.1": {
        "zt_activities": ["Net.3.1"],
        "rationale": "Ensures DMS replication instances are not public."
    },

    # === Backup/Resilience Controls ===
    "Backup.1": {
        "zt_activities": ["Data.3.1"],
        "rationale": "Validates backup recovery points are encrypted at rest."
    },
    "DynamoDB.1": {
        "zt_activities": ["AO.3.1"],
        "rationale": "Ensures DynamoDB auto-scaling for resilience."
    },
    "DynamoDB.2": {
        "zt_activities": ["Data.3.1"],
        "rationale": "Validates DynamoDB point-in-time recovery for data backup."
    },
    "DynamoDB.4": {
        "zt_activities": ["Data.3.1"],
        "rationale": "Ensures DynamoDB tables are in backup plans."
    },
    "DynamoDB.6": {
        "zt_activities": ["AO.5.1"],
        "rationale": "Validates DynamoDB deletion protection."
    },
    "EFS.2": {
        "zt_activities": ["Data.3.1"],
        "rationale": "Ensures EFS volumes are in backup plans."
    },

    # === WAF Controls ===
    "ELB.16": {
        "zt_activities": ["Net.4.1"],
        "rationale": "Validates ALB is associated with a WAF Web ACL for application protection."
    },
    "WAF.11": {
        "zt_activities": ["VA.1.1", "Net.4.1"],
        "rationale": "Ensures WAF web ACL logging is enabled for security monitoring."
    },

    # === Code Security ===
    "CodeBuild.1": {
        "zt_activities": ["App.3.1"],
        "rationale": "Ensures CodeBuild source URLs don't contain credentials, supporting secure development."
    },
    "CodeBuild.2": {
        "zt_activities": ["App.3.1"],
        "rationale": "Validates CodeBuild projects don't have cleartext credentials in environment variables."
    },

    # === Secrets Manager ===
    "SecretsManager.1": {
        "zt_activities": ["User.1.3"],
        "rationale": "Ensures secrets have automatic rotation enabled for credential lifecycle management."
    },
    "SecretsManager.3": {
        "zt_activities": ["User.1.3"],
        "rationale": "Identifies unused secrets for removal, reducing credential attack surface."
    },
    "SecretsManager.4": {
        "zt_activities": ["User.1.3"],
        "rationale": "Validates secrets are rotated within specified timeframe."
    },

    # === ACM ===
    "ACM.1": {
        "zt_activities": ["Net.5.2", "Data.5.1"],
        "rationale": "Ensures certificates are renewed before expiration for continuous TLS protection."
    },

    # === SageMaker ===
    "SageMaker.1": {
        "zt_activities": ["Net.3.1"],
        "rationale": "Ensures SageMaker notebooks don't have direct internet access."
    },

    # === EMR ===
    "EMR.1": {
        "zt_activities": ["Net.3.1"],
        "rationale": "Ensures EMR primary nodes don't have public IP addresses."
    },

    # === Account ===
    "Account.1": {
        "zt_activities": ["AO.1.1"],
        "rationale": "Validates security contact information is provided for incident response."
    },
}


def get_zt_activities_for_rule(rule_id):
    """Return ZT activities and rationale for a Security Hub control."""
    entry = SH_TO_ZT_MAPPING.get(rule_id)
    if entry:
        return entry["zt_activities"], entry["rationale"]
    return [], ""


def export_mapping_csv():
    """Export the full mapping as CSV string."""
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "security_hub_control",
        "zt_activity",
        "zt_pillar",
        "zt_level",
        "zt_description",
        "mapping_rationale",
    ])

    from zt_mapping import ZT_ACTIVITIES
    zt_lookup = {a[0]: (a[1], a[2], a[3]) for a in ZT_ACTIVITIES}

    for rule_id, entry in sorted(SH_TO_ZT_MAPPING.items()):
        for zt_act in entry["zt_activities"]:
            pillar, level, desc = zt_lookup.get(zt_act, ("Unknown", "Unknown", "Unknown"))
            writer.writerow([
                rule_id,
                zt_act,
                pillar,
                level,
                desc,
                entry["rationale"],
            ])

    return output.getvalue()


def export_mapping_json():
    """Export the full mapping as JSON string."""
    from zt_mapping import ZT_ACTIVITIES
    zt_lookup = {a[0]: {"pillar": a[1], "level": a[2], "description": a[3]} for a in ZT_ACTIVITIES}

    result = []
    for rule_id, entry in sorted(SH_TO_ZT_MAPPING.items()):
        for zt_act in entry["zt_activities"]:
            zt_info = zt_lookup.get(zt_act, {})
            result.append({
                "security_hub_control": rule_id,
                "zt_activity": zt_act,
                "zt_pillar": zt_info.get("pillar", "Unknown"),
                "zt_level": zt_info.get("level", "Unknown"),
                "zt_description": zt_info.get("description", "Unknown"),
                "mapping_rationale": entry["rationale"],
            })

    return json.dumps(result, indent=2)
