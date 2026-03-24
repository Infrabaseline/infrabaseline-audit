"""
Fix registry — maps every control_id to the exact Infrabaseline module
and variable that remediates it.

This is intentionally decoupled from check logic so mappings can be
updated independently (e.g. when a new kit version ships a new variable name).

Keys are check_id strings matching CheckResult.check_id.
"""

from infrabaseline_audit.models import Fix

FIXES: dict[str, Fix] = {

    # ── HIPAA ────────────────────────────────────────────────────────────────

    "hipaa-kms-rds": Fix(
        kit="HIPAA Kit",
        module="modules/kms",
        variable="var.enable_rds_encryption",
        value="true",
        description="Creates a dedicated CMK for RDS and attaches it to all instances.",
    ),

    "hipaa-s3-public-access": Fix(
        kit="HIPAA Kit",
        module="modules/s3",
        variable="var.block_public_access",
        value="true",
        description="Enables all four S3 Block Public Access settings at the bucket level.",
    ),

    "hipaa-cloudtrail-enabled": Fix(
        kit="HIPAA Kit",
        module="modules/cloudtrail",
        variable="var.enable_multi_region_trail",
        value="true",
        description="Creates a multi-region CloudTrail trail with log file validation.",
    ),

    "hipaa-cloudtrail-delivery": Fix(
        kit="HIPAA Kit",
        module="modules/cloudtrail",
        variable="var.enable_log_delivery",
        value="true",
        description="Configures S3 delivery bucket with KMS encryption for trail logs.",
    ),

    "hipaa-guardduty-enabled": Fix(
        kit="HIPAA Kit",
        module="modules/guardduty",
        variable="var.enable_guardduty",
        value="true",
        description="Enables GuardDuty detector in all configured regions.",
    ),

    "hipaa-iam-no-wildcards": Fix(
        kit="HIPAA Kit",
        module="modules/iam",
        variable="var.deny_wildcard_actions",
        value="true",
        description="Attaches an SCP/IAM boundary that denies policies with Action: '*'.",
    ),

    "hipaa-mfa-enforced": Fix(
        kit="HIPAA Kit",
        module="modules/iam",
        variable="var.enforce_mfa",
        value="true",
        description="Attaches MFA enforcement policy using BoolIfExists condition key.",
    ),

    "hipaa-vpc-flow-logs": Fix(
        kit="HIPAA Kit",
        module="modules/vpc",
        variable="var.enable_flow_logs",
        value="true",
        description="Enables VPC Flow Logs to CloudWatch Logs with a 365-day retention group.",
    ),

    "hipaa-secrets-rotation": Fix(
        kit="HIPAA Kit",
        module="modules/secrets",
        variable="var.enable_rotation",
        value="true",
        description="Configures automatic rotation on all Secrets Manager secrets.",
    ),

    "hipaa-aurora-encryption": Fix(
        kit="HIPAA Kit",
        module="modules/aurora",
        variable="var.storage_encrypted",
        value="true",
        description="Enforces storage encryption on Aurora clusters using the KMS CMK.",
    ),

    # ── SOC 2 ────────────────────────────────────────────────────────────────

    "soc2-cc6-1-least-privilege": Fix(
        kit="SOC 2 Kit",
        module="modules/iam",
        variable="var.enable_least_privilege_boundaries",
        value="true",
        description="Deploys permission boundaries and SCPs scoped to approved service actions.",
    ),

    "soc2-cc6-7-s3-public": Fix(
        kit="SOC 2 Kit",
        module="modules/s3",
        variable="var.block_public_access",
        value="true",
        description="Enables all four S3 Block Public Access settings at the bucket level.",
    ),

    "soc2-cc7-2-guardduty": Fix(
        kit="SOC 2 Kit",
        module="modules/guardduty",
        variable="var.enable_guardduty",
        value="true",
        description="Enables GuardDuty detector and configures finding export to S3.",
    ),

    "soc2-cc6-3-mfa": Fix(
        kit="SOC 2 Kit",
        module="modules/iam",
        variable="var.enforce_mfa",
        value="true",
        description="Attaches MFA enforcement policy using BoolIfExists condition key.",
    ),

    "soc2-cc7-1-cloudtrail": Fix(
        kit="SOC 2 Kit",
        module="modules/cloudtrail",
        variable="var.enable_multi_region_trail",
        value="true",
        description="Creates a multi-region CloudTrail trail with log file validation.",
    ),

    "soc2-cc6-6-vpc": Fix(
        kit="SOC 2 Kit",
        module="modules/vpc",
        variable="var.enable_flow_logs",
        value="true",
        description="Enables VPC Flow Logs and restricts default security group rules.",
    ),

    "soc2-cc9-1-backup": Fix(
        kit="SOC 2 Kit",
        module="modules/aurora",
        variable="var.backup_retention_days",
        value="35",
        description="Sets Aurora backup retention to 35 days and enables automated backups.",
    ),

    "soc2-cc6-8-kms": Fix(
        kit="SOC 2 Kit",
        module="modules/kms",
        variable="var.enable_key_rotation",
        value="true",
        description="Enables automatic annual key rotation on all customer-managed KMS keys.",
    ),

    "soc2-cc7-3-log-retention": Fix(
        kit="SOC 2 Kit",
        module="modules/cloudtrail",
        variable="var.log_retention_days",
        value="365",
        description="Sets CloudWatch Logs retention policy to 365 days on the trail log group.",
    ),

    "soc2-cc6-2-passrole": Fix(
        kit="SOC 2 Kit",
        module="modules/iam",
        variable="var.scope_pass_role",
        value="true",
        description="Scopes iam:PassRole to approved services only via an explicit allow policy.",
    ),
}
