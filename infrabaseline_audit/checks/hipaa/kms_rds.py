"""
HIPAA 164.312(a)(2)(iv) — KMS encryption on RDS instances.

Check logic:
  1. List all RDS DB instances.
  2. Confirm every instance has StorageEncrypted=True.
  3. Confirm the KmsKeyId is a customer-managed key (not the default aws/rds alias).

Fix: infrabaseline HIPAA Kit → modules/kms
     var.enable_rds_encryption = true
"""

import boto3
from botocore.exceptions import ClientError, NoCredentialsError

from infrabaseline_audit.models import CheckResult, Framework, Status
from infrabaseline_audit.fixes.registry import FIXES

CHECK_ID   = "hipaa-kms-rds"
CONTROL_ID = "164.312(a)(2)(iv)"
TITLE      = "KMS encryption on RDS"
FRAMEWORK  = Framework.HIPAA


def run(session: boto3.Session) -> CheckResult:
    try:
        rds = session.client("rds")
        paginator = rds.get_paginator("describe_db_instances")
        instances = []
        for page in paginator.paginate():
            instances.extend(page["DBInstances"])

        if not instances:
            return CheckResult(
                check_id=CHECK_ID,
                control_id=CONTROL_ID,
                title=TITLE,
                framework=FRAMEWORK,
                status=Status.WARNING,
                issue="No RDS instances found in this account/region.",
            )

        unencrypted = []
        default_key = []

        for db in instances:
            db_id = db["DBInstanceIdentifier"]
            if not db.get("StorageEncrypted"):
                unencrypted.append(db_id)
                continue
            kms_key = db.get("KmsKeyId", "")
            if "alias/aws/rds" in kms_key:
                default_key.append(db_id)

        issues = []
        if unencrypted:
            issues.append(f"Unencrypted instances: {', '.join(unencrypted)}")
        if default_key:
            issues.append(f"Using default aws/rds key (CMK required): {', '.join(default_key)}")

        if issues:
            return CheckResult(
                check_id=CHECK_ID,
                control_id=CONTROL_ID,
                title=TITLE,
                framework=FRAMEWORK,
                status=Status.FAILING,
                issue=" | ".join(issues),
                fix=FIXES[CHECK_ID],
            )

        return CheckResult(
            check_id=CHECK_ID,
            control_id=CONTROL_ID,
            title=TITLE,
            framework=FRAMEWORK,
            status=Status.PASSING,
        )

    except NoCredentialsError:
        return CheckResult(
            check_id=CHECK_ID, control_id=CONTROL_ID, title=TITLE, framework=FRAMEWORK,
            status=Status.ERROR,
            error_msg="No AWS credentials found. Run 'aws configure' or set AWS_PROFILE.",
        )
    except ClientError as e:
        return CheckResult(
            check_id=CHECK_ID, control_id=CONTROL_ID, title=TITLE, framework=FRAMEWORK,
            status=Status.ERROR,
            error_msg=f"AWS API error: {e.response['Error']['Code']} — {e.response['Error']['Message']}",
        )
