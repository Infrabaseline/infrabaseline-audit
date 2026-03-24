"""
HIPAA 164.312(a)(2)(iv) — Aurora clusters encrypted at rest with CMK.

Check logic:
  1. List all RDS DB clusters (Aurora clusters).
  2. Confirm StorageEncrypted=True for each.
  3. Confirm KmsKeyId is a customer-managed key (not alias/aws/rds).

Fix: infrabaseline HIPAA Kit → modules/aurora
     var.storage_encrypted = true
"""

import boto3
from botocore.exceptions import ClientError, NoCredentialsError

from infrabaseline_audit.models import CheckResult, Framework, Status
from infrabaseline_audit.fixes.registry import FIXES

CHECK_ID   = "hipaa-aurora-encryption"
CONTROL_ID = "164.312(a)(2)(iv)"
TITLE      = "Aurora encryption at rest"
FRAMEWORK  = Framework.HIPAA


def run(session: boto3.Session) -> CheckResult:
    try:
        rds = session.client("rds")
        paginator = rds.get_paginator("describe_db_clusters")
        clusters = []

        for page in paginator.paginate():
            clusters.extend(page["DBClusters"])

        # Filter to Aurora clusters only
        aurora_clusters = [
            c for c in clusters
            if c.get("Engine", "").startswith("aurora")
        ]

        if not aurora_clusters:
            return CheckResult(
                check_id=CHECK_ID,
                control_id=CONTROL_ID,
                title=TITLE,
                framework=FRAMEWORK,
                status=Status.WARNING,
                issue="No Aurora clusters found in this region.",
            )

        unencrypted = []
        default_key = []

        for cluster in aurora_clusters:
            cluster_id = cluster["DBClusterIdentifier"]

            if not cluster.get("StorageEncrypted"):
                unencrypted.append(cluster_id)
                continue

            kms_key = cluster.get("KmsKeyId", "")
            if "alias/aws/rds" in kms_key:
                default_key.append(cluster_id)

        issues = []
        if unencrypted:
            issues.append(f"Unencrypted clusters: {', '.join(unencrypted)}")
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
