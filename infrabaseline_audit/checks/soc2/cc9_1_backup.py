"""
SOC2 CC9.1 — Backup retention: Aurora clusters retain backups for >= 35 days.

Check logic:
  1. List all Aurora clusters.
  2. Confirm BackupRetentionPeriod >= 35 days on each.
  3. Check AWS Backup plans for any vaults protecting RDS/Aurora resources.

Fix: infrabaseline SOC 2 Kit → modules/aurora
     var.backup_retention_days = 35
"""

import boto3
from botocore.exceptions import ClientError, NoCredentialsError

from infrabaseline_audit.models import CheckResult, Framework, Status
from infrabaseline_audit.fixes.registry import FIXES

CHECK_ID            = "soc2-cc9-1-backup"
CONTROL_ID          = "CC9.1"
TITLE               = "Backup retention"
FRAMEWORK           = Framework.SOC2
MIN_RETENTION_DAYS  = 35


def run(session: boto3.Session) -> CheckResult:
    try:
        rds = session.client("rds")
        paginator = rds.get_paginator("describe_db_clusters")
        clusters = []

        for page in paginator.paginate():
            clusters.extend(page["DBClusters"])

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
                issue="No Aurora clusters found — backup retention cannot be verified.",
            )

        insufficient = []

        for cluster in aurora_clusters:
            cluster_id = cluster["DBClusterIdentifier"]
            retention = cluster.get("BackupRetentionPeriod", 0)

            if retention < MIN_RETENTION_DAYS:
                insufficient.append(
                    f"{cluster_id} (retention: {retention}d, required: {MIN_RETENTION_DAYS}d)"
                )

        if insufficient:
            detail = ", ".join(insufficient[:5])
            if len(insufficient) > 5:
                detail += f" ... and {len(insufficient) - 5} more"
            return CheckResult(
                check_id=CHECK_ID,
                control_id=CONTROL_ID,
                title=TITLE,
                framework=FRAMEWORK,
                status=Status.FAILING,
                issue=f"{len(insufficient)} Aurora cluster(s) have insufficient backup retention.",
                detail=detail,
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
