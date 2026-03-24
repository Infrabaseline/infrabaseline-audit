"""
SOC2 CC6.7 — S3 public access blocked on all buckets.

Check logic:
  Identical to HIPAA hipaa-s3-public-access but mapped to SOC2 CC6.7.
  All four Block Public Access flags must be True on every bucket.

Fix: infrabaseline SOC 2 Kit → modules/s3
     var.block_public_access = true
"""

import boto3
from botocore.exceptions import ClientError, NoCredentialsError

from infrabaseline_audit.models import CheckResult, Framework, Status
from infrabaseline_audit.fixes.registry import FIXES

CHECK_ID   = "soc2-cc6-7-s3-public"
CONTROL_ID = "CC6.7"
TITLE      = "S3 public access blocked"
FRAMEWORK  = Framework.SOC2

BPA_KEYS = [
    "BlockPublicAcls",
    "IgnorePublicAcls",
    "BlockPublicPolicy",
    "RestrictPublicBuckets",
]


def run(session: boto3.Session) -> CheckResult:
    try:
        s3 = session.client("s3")
        buckets = s3.list_buckets().get("Buckets", [])

        if not buckets:
            return CheckResult(
                check_id=CHECK_ID,
                control_id=CONTROL_ID,
                title=TITLE,
                framework=FRAMEWORK,
                status=Status.WARNING,
                issue="No S3 buckets found in this account.",
            )

        failing_buckets = []

        for bucket in buckets:
            name = bucket["Name"]
            try:
                resp = s3.get_public_access_block(Bucket=name)
                config = resp.get("PublicAccessBlockConfiguration", {})
                if not all(config.get(k) for k in BPA_KEYS):
                    missing = [k for k in BPA_KEYS if not config.get(k)]
                    failing_buckets.append(f"{name} (missing: {', '.join(missing)})")
            except ClientError as e:
                if e.response["Error"]["Code"] == "NoSuchPublicAccessBlockConfiguration":
                    failing_buckets.append(f"{name} (no Block Public Access config)")
                else:
                    failing_buckets.append(f"{name} (error: {e.response['Error']['Code']})")

        if failing_buckets:
            detail = "; ".join(failing_buckets[:5])
            if len(failing_buckets) > 5:
                detail += f" ... and {len(failing_buckets) - 5} more"
            return CheckResult(
                check_id=CHECK_ID,
                control_id=CONTROL_ID,
                title=TITLE,
                framework=FRAMEWORK,
                status=Status.FAILING,
                issue=f"{len(failing_buckets)} bucket(s) not fully blocking public access.",
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
