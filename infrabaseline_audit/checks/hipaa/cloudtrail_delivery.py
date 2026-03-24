"""
HIPAA 164.312(b) — CloudTrail log delivery working (S3 delivery confirmed).

Check logic:
  1. List all trails.
  2. For each multi-region trail, confirm S3BucketName is set.
  3. Call get_trail_status and confirm LatestDeliveryTime is within last 24h.
  4. Confirm no LatestDeliveryError is present.

Fix: infrabaseline HIPAA Kit → modules/cloudtrail
     var.enable_log_delivery = true
"""

import boto3
from botocore.exceptions import ClientError, NoCredentialsError
from datetime import datetime, timezone, timedelta

from infrabaseline_audit.models import CheckResult, Framework, Status
from infrabaseline_audit.fixes.registry import FIXES

CHECK_ID   = "hipaa-cloudtrail-delivery"
CONTROL_ID = "164.312(b)"
TITLE      = "CloudTrail log delivery working"
FRAMEWORK  = Framework.HIPAA
MAX_DELIVERY_AGE_HOURS = 24


def run(session: boto3.Session) -> CheckResult:
    try:
        ct = session.client("cloudtrail")
        trails = ct.describe_trails(includeShadowTrails=False).get("trailList", [])

        if not trails:
            return CheckResult(
                check_id=CHECK_ID,
                control_id=CONTROL_ID,
                title=TITLE,
                framework=FRAMEWORK,
                status=Status.FAILING,
                issue="No CloudTrail trails found — log delivery cannot be confirmed.",
                fix=FIXES[CHECK_ID],
            )

        issues = []
        passing = False

        for trail in trails:
            if not trail.get("IsMultiRegionTrail"):
                continue

            name = trail["Name"]
            s3_bucket = trail.get("S3BucketName")

            if not s3_bucket:
                issues.append(f"{name}: no S3 delivery bucket configured")
                continue

            status_resp = ct.get_trail_status(Name=trail["TrailARN"])

            delivery_error = status_resp.get("LatestDeliveryError")
            if delivery_error:
                issues.append(f"{name}: delivery error — {delivery_error}")
                continue

            latest_delivery = status_resp.get("LatestDeliveryTime")
            if not latest_delivery:
                issues.append(f"{name}: no delivery recorded yet")
                continue

            cutoff = datetime.now(timezone.utc) - timedelta(hours=MAX_DELIVERY_AGE_HOURS)
            if latest_delivery < cutoff:
                age_h = int((datetime.now(timezone.utc) - latest_delivery).total_seconds() / 3600)
                issues.append(f"{name}: last delivery was {age_h}h ago (threshold: {MAX_DELIVERY_AGE_HOURS}h)")
                continue

            passing = True
            break

        if passing:
            return CheckResult(
                check_id=CHECK_ID,
                control_id=CONTROL_ID,
                title=TITLE,
                framework=FRAMEWORK,
                status=Status.PASSING,
            )

        return CheckResult(
            check_id=CHECK_ID,
            control_id=CONTROL_ID,
            title=TITLE,
            framework=FRAMEWORK,
            status=Status.FAILING,
            issue=" | ".join(issues) if issues else "No multi-region trail with active log delivery found.",
            fix=FIXES[CHECK_ID],
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
