"""
HIPAA 164.312(b) — CloudTrail enabled and multi-region.

Check logic:
  1. List all trails in the account.
  2. Confirm at least one trail has IsMultiRegionTrail=True.
  3. Confirm that trail has LogFileValidationEnabled=True.
  4. Confirm that trail is currently logging (GetTrailStatus → IsLogging).

Fix: infrabaseline HIPAA Kit → modules/cloudtrail
     var.enable_multi_region_trail = true
"""

import boto3
from botocore.exceptions import ClientError, NoCredentialsError

from infrabaseline_audit.models import CheckResult, Fix, Framework, Status
from infrabaseline_audit.fixes.registry import FIXES

CHECK_ID    = "hipaa-cloudtrail-enabled"
CONTROL_ID  = "164.312(b)"
TITLE       = "CloudTrail enabled + multi-region"
FRAMEWORK   = Framework.HIPAA


def run(session: boto3.Session) -> CheckResult:
    """
    Entry point called by runner.py.
    Every check receives a boto3.Session and returns a CheckResult.
    """
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
                issue="No CloudTrail trails found in this account.",
                fix=FIXES[CHECK_ID],
            )

        # Look for a multi-region trail with log validation that is actively logging
        for trail in trails:
            if not trail.get("IsMultiRegionTrail"):
                continue
            if not trail.get("LogFileValidationEnabled"):
                continue

            trail_arn = trail["TrailARN"]
            status_resp = ct.get_trail_status(Name=trail_arn)

            if status_resp.get("IsLogging"):
                return CheckResult(
                    check_id=CHECK_ID,
                    control_id=CONTROL_ID,
                    title=TITLE,
                    framework=FRAMEWORK,
                    status=Status.PASSING,
                )

        # Trails exist but none satisfy all three conditions — build a helpful issue message
        issues = []
        non_multi = [t["Name"] for t in trails if not t.get("IsMultiRegionTrail")]
        no_validation = [t["Name"] for t in trails if t.get("IsMultiRegionTrail") and not t.get("LogFileValidationEnabled")]
        not_logging = []

        for trail in trails:
            if trail.get("IsMultiRegionTrail") and trail.get("LogFileValidationEnabled"):
                s = ct.get_trail_status(Name=trail["TrailARN"])
                if not s.get("IsLogging"):
                    not_logging.append(trail["Name"])

        if non_multi:
            issues.append(f"Single-region trails (not compliant): {', '.join(non_multi)}")
        if no_validation:
            issues.append(f"Multi-region trails missing log validation: {', '.join(no_validation)}")
        if not_logging:
            issues.append(f"Multi-region trails not currently logging: {', '.join(not_logging)}")

        return CheckResult(
            check_id=CHECK_ID,
            control_id=CONTROL_ID,
            title=TITLE,
            framework=FRAMEWORK,
            status=Status.FAILING,
            issue=" | ".join(issues) if issues else "No compliant multi-region trail found.",
            fix=FIXES[CHECK_ID],
        )

    except NoCredentialsError:
        return CheckResult(
            check_id=CHECK_ID,
            control_id=CONTROL_ID,
            title=TITLE,
            framework=FRAMEWORK,
            status=Status.ERROR,
            error_msg="No AWS credentials found. Run 'aws configure' or set AWS_PROFILE.",
        )
    except ClientError as e:
        return CheckResult(
            check_id=CHECK_ID,
            control_id=CONTROL_ID,
            title=TITLE,
            framework=FRAMEWORK,
            status=Status.ERROR,
            error_msg=f"AWS API error: {e.response['Error']['Code']} — {e.response['Error']['Message']}",
        )
