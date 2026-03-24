"""
SOC2 CC7.1 — CloudTrail logging enabled and multi-region.

Check logic:
  Mirrors HIPAA hipaa-cloudtrail-enabled but scoped to SOC2 CC7.1.
  At least one multi-region trail must be active with log validation.

Fix: infrabaseline SOC 2 Kit → modules/cloudtrail
     var.enable_multi_region_trail = true
"""

import boto3
from botocore.exceptions import ClientError, NoCredentialsError

from infrabaseline_audit.models import CheckResult, Framework, Status
from infrabaseline_audit.fixes.registry import FIXES

CHECK_ID   = "soc2-cc7-1-cloudtrail"
CONTROL_ID = "CC7.1"
TITLE      = "CloudTrail logging"
FRAMEWORK  = Framework.SOC2


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
                issue="No CloudTrail trails found in this account.",
                fix=FIXES[CHECK_ID],
            )

        issues = []

        for trail in trails:
            if not trail.get("IsMultiRegionTrail"):
                continue
            if not trail.get("LogFileValidationEnabled"):
                continue

            status_resp = ct.get_trail_status(Name=trail["TrailARN"])
            if status_resp.get("IsLogging"):
                return CheckResult(
                    check_id=CHECK_ID,
                    control_id=CONTROL_ID,
                    title=TITLE,
                    framework=FRAMEWORK,
                    status=Status.PASSING,
                )

        non_multi = [t["Name"] for t in trails if not t.get("IsMultiRegionTrail")]
        if non_multi:
            issues.append(f"Single-region trails only: {', '.join(non_multi)}")

        no_validation = [
            t["Name"] for t in trails
            if t.get("IsMultiRegionTrail") and not t.get("LogFileValidationEnabled")
        ]
        if no_validation:
            issues.append(f"Missing log validation: {', '.join(no_validation)}")

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
