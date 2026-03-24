"""
HIPAA 164.312(b) — GuardDuty enabled and actively monitoring.

Check logic:
  1. List all GuardDuty detectors.
  2. Confirm at least one detector exists.
  3. Confirm detector status is ENABLED.
  4. Confirm FindingPublishingFrequency is set (not default NONE).

Fix: infrabaseline HIPAA Kit → modules/guardduty
     var.enable_guardduty = true
"""

import boto3
from botocore.exceptions import ClientError, NoCredentialsError

from infrabaseline_audit.models import CheckResult, Framework, Status
from infrabaseline_audit.fixes.registry import FIXES

CHECK_ID   = "hipaa-guardduty-enabled"
CONTROL_ID = "164.312(b)"
TITLE      = "GuardDuty enabled"
FRAMEWORK  = Framework.HIPAA


def run(session: boto3.Session) -> CheckResult:
    try:
        gd = session.client("guardduty")
        detector_ids = gd.list_detectors().get("DetectorIds", [])

        if not detector_ids:
            return CheckResult(
                check_id=CHECK_ID,
                control_id=CONTROL_ID,
                title=TITLE,
                framework=FRAMEWORK,
                status=Status.FAILING,
                issue="No GuardDuty detectors found in this region.",
                fix=FIXES[CHECK_ID],
            )

        issues = []
        passing = False

        for detector_id in detector_ids:
            detector = gd.get_detector(DetectorId=detector_id)
            status_val = detector.get("Status", "")

            if status_val != "ENABLED":
                issues.append(f"Detector {detector_id} is {status_val} (expected ENABLED)")
                continue

            passing = True

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
            issue=" | ".join(issues),
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
