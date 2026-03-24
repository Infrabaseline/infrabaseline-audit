"""
SOC2 CC7.2 — GuardDuty enabled and findings exported.

Check logic:
  1. List all GuardDuty detectors.
  2. Confirm at least one detector is ENABLED.
  3. Confirm a publishing destination (S3 or CloudWatch) is configured.

Fix: infrabaseline SOC 2 Kit → modules/guardduty
     var.enable_guardduty = true
"""

import boto3
from botocore.exceptions import ClientError, NoCredentialsError

from infrabaseline_audit.models import CheckResult, Framework, Status
from infrabaseline_audit.fixes.registry import FIXES

CHECK_ID   = "soc2-cc7-2-guardduty"
CONTROL_ID = "CC7.2"
TITLE      = "GuardDuty enabled"
FRAMEWORK  = Framework.SOC2


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
            if detector.get("Status") != "ENABLED":
                issues.append(f"Detector {detector_id} is not ENABLED")
                continue

            # Check for publishing destinations (findings export)
            destinations = gd.list_publishing_destinations(
                DetectorId=detector_id
            ).get("Destinations", [])

            active_destinations = [
                d for d in destinations
                if d.get("Status") == "PUBLISHING"
            ]

            if not active_destinations:
                issues.append(
                    f"Detector {detector_id} is ENABLED but has no active publishing destination for findings export"
                )
                # Still count as passing for basic enablement — just warn on export
                passing = True
            else:
                passing = True

        if passing and not issues:
            return CheckResult(
                check_id=CHECK_ID,
                control_id=CONTROL_ID,
                title=TITLE,
                framework=FRAMEWORK,
                status=Status.PASSING,
            )

        if passing and issues:
            return CheckResult(
                check_id=CHECK_ID,
                control_id=CONTROL_ID,
                title=TITLE,
                framework=FRAMEWORK,
                status=Status.WARNING,
                issue=" | ".join(issues),
                fix=FIXES[CHECK_ID],
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
