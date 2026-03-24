"""
HIPAA 164.312(a)(2)(i) — Secrets Manager rotation configured on all secrets.

Check logic:
  1. List all Secrets Manager secrets.
  2. For each secret, confirm RotationEnabled=True.
  3. Confirm LastRotatedDate is within the rotation interval.

Fix: infrabaseline HIPAA Kit → modules/secrets
     var.enable_rotation = true
"""

import boto3
from botocore.exceptions import ClientError, NoCredentialsError
from datetime import datetime, timezone, timedelta

from infrabaseline_audit.models import CheckResult, Framework, Status
from infrabaseline_audit.fixes.registry import FIXES

CHECK_ID   = "hipaa-secrets-rotation"
CONTROL_ID = "164.312(a)(2)(i)"
TITLE      = "Secrets rotation configured"
FRAMEWORK  = Framework.HIPAA


def run(session: boto3.Session) -> CheckResult:
    try:
        sm = session.client("secretsmanager")
        paginator = sm.get_paginator("list_secrets")

        no_rotation = []
        overdue = []
        total = 0

        for page in paginator.paginate():
            for secret in page["SecretList"]:
                total += 1
                name = secret["Name"]

                if not secret.get("RotationEnabled"):
                    no_rotation.append(name)
                    continue

                rotation_days = secret.get("RotationRules", {}).get("AutomaticallyAfterDays", 90)
                last_rotated = secret.get("LastRotatedDate")

                if last_rotated:
                    cutoff = datetime.now(timezone.utc) - timedelta(days=rotation_days + 7)
                    if last_rotated < cutoff:
                        overdue.append(f"{name} (overdue by rotation policy)")

        if total == 0:
            return CheckResult(
                check_id=CHECK_ID,
                control_id=CONTROL_ID,
                title=TITLE,
                framework=FRAMEWORK,
                status=Status.WARNING,
                issue="No Secrets Manager secrets found in this account.",
            )

        issues = []
        if no_rotation:
            issues.append(f"{len(no_rotation)} secret(s) have rotation disabled")
        if overdue:
            issues.append(f"{len(overdue)} secret(s) overdue for rotation")

        if issues:
            all_violations = no_rotation + [o.split(" ")[0] for o in overdue]
            detail = ", ".join(all_violations[:5])
            if len(all_violations) > 5:
                detail += f" ... and {len(all_violations) - 5} more"
            return CheckResult(
                check_id=CHECK_ID,
                control_id=CONTROL_ID,
                title=TITLE,
                framework=FRAMEWORK,
                status=Status.FAILING,
                issue=" | ".join(issues),
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
