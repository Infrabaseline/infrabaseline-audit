"""
SOC2 CC6.3 — MFA enforced for all IAM users with console access.

Check logic:
  1. List all IAM users.
  2. Get login profile to identify console users.
  3. For console users, confirm at least one MFA device is registered.

Fix: infrabaseline SOC 2 Kit → modules/iam
     var.enforce_mfa = true
"""

import boto3
from botocore.exceptions import ClientError, NoCredentialsError

from infrabaseline_audit.models import CheckResult, Framework, Status
from infrabaseline_audit.fixes.registry import FIXES

CHECK_ID   = "soc2-cc6-3-mfa"
CONTROL_ID = "CC6.3"
TITLE      = "MFA enforced"
FRAMEWORK  = Framework.SOC2


def run(session: boto3.Session) -> CheckResult:
    try:
        iam = session.client("iam")
        paginator = iam.get_paginator("list_users")
        users_without_mfa = []
        console_users_checked = 0

        for page in paginator.paginate():
            for user in page["Users"]:
                username = user["UserName"]

                # Only check users with console access (login profile)
                try:
                    iam.get_login_profile(UserName=username)
                    has_console = True
                except ClientError as e:
                    if e.response["Error"]["Code"] == "NoSuchEntity":
                        has_console = False
                    else:
                        raise

                if not has_console:
                    continue

                console_users_checked += 1
                mfa_devices = iam.list_mfa_devices(UserName=username).get("MFADevices", [])
                if not mfa_devices:
                    users_without_mfa.append(username)

        if console_users_checked == 0:
            return CheckResult(
                check_id=CHECK_ID,
                control_id=CONTROL_ID,
                title=TITLE,
                framework=FRAMEWORK,
                status=Status.WARNING,
                issue="No IAM users with console access found.",
            )

        if users_without_mfa:
            detail = ", ".join(users_without_mfa[:5])
            if len(users_without_mfa) > 5:
                detail += f" ... and {len(users_without_mfa) - 5} more"
            return CheckResult(
                check_id=CHECK_ID,
                control_id=CONTROL_ID,
                title=TITLE,
                framework=FRAMEWORK,
                status=Status.FAILING,
                issue=f"{len(users_without_mfa)} console user(s) have no MFA registered.",
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
