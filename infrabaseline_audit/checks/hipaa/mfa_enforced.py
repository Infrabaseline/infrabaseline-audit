"""
HIPAA 164.312(d) — MFA enforced for all IAM users.

Check logic:
  1. List all IAM users.
  2. For each user, call list_mfa_devices.
  3. Flag any user with zero MFA devices attached.
  4. Also check if an account-level MFA enforcement policy is attached.

Fix: infrabaseline HIPAA Kit → modules/iam
     var.enforce_mfa = true
"""

import boto3
from botocore.exceptions import ClientError, NoCredentialsError

from infrabaseline_audit.models import CheckResult, Framework, Status
from infrabaseline_audit.fixes.registry import FIXES

CHECK_ID   = "hipaa-mfa-enforced"
CONTROL_ID = "164.312(d)"
TITLE      = "MFA enforced"
FRAMEWORK  = Framework.HIPAA


def run(session: boto3.Session) -> CheckResult:
    try:
        iam = session.client("iam")
        paginator = iam.get_paginator("list_users")
        users_without_mfa = []

        for page in paginator.paginate():
            for user in page["Users"]:
                username = user["UserName"]
                mfa_devices = iam.list_mfa_devices(UserName=username).get("MFADevices", [])
                if not mfa_devices:
                    users_without_mfa.append(username)

        if not users_without_mfa:
            return CheckResult(
                check_id=CHECK_ID,
                control_id=CONTROL_ID,
                title=TITLE,
                framework=FRAMEWORK,
                status=Status.PASSING,
            )

        # Check if there's at least an MFA enforcement policy in place (partial credit)
        mfa_policy_found = False
        policy_paginator = iam.get_paginator("list_policies")
        for page in policy_paginator.paginate(Scope="Local"):
            for policy in page["Policies"]:
                if "mfa" in policy["PolicyName"].lower() or "MFA" in policy["PolicyName"]:
                    mfa_policy_found = True
                    break

        detail = ", ".join(users_without_mfa[:5])
        if len(users_without_mfa) > 5:
            detail += f" ... and {len(users_without_mfa) - 5} more"

        issue = f"{len(users_without_mfa)} IAM user(s) have no MFA device registered."
        if mfa_policy_found:
            issue += " MFA enforcement policy exists but some users haven't enrolled."

        return CheckResult(
            check_id=CHECK_ID,
            control_id=CONTROL_ID,
            title=TITLE,
            framework=FRAMEWORK,
            status=Status.FAILING,
            issue=issue,
            detail=detail,
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
