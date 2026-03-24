"""
SOC2 CC6.8 — KMS customer-managed keys have automatic rotation enabled.

Check logic:
  1. List all customer-managed KMS keys (KeyManager=CUSTOMER).
  2. For each key, call get_key_rotation_status.
  3. Flag any key where rotation is disabled.
  4. Skip keys that are pending deletion.

Fix: infrabaseline SOC 2 Kit → modules/kms
     var.enable_key_rotation = true
"""

import boto3
from botocore.exceptions import ClientError, NoCredentialsError

from infrabaseline_audit.models import CheckResult, Framework, Status
from infrabaseline_audit.fixes.registry import FIXES

CHECK_ID   = "soc2-cc6-8-kms"
CONTROL_ID = "CC6.8"
TITLE      = "KMS encryption + key rotation"
FRAMEWORK  = Framework.SOC2


def run(session: boto3.Session) -> CheckResult:
    try:
        kms = session.client("kms")
        paginator = kms.get_paginator("list_keys")

        no_rotation = []
        total_cmk = 0

        for page in paginator.paginate():
            for key in page["Keys"]:
                key_id = key["KeyId"]

                try:
                    metadata = kms.describe_key(KeyId=key_id)["KeyMetadata"]
                except ClientError:
                    continue

                # Skip AWS-managed keys and keys pending deletion
                if metadata.get("KeyManager") != "CUSTOMER":
                    continue
                if metadata.get("KeyState") in ("PendingDeletion", "Disabled"):
                    continue
                # Skip asymmetric keys — rotation not supported
                if metadata.get("KeySpec", "SYMMETRIC_DEFAULT") != "SYMMETRIC_DEFAULT":
                    continue

                total_cmk += 1
                rotation = kms.get_key_rotation_status(KeyId=key_id)

                if not rotation.get("KeyRotationEnabled"):
                    alias_resp = kms.list_aliases(KeyId=key_id)
                    aliases = [a["AliasName"] for a in alias_resp.get("Aliases", [])]
                    label = aliases[0] if aliases else key_id
                    no_rotation.append(label)

        if total_cmk == 0:
            return CheckResult(
                check_id=CHECK_ID,
                control_id=CONTROL_ID,
                title=TITLE,
                framework=FRAMEWORK,
                status=Status.WARNING,
                issue="No customer-managed KMS keys found. CMKs are required for SOC2 CC6.8.",
                fix=FIXES[CHECK_ID],
            )

        if no_rotation:
            detail = ", ".join(no_rotation[:5])
            if len(no_rotation) > 5:
                detail += f" ... and {len(no_rotation) - 5} more"
            return CheckResult(
                check_id=CHECK_ID,
                control_id=CONTROL_ID,
                title=TITLE,
                framework=FRAMEWORK,
                status=Status.FAILING,
                issue=f"{len(no_rotation)} CMK(s) do not have automatic rotation enabled.",
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
