"""
SOC2 CC6.2 — iam:PassRole scoped to approved services only.

Check logic:
  1. List all customer-managed IAM policies and inline role policies.
  2. Flag any statement that grants iam:PassRole with Resource: '*'
     and no Condition key restricting iam:PassedToService.
  3. An unrestricted PassRole is a privilege escalation risk.

Fix: infrabaseline SOC 2 Kit → modules/iam
     var.scope_pass_role = true
"""

import json
import boto3
from botocore.exceptions import ClientError, NoCredentialsError

from infrabaseline_audit.models import CheckResult, Framework, Status
from infrabaseline_audit.fixes.registry import FIXES

CHECK_ID   = "soc2-cc6-2-passrole"
CONTROL_ID = "CC6.2"
TITLE      = "PassRole scoping"
FRAMEWORK  = Framework.SOC2


def _has_unrestricted_passrole(policy_doc: dict) -> bool:
    """
    Returns True if any Allow statement grants iam:PassRole on Resource: '*'
    without a iam:PassedToService condition.
    """
    for stmt in policy_doc.get("Statement", []):
        if stmt.get("Effect") != "Allow":
            continue

        actions = stmt.get("Action", [])
        if isinstance(actions, str):
            actions = [actions]

        has_passrole = any(
            a in ("iam:PassRole", "iam:*", "*") for a in actions
        )
        if not has_passrole:
            continue

        resources = stmt.get("Resource", [])
        if isinstance(resources, str):
            resources = [resources]
        if "*" not in resources:
            continue

        # Check for PassedToService condition
        conditions = stmt.get("Condition", {})
        string_equals = conditions.get("StringEquals", {})
        string_like   = conditions.get("StringLike", {})

        has_service_condition = (
            "iam:PassedToService" in string_equals
            or "iam:PassedToService" in string_like
        )

        if not has_service_condition:
            return True

    return False


def run(session: boto3.Session) -> CheckResult:
    try:
        iam = session.client("iam")
        violations = []

        # Check customer-managed policies
        paginator = iam.get_paginator("list_policies")
        for page in paginator.paginate(Scope="Local"):
            for policy in page["Policies"]:
                arn        = policy["Arn"]
                version_id = policy["DefaultVersionId"]
                doc = iam.get_policy_version(PolicyArn=arn, VersionId=version_id)
                policy_doc = doc["PolicyVersion"]["Document"]
                if isinstance(policy_doc, str):
                    policy_doc = json.loads(policy_doc)
                if _has_unrestricted_passrole(policy_doc):
                    violations.append(f"managed-policy:{policy['PolicyName']}")

        # Check inline role policies
        role_paginator = iam.get_paginator("list_roles")
        for page in role_paginator.paginate():
            for role in page["Roles"]:
                role_name = role["RoleName"]
                inline = iam.list_role_policies(RoleName=role_name)
                for policy_name in inline["PolicyNames"]:
                    doc = iam.get_role_policy(RoleName=role_name, PolicyName=policy_name)
                    policy_doc = doc["PolicyDocument"]
                    if isinstance(policy_doc, str):
                        policy_doc = json.loads(policy_doc)
                    if _has_unrestricted_passrole(policy_doc):
                        violations.append(f"role:{role_name}/inline:{policy_name}")

        if violations:
            detail = ", ".join(violations[:5])
            if len(violations) > 5:
                detail += f" ... and {len(violations) - 5} more"
            return CheckResult(
                check_id=CHECK_ID,
                control_id=CONTROL_ID,
                title=TITLE,
                framework=FRAMEWORK,
                status=Status.FAILING,
                issue=f"{len(violations)} policy/policies grant unrestricted iam:PassRole.",
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
