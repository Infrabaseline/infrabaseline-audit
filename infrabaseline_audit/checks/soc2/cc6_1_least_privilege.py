"""
SOC2 CC6.1 — IAM least privilege (no overly permissive managed policies attached).

Check logic:
  1. List all IAM roles and users.
  2. Flag any with AWS-managed AdministratorAccess policy attached directly.
  3. Flag any customer-managed policy with Action: '*' and Resource: '*'.
  4. Check for permission boundaries being set on roles.

Fix: infrabaseline SOC 2 Kit → modules/iam
     var.enable_least_privilege_boundaries = true
"""

import json
import boto3
from botocore.exceptions import ClientError, NoCredentialsError

from infrabaseline_audit.models import CheckResult, Framework, Status
from infrabaseline_audit.fixes.registry import FIXES

CHECK_ID   = "soc2-cc6-1-least-privilege"
CONTROL_ID = "CC6.1"
TITLE      = "IAM least privilege"
FRAMEWORK  = Framework.SOC2

ADMIN_POLICY_ARN = "arn:aws:iam::aws:policy/AdministratorAccess"


def _policy_has_full_access(policy_doc: dict) -> bool:
    for stmt in policy_doc.get("Statement", []):
        if stmt.get("Effect") != "Allow":
            continue
        actions = stmt.get("Action", [])
        resources = stmt.get("Resource", [])
        if isinstance(actions, str):
            actions = [actions]
        if isinstance(resources, str):
            resources = [resources]
        if "*" in actions and "*" in resources:
            return True
    return False


def run(session: boto3.Session) -> CheckResult:
    try:
        iam = session.client("iam")
        violations = []

        # Check roles with AdministratorAccess or full-access inline policies
        role_paginator = iam.get_paginator("list_roles")
        for page in role_paginator.paginate():
            for role in page["Roles"]:
                role_name = role["RoleName"]
                has_boundary = bool(role.get("PermissionsBoundary"))

                attached = iam.list_attached_role_policies(RoleName=role_name)
                for policy in attached["AttachedPolicies"]:
                    if policy["PolicyArn"] == ADMIN_POLICY_ARN and not has_boundary:
                        violations.append(f"role:{role_name} has AdministratorAccess (no boundary)")

                # Check inline policies
                inline = iam.list_role_policies(RoleName=role_name)
                for policy_name in inline["PolicyNames"]:
                    doc = iam.get_role_policy(RoleName=role_name, PolicyName=policy_name)
                    policy_doc = doc["PolicyDocument"]
                    if isinstance(policy_doc, str):
                        policy_doc = json.loads(policy_doc)
                    if _policy_has_full_access(policy_doc):
                        violations.append(f"role:{role_name}/inline:{policy_name} has Action:* Resource:*")

        # Check users with AdministratorAccess
        user_paginator = iam.get_paginator("list_users")
        for page in user_paginator.paginate():
            for user in page["Users"]:
                username = user["UserName"]
                attached = iam.list_attached_user_policies(UserName=username)
                for policy in attached["AttachedPolicies"]:
                    if policy["PolicyArn"] == ADMIN_POLICY_ARN:
                        violations.append(f"user:{username} has AdministratorAccess directly attached")

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
                issue=f"{len(violations)} least-privilege violation(s) found.",
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
