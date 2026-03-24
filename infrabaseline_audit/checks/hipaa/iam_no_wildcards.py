"""
HIPAA 164.312(a)(1) — IAM policies must not use wildcard actions (Action: '*').

Check logic:
  1. List all customer-managed IAM policies (Scope=Local).
  2. For each policy, get the default version document.
  3. Flag any statement where Action is '*' or contains '*' as a standalone entry.
  4. Also check inline policies on users, groups, and roles.

Fix: infrabaseline HIPAA Kit → modules/iam
     var.deny_wildcard_actions = true
"""

import json
import boto3
from botocore.exceptions import ClientError, NoCredentialsError

from infrabaseline_audit.models import CheckResult, Framework, Status
from infrabaseline_audit.fixes.registry import FIXES

CHECK_ID   = "hipaa-iam-no-wildcards"
CONTROL_ID = "164.312(a)(1)"
TITLE      = "IAM no wildcards"
FRAMEWORK  = Framework.HIPAA


def _has_wildcard_action(policy_doc: dict) -> bool:
    for stmt in policy_doc.get("Statement", []):
        if stmt.get("Effect") != "Allow":
            continue
        actions = stmt.get("Action", [])
        if isinstance(actions, str):
            actions = [actions]
        if "*" in actions:
            return True
    return False


def run(session: boto3.Session) -> CheckResult:
    try:
        iam = session.client("iam")
        violating = []

        # Check customer-managed policies
        paginator = iam.get_paginator("list_policies")
        for page in paginator.paginate(Scope="Local"):
            for policy in page["Policies"]:
                arn = policy["Arn"]
                version_id = policy["DefaultVersionId"]
                doc = iam.get_policy_version(PolicyArn=arn, VersionId=version_id)
                policy_doc = doc["PolicyVersion"]["Document"]
                if isinstance(policy_doc, str):
                    policy_doc = json.loads(policy_doc)
                if _has_wildcard_action(policy_doc):
                    violating.append(f"policy:{policy['PolicyName']}")

        # Check inline policies on roles (most common violation source)
        role_paginator = iam.get_paginator("list_roles")
        for page in role_paginator.paginate():
            for role in page["Roles"]:
                role_name = role["RoleName"]
                inline_resp = iam.list_role_policies(RoleName=role_name)
                for policy_name in inline_resp["PolicyNames"]:
                    doc = iam.get_role_policy(RoleName=role_name, PolicyName=policy_name)
                    policy_doc = doc["PolicyDocument"]
                    if isinstance(policy_doc, str):
                        policy_doc = json.loads(policy_doc)
                    if _has_wildcard_action(policy_doc):
                        violating.append(f"role:{role_name}/inline:{policy_name}")

        if violating:
            detail = ", ".join(violating[:5])
            if len(violating) > 5:
                detail += f" ... and {len(violating) - 5} more"
            return CheckResult(
                check_id=CHECK_ID,
                control_id=CONTROL_ID,
                title=TITLE,
                framework=FRAMEWORK,
                status=Status.FAILING,
                issue=f"{len(violating)} policy/policies with wildcard Action: '*' found.",
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
