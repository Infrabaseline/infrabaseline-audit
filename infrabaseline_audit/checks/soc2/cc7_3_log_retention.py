"""
SOC2 CC7.3 — CloudWatch Logs retention set to >= 365 days on trail log groups.

Check logic:
  1. List all CloudTrail trails to identify their CloudWatch log group names.
  2. For each log group, call describe_log_groups and check retentionInDays.
  3. retentionInDays must be >= 365 (or None = "Never Expire" which is compliant).
  4. Also check any log group with "cloudtrail" in the name as a catch-all.

Fix: infrabaseline SOC 2 Kit → modules/cloudtrail
     var.log_retention_days = 365
"""

import boto3
from botocore.exceptions import ClientError, NoCredentialsError

from infrabaseline_audit.models import CheckResult, Framework, Status
from infrabaseline_audit.fixes.registry import FIXES

CHECK_ID            = "soc2-cc7-3-log-retention"
CONTROL_ID          = "CC7.3"
TITLE               = "Log retention 365 days"
FRAMEWORK           = Framework.SOC2
MIN_RETENTION_DAYS  = 365


def run(session: boto3.Session) -> CheckResult:
    try:
        ct  = session.client("cloudtrail")
        cwl = session.client("logs")

        trails = ct.describe_trails(includeShadowTrails=False).get("trailList", [])
        log_group_names = set()

        for trail in trails:
            lg = trail.get("CloudWatchLogsLogGroupArn")
            if lg:
                # ARN format: arn:aws:logs:region:account:log-group:NAME:*
                parts = lg.split(":")
                if len(parts) >= 7:
                    log_group_names.add(parts[6])

        if not log_group_names:
            # Fallback: look for any log group with cloudtrail in name
            paginator = cwl.get_paginator("describe_log_groups")
            for page in paginator.paginate():
                for lg in page["logGroups"]:
                    if "cloudtrail" in lg["logGroupName"].lower():
                        log_group_names.add(lg["logGroupName"])

        if not log_group_names:
            return CheckResult(
                check_id=CHECK_ID,
                control_id=CONTROL_ID,
                title=TITLE,
                framework=FRAMEWORK,
                status=Status.FAILING,
                issue="No CloudTrail log groups found in CloudWatch Logs.",
                fix=FIXES[CHECK_ID],
            )

        insufficient = []

        for lg_name in log_group_names:
            try:
                resp = cwl.describe_log_groups(logGroupNamePrefix=lg_name)
                groups = resp.get("logGroups", [])
                matched = [g for g in groups if g["logGroupName"] == lg_name]

                if not matched:
                    insufficient.append(f"{lg_name} (log group not found)")
                    continue

                retention = matched[0].get("retentionInDays")
                # None means "Never Expire" — compliant
                if retention is not None and retention < MIN_RETENTION_DAYS:
                    insufficient.append(f"{lg_name} (retention: {retention}d, required: {MIN_RETENTION_DAYS}d)")

            except ClientError:
                insufficient.append(f"{lg_name} (could not check retention)")

        if insufficient:
            return CheckResult(
                check_id=CHECK_ID,
                control_id=CONTROL_ID,
                title=TITLE,
                framework=FRAMEWORK,
                status=Status.FAILING,
                issue=f"{len(insufficient)} log group(s) have insufficient retention.",
                detail=", ".join(insufficient),
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
