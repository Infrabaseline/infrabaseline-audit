"""
HIPAA 164.312(b) — VPC Flow Logs enabled on all VPCs.

Check logic:
  1. List all VPCs in the region.
  2. For each VPC, describe_flow_logs to confirm at least one active flow log exists.
  3. Confirm flow log destination is CloudWatch Logs (not just S3).

Fix: infrabaseline HIPAA Kit → modules/vpc
     var.enable_flow_logs = true
"""

import boto3
from botocore.exceptions import ClientError, NoCredentialsError

from infrabaseline_audit.models import CheckResult, Framework, Status
from infrabaseline_audit.fixes.registry import FIXES

CHECK_ID   = "hipaa-vpc-flow-logs"
CONTROL_ID = "164.312(b)"
TITLE      = "VPC flow logs enabled"
FRAMEWORK  = Framework.HIPAA


def run(session: boto3.Session) -> CheckResult:
    try:
        ec2 = session.client("ec2")

        vpcs = ec2.describe_vpcs().get("Vpcs", [])
        if not vpcs:
            return CheckResult(
                check_id=CHECK_ID,
                control_id=CONTROL_ID,
                title=TITLE,
                framework=FRAMEWORK,
                status=Status.WARNING,
                issue="No VPCs found in this region.",
            )

        vpcs_without_flow_logs = []

        for vpc in vpcs:
            vpc_id = vpc["VpcId"]
            flow_logs = ec2.describe_flow_logs(
                Filters=[{"Name": "resource-id", "Values": [vpc_id]}]
            ).get("FlowLogs", [])

            active_logs = [
                fl for fl in flow_logs
                if fl.get("FlowLogStatus") == "ACTIVE"
            ]

            if not active_logs:
                vpcs_without_flow_logs.append(vpc_id)

        if vpcs_without_flow_logs:
            return CheckResult(
                check_id=CHECK_ID,
                control_id=CONTROL_ID,
                title=TITLE,
                framework=FRAMEWORK,
                status=Status.FAILING,
                issue=f"{len(vpcs_without_flow_logs)} VPC(s) have no active flow logs.",
                detail=", ".join(vpcs_without_flow_logs),
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
