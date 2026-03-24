"""
SOC2 CC6.6 — VPC network controls: flow logs enabled, default SG restricted.

Check logic:
  1. List all VPCs.
  2. Confirm VPC flow logs are active for each VPC.
  3. Confirm the default security group has no inbound or outbound rules
     (AWS best practice: default SG should be empty).

Fix: infrabaseline SOC 2 Kit → modules/vpc
     var.enable_flow_logs = true
"""

import boto3
from botocore.exceptions import ClientError, NoCredentialsError

from infrabaseline_audit.models import CheckResult, Framework, Status
from infrabaseline_audit.fixes.registry import FIXES

CHECK_ID   = "soc2-cc6-6-vpc"
CONTROL_ID = "CC6.6"
TITLE      = "VPC network controls"
FRAMEWORK  = Framework.SOC2


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

        issues = []

        for vpc in vpcs:
            vpc_id = vpc["VpcId"]

            # Check flow logs
            flow_logs = ec2.describe_flow_logs(
                Filters=[{"Name": "resource-id", "Values": [vpc_id]}]
            ).get("FlowLogs", [])

            active = [fl for fl in flow_logs if fl.get("FlowLogStatus") == "ACTIVE"]
            if not active:
                issues.append(f"{vpc_id}: no active flow logs")

            # Check default security group
            sgs = ec2.describe_security_groups(
                Filters=[
                    {"Name": "vpc-id", "Values": [vpc_id]},
                    {"Name": "group-name", "Values": ["default"]},
                ]
            ).get("SecurityGroups", [])

            for sg in sgs:
                if sg.get("IpPermissions") or sg.get("IpPermissionsEgress"):
                    issues.append(f"{vpc_id}: default SG has open rules (sg-id: {sg['GroupId']})")

        if issues:
            detail = " | ".join(issues[:4])
            if len(issues) > 4:
                detail += f" ... and {len(issues) - 4} more"
            return CheckResult(
                check_id=CHECK_ID,
                control_id=CONTROL_ID,
                title=TITLE,
                framework=FRAMEWORK,
                status=Status.FAILING,
                issue=f"{len(issues)} VPC network control issue(s) found.",
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
