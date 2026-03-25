infrabaseline-audit
HIPAA & SOC2 compliance scanner for AWS.
Scan your account in under 60 seconds. Every failure maps directly to the Terraform module that fixes it.
❌ HIPAA 164.312(b) — CloudTrail enabled + multi-region
   Status: FAILING
   Issue:  Single-region trails only: my-trail
   Fix: infrabaseline HIPAA Kit → modules/cloudtrail
        var.enable_multi_region_trail = true
        Creates a multi-region CloudTrail trail with log file validation.

✅ SOC2 CC6.7 — S3 public access blocked
   Status: PASSING

Install
bashpip install infrabaseline-audit
Requires Python 3.11+ and AWS credentials configured locally.

Usage
bash# Audit everything (HIPAA + SOC2)
infrabaseline-audit

# HIPAA only
infrabaseline-audit --framework hipaa

# SOC2 only
infrabaseline-audit --framework soc2

# Use a named AWS profile
infrabaseline-audit --profile staging

# Override region
infrabaseline-audit --region us-west-2

# Plain text (no ANSI colour)
infrabaseline-audit --no-color

# Version
infrabaseline-audit --version

What it checks
HIPAA (10 controls)
ControlCheck164.312(a)(2)(iv)KMS encryption on RDS164.312(c)(1)S3 public access blocked164.312(b)CloudTrail enabled + multi-region164.312(b)CloudTrail log delivery working164.312(b)GuardDuty enabled164.312(a)(1)IAM no wildcards164.312(d)MFA enforced164.312(b)VPC flow logs enabled164.312(a)(2)(i)Secrets rotation configured164.312(a)(2)(iv)Aurora encryption at rest
SOC 2 (10 controls)
ControlCheckCC6.1IAM least privilegeCC6.7S3 public access blockedCC7.2GuardDuty enabledCC6.3MFA enforcedCC7.1CloudTrail loggingCC6.6VPC network controlsCC9.1Backup retention (35 days)CC6.8KMS key rotationCC7.3Log retention (365 days)CC6.2PassRole scoping

Prerequisites

AWS credentials configured (aws configure or AWS_PROFILE set)
IAM permissions: ReadOnly access across CloudTrail, GuardDuty, IAM, KMS, RDS, S3, EC2, SecretsManager, CloudWatch Logs


Fix everything with Infrabaseline
Each failing control maps directly to a production-tested Terraform module:

HIPAA Kit — $397 — 10 HIPAA controls, 76 resources, tested in us-east-1
SOC 2 Kit — $497 — 10 SOC2 controls, 49 files across 7 modules
Bundle — $697 — Both kits

→ infrabaseline.com

Development
bashgit clone https://github.com/Infrabaseline/infrabaseline-audit
cd infrabaseline-audit
pip install -e ".[dev]"

# Run tests
pytest

# Lint
ruff check .

License
MIT © Infrabaseline
