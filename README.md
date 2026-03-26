# infrabaseline-audit

**HIPAA & SOC2 compliance scanner for AWS.**  
Scan your account in under 60 seconds. Every failure maps directly to the Terraform module that fixes it.

```
❌ HIPAA 164.312(b) — CloudTrail enabled + multi-region
   Status: FAILING
   Issue:  Single-region trails only: my-trail
   Fix: infrabaseline HIPAA Kit → modules/cloudtrail
        var.enable_multi_region_trail = true
        Creates a multi-region CloudTrail trail with log file validation.

✅ SOC2 CC6.7 — S3 public access blocked
   Status: PASSING
```

---

## Install

**Option 1 — pipx (recommended for Mac/Linux, installs as a global CLI tool)**
```bash
brew install pipx
pipx install infrabaseline-audit
```

**Option 2 — pip inside a virtual environment**
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install infrabaseline-audit
```

**Option 3 — pip direct (if you manage your own Python environment)**
```bash
pip install infrabaseline-audit
```

Requires Python 3.11+ and AWS credentials configured locally (`aws configure` or `AWS_PROFILE` set).

---

## Usage

```bash
# Audit everything (HIPAA + SOC2)
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
```

---

## What it checks

### HIPAA (10 controls)

| Control | Check |
|---|---|
| 164.312(a)(2)(iv) | KMS encryption on RDS |
| 164.312(c)(1) | S3 public access blocked |
| 164.312(b) | CloudTrail enabled + multi-region |
| 164.312(b) | CloudTrail log delivery working |
| 164.312(b) | GuardDuty enabled |
| 164.312(a)(1) | IAM no wildcards |
| 164.312(d) | MFA enforced |
| 164.312(b) | VPC flow logs enabled |
| 164.312(a)(2)(i) | Secrets rotation configured |
| 164.312(a)(2)(iv) | Aurora encryption at rest |

### SOC 2 (10 controls)

| Control | Check |
|---|---|
| CC6.1 | IAM least privilege |
| CC6.7 | S3 public access blocked |
| CC7.2 | GuardDuty enabled |
| CC6.3 | MFA enforced |
| CC7.1 | CloudTrail logging |
| CC6.6 | VPC network controls |
| CC9.1 | Backup retention (35 days) |
| CC6.8 | KMS key rotation |
| CC7.3 | Log retention (365 days) |
| CC6.2 | PassRole scoping |

---

## Prerequisites

- AWS credentials configured (`aws configure` or `AWS_PROFILE` set)
- IAM permissions: ReadOnly access across CloudTrail, GuardDuty, IAM, KMS, RDS, S3, EC2, SecretsManager, CloudWatch Logs

---

## Fix everything with Infrabaseline

Each failing control maps directly to a production-tested Terraform module:

- **[HIPAA Kit — $397](https://infrabaseline.gumroad.com/l/hipaa-terraform-kit)** — 10 HIPAA controls, 76 resources, tested in us-east-1
- **[SOC 2 Kit — $497](https://infrabaseline.gumroad.com/l/soc2-terraform-kit)** — 10 SOC2 controls, 49 files across 7 modules
- **[Bundle — $697](https://infrabaseline.gumroad.com/l/hipaa-soc2-bundle-kit)** — Both kits

→ [infrabaseline.com](https://infrabaseline.com)

---

## Development

```bash
git clone https://github.com/Infrabaseline/infrabaseline-audit
cd infrabaseline-audit
pip install -e ".[dev]"

# Run tests
pytest

# Lint
ruff check .
```

---

## License

MIT © [Infrabaseline](https://infrabaseline.com)
