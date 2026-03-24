"""
runner.py — Orchestrates all 20 checks concurrently using ThreadPoolExecutor.

Each check is IO-bound (boto3 API calls), so threading gives real speedup.
The runner returns results in a deterministic order regardless of completion order.
"""

import boto3
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List

from infrabaseline_audit.models import CheckResult, Framework

# ── HIPAA checks ──────────────────────────────────────────────────────────────
from infrabaseline_audit.checks.hipaa import (
    kms_rds,
    s3_public_access,
    cloudtrail_enabled,
    cloudtrail_delivery,
    guardduty,
    iam_no_wildcards,
    mfa_enforced,
    vpc_flow_logs,
    secrets_rotation,
    aurora_encryption,
)

# ── SOC2 checks ───────────────────────────────────────────────────────────────
from infrabaseline_audit.checks.soc2 import (
    cc6_1_least_privilege,
    cc6_7_s3_public,
    cc7_2_guardduty,
    cc6_3_mfa,
    cc7_1_cloudtrail,
    cc6_6_vpc,
    cc9_1_backup,
    cc6_8_kms,
    cc7_3_log_retention,
    cc6_2_passrole,
)

# Ordered list of (module, display_order) — order determines terminal output order
HIPAA_CHECKS = [
    kms_rds,
    s3_public_access,
    cloudtrail_enabled,
    cloudtrail_delivery,
    guardduty,
    iam_no_wildcards,
    mfa_enforced,
    vpc_flow_logs,
    secrets_rotation,
    aurora_encryption,
]

SOC2_CHECKS = [
    cc6_1_least_privilege,
    cc6_7_s3_public,
    cc7_2_guardduty,
    cc6_3_mfa,
    cc7_1_cloudtrail,
    cc6_6_vpc,
    cc9_1_backup,
    cc6_8_kms,
    cc7_3_log_retention,
    cc6_2_passrole,
]

ALL_CHECKS = HIPAA_CHECKS + SOC2_CHECKS
MAX_WORKERS = 10  # boto3 is thread-safe; 10 concurrent calls is safe and fast


def run_all(
    session: boto3.Session,
    framework: str = "all",
    max_workers: int = MAX_WORKERS,
) -> List[CheckResult]:
    """
    Run all checks (or a filtered subset) and return results in display order.

    Args:
        session:     A configured boto3 Session.
        framework:   "hipaa", "soc2", or "all" (default).
        max_workers: Thread pool size.

    Returns:
        List[CheckResult] in the same order as HIPAA_CHECKS + SOC2_CHECKS.
    """
    if framework == "hipaa":
        checks = HIPAA_CHECKS
    elif framework == "soc2":
        checks = SOC2_CHECKS
    else:
        checks = ALL_CHECKS

    # Map index → result so we can re-sort after concurrent completion
    results: dict[int, CheckResult] = {}

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_index = {
            executor.submit(check.run, session): i
            for i, check in enumerate(checks)
        }

        for future in as_completed(future_to_index):
            index = future_to_index[future]
            try:
                results[index] = future.result()
            except Exception as exc:
                # Defensive: a check raised an unhandled exception
                # Build an ERROR result so the runner never crashes
                check_module = checks[index]
                results[index] = CheckResult(
                    check_id=getattr(check_module, "CHECK_ID", f"unknown-{index}"),
                    control_id=getattr(check_module, "CONTROL_ID", "UNKNOWN"),
                    title=getattr(check_module, "TITLE", "Unknown check"),
                    framework=getattr(check_module, "FRAMEWORK", Framework.HIPAA),
                    status=__import__(
                        "infrabaseline_audit.models", fromlist=["Status"]
                    ).Status.ERROR,
                    error_msg=f"Unhandled exception: {exc}",
                )

    # Return in original display order
    return [results[i] for i in range(len(checks))]
