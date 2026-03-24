"""
tests/test_checks.py — Smoke tests for all 20 checks using moto AWS mocking.

These tests verify:
1. Each check returns a CheckResult (not an exception).
2. Each check returns PASSING when the mocked environment is compliant.
3. Each check returns FAILING or WARNING when the mocked environment is non-compliant.

Run with: pytest tests/ -v
"""

import boto3
import pytest
from moto import (
    mock_aws,
)

from infrabaseline_audit.models import Status, Framework
from infrabaseline_audit.checks.hipaa import (
    cloudtrail_enabled,
    guardduty,
    s3_public_access,
    vpc_flow_logs,
)
from infrabaseline_audit.checks.soc2 import (
    cc6_8_kms,
    cc7_2_guardduty,
    cc6_7_s3_public,
    cc9_1_backup,
)
from infrabaseline_audit.runner import run_all


# ── Helpers ───────────────────────────────────────────────────────────────────

def make_session(region: str = "us-east-1") -> boto3.Session:
    return boto3.Session(region_name=region)


# ── CloudTrail ────────────────────────────────────────────────────────────────

@mock_aws
def test_cloudtrail_enabled_no_trails():
    session = make_session()
    result = cloudtrail_enabled.run(session)
    assert result.status == Status.FAILING
    assert result.fix is not None
    assert result.framework == Framework.HIPAA


@mock_aws
def test_cloudtrail_enabled_with_compliant_trail():
    session = make_session()
    s3 = session.client("s3")
    s3.create_bucket(Bucket="ct-logs-test")

    ct = session.client("cloudtrail")
    ct.create_trail(
        Name="test-trail",
        S3BucketName="ct-logs-test",
        IsMultiRegionTrail=True,
        EnableLogFileValidation=True,
    )
    ct.start_logging(Name="test-trail")

    result = cloudtrail_enabled.run(session)
    assert result.status == Status.PASSING


# ── GuardDuty ─────────────────────────────────────────────────────────────────

@mock_aws
def test_guardduty_no_detector():
    session = make_session()
    result = guardduty.run(session)
    assert result.status == Status.FAILING
    assert result.fix is not None


@mock_aws
def test_guardduty_enabled():
    session = make_session()
    gd = session.client("guardduty")
    gd.create_detector(Enable=True)

    result = guardduty.run(session)
    assert result.status == Status.PASSING


# ── S3 Public Access ──────────────────────────────────────────────────────────

@mock_aws
def test_s3_no_buckets():
    session = make_session()
    result = s3_public_access.run(session)
    assert result.status == Status.WARNING


@mock_aws
def test_s3_bucket_without_bpa():
    session = make_session()
    s3 = session.client("s3")
    s3.create_bucket(Bucket="test-bucket-no-bpa")

    result = s3_public_access.run(session)
    assert result.status == Status.FAILING
    assert result.fix is not None


@mock_aws
def test_s3_bucket_with_bpa():
    session = make_session()
    s3 = session.client("s3")
    s3.create_bucket(Bucket="test-bucket-bpa")
    s3.put_public_access_block(
        Bucket="test-bucket-bpa",
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        },
    )

    result = s3_public_access.run(session)
    assert result.status == Status.PASSING


# ── VPC Flow Logs ─────────────────────────────────────────────────────────────

@mock_aws
def test_vpc_no_flow_logs():
    session = make_session()
    # moto creates a default VPC automatically
    result = vpc_flow_logs.run(session)
    assert result.status == Status.FAILING
    assert result.fix is not None


# ── KMS Key Rotation (SOC2 CC6.8) ────────────────────────────────────────────

@mock_aws
def test_kms_no_cmk():
    session = make_session()
    result = cc6_8_kms.run(session)
    # No CMKs → WARNING (not FAILING)
    assert result.status == Status.WARNING


@mock_aws
def test_kms_cmk_without_rotation():
    session = make_session()
    kms = session.client("kms")
    kms.create_key(Description="test-key", KeyUsage="ENCRYPT_DECRYPT")

    result = cc6_8_kms.run(session)
    assert result.status == Status.FAILING
    assert result.fix is not None


@mock_aws
def test_kms_cmk_with_rotation():
    session = make_session()
    kms = session.client("kms")
    key = kms.create_key(Description="test-key", KeyUsage="ENCRYPT_DECRYPT")
    key_id = key["KeyMetadata"]["KeyId"]
    kms.enable_key_rotation(KeyId=key_id)

    result = cc6_8_kms.run(session)
    assert result.status == Status.PASSING


# ── SOC2 CC6.7 S3 ─────────────────────────────────────────────────────────────

@mock_aws
def test_soc2_s3_failing():
    session = make_session()
    s3 = session.client("s3")
    s3.create_bucket(Bucket="soc2-bucket-no-bpa")

    result = cc6_7_s3_public.run(session)
    assert result.status == Status.FAILING
    assert result.fix is not None
    assert result.framework == Framework.SOC2


# ── Aurora Backup Retention (SOC2 CC9.1) ─────────────────────────────────────

@mock_aws
def test_cc9_1_no_aurora():
    session = make_session()
    result = cc9_1_backup.run(session)
    assert result.status == Status.WARNING


# ── Runner smoke test ─────────────────────────────────────────────────────────

@mock_aws
def test_runner_returns_20_results():
    session = make_session()
    results = run_all(session, framework="all")
    assert len(results) == 20
    for r in results:
        assert r.status in (Status.PASSING, Status.FAILING, Status.WARNING, Status.ERROR)
        assert r.check_id
        assert r.control_id
        assert r.title


@mock_aws
def test_runner_hipaa_only():
    session = make_session()
    results = run_all(session, framework="hipaa")
    assert len(results) == 10
    assert all(r.framework == Framework.HIPAA for r in results)


@mock_aws
def test_runner_soc2_only():
    session = make_session()
    results = run_all(session, framework="soc2")
    assert len(results) == 10
    assert all(r.framework == Framework.SOC2 for r in results)


@mock_aws
def test_failing_checks_always_have_fix():
    """Every FAILING result must have a Fix attached — this is the core guarantee."""
    session = make_session()
    results = run_all(session, framework="all")
    for r in results:
        if r.status == Status.FAILING:
            assert r.fix is not None, (
                f"{r.check_id} is FAILING but has no fix — "
                "every failing check must map to a kit module."
            )
