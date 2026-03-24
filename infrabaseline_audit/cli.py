"""
cli.py — Entry point for infrabaseline-audit.

Usage:
    infrabaseline-audit                        # run all 20 checks
    infrabaseline-audit --framework hipaa      # HIPAA only
    infrabaseline-audit --framework soc2       # SOC2 only
    infrabaseline-audit --profile my-profile   # use a named AWS profile
    infrabaseline-audit --region us-west-2     # override region
    infrabaseline-audit --no-color             # plain text output
"""

import argparse
import sys
import time

try:
    import pyfiglet
    HAS_FIGLET = True
except ImportError:
    HAS_FIGLET = False

import boto3
from botocore.exceptions import NoCredentialsError, ProfileNotFound

from infrabaseline_audit import __version__
from infrabaseline_audit.models import Status
from infrabaseline_audit.runner import run_all

# ANSI colours
GREEN  = "\033[92m"
RED    = "\033[91m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
DIM    = "\033[2m"
RESET  = "\033[0m"


def _c(text: str, colour: str, use_colour: bool) -> str:
    return f"{colour}{text}{RESET}" if use_colour else text


def print_banner(use_colour: bool) -> None:
    if HAS_FIGLET:
        banner = pyfiglet.figlet_format("INFRABASELINE", font="slant")
    else:
        banner = "INFRABASELINE AUDIT\n"
    print(_c(banner, CYAN, use_colour))
    print(_c(f"  Engineering proof > paper compliance   v{__version__}", DIM, use_colour))
    print(_c("  infrabaseline.com\n", DIM, use_colour))


def print_header(title: str, use_colour: bool) -> None:
    line = "-" * 60
    print(f"\n{_c(line, DIM, use_colour)}")
    print(f"  {_c(title, BOLD, use_colour)}")
    print(f"{_c(line, DIM, use_colour)}")


def render_result(result, use_colour: bool) -> None:
    icon_map = {
        Status.PASSING: (_c("✅", GREEN, use_colour), GREEN),
        Status.FAILING: (_c("❌", RED,   use_colour), RED),
        Status.WARNING: (_c("⚠️ ", YELLOW, use_colour), YELLOW),
        Status.ERROR:   (_c("🔴", RED,   use_colour), RED),
    }
    icon, colour = icon_map[result.status]

    fw   = result.framework.value
    line = f"{icon} {_c(fw, BOLD, use_colour)} {result.control_id} — {result.title}"
    print(line)
    print(f"   Status: {_c(result.status.value, colour, use_colour)}")

    if result.issue:
        print(f"   Issue:  {result.issue}")
    if result.detail:
        print(f"   Detail: {_c(result.detail, DIM, use_colour)}")
    if result.fix:
        kit_line  = f"   Fix: infrabaseline {result.fix.kit} → {result.fix.module}"
        var_line  = f"        {_c(result.fix.variable, CYAN, use_colour)} = {_c(result.fix.value, GREEN, use_colour)}"
        desc_line = f"        {_c(result.fix.description, DIM, use_colour)}"
        print(kit_line)
        print(var_line)
        print(desc_line)
    if result.error_msg:
        print(f"   Error:  {_c(result.error_msg, RED, use_colour)}")

    print()


def print_summary(results, elapsed: float, use_colour: bool) -> None:
    total    = len(results)
    passing  = sum(1 for r in results if r.status == Status.PASSING)
    failing  = sum(1 for r in results if r.status == Status.FAILING)
    warnings = sum(1 for r in results if r.status == Status.WARNING)
    errors   = sum(1 for r in results if r.status == Status.ERROR)

    line = "=" * 60
    print(_c(line, BOLD, use_colour))
    print(f"  {_c('AUDIT SUMMARY', BOLD, use_colour)}")
    print(_c(line, BOLD, use_colour))
    print(f"  Checks run:  {total}")
    print(f"  {_c('Passing', GREEN, use_colour)}:     {passing}")
    print(f"  {_c('Failing', RED, use_colour)}:     {failing}")
    if warnings:
        print(f"  {_c('Warnings', YELLOW, use_colour)}:    {warnings}")
    if errors:
        print(f"  {_c('Errors', RED, use_colour)}:      {errors}")
    print(f"  Time:        {elapsed:.1f}s")
    print(_c(line, BOLD, use_colour))

    if failing > 0:
        cta = (
            f"\n  {_c(f'{failing} control(s) failing.', RED, use_colour)} "
            f"Each failure above maps directly to the\n"
            f"  Infrabaseline module that fixes it.\n\n"
            f"  {_c('→ HIPAA Kit ($397):', BOLD, use_colour)} infrabaseline.gumroad.com/l/hipaa-kit\n"
            f"  {_c('→ SOC 2 Kit ($497):', BOLD, use_colour)} infrabaseline.gumroad.com/l/soc2-kit\n"
            f"  {_c('→ Bundle    ($697):', BOLD, use_colour)} infrabaseline.gumroad.com/l/hipaa-soc2-bundle\n"
        )
        print(cta)
    else:
        print(f"\n  {_c('All checks passing. ', GREEN, use_colour)}Nice work.\n")


def build_session(profile, region):
    kwargs = {}
    if profile:
        kwargs["profile_name"] = profile
    if region:
        kwargs["region_name"] = region
    return boto3.Session(**kwargs)


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="infrabaseline-audit",
        description="Scan your AWS account for HIPAA and SOC2 compliance gaps.",
    )
    parser.add_argument(
        "--framework",
        choices=["hipaa", "soc2", "all"],
        default="all",
        help="Which framework to audit (default: all)",
    )
    parser.add_argument(
        "--profile",
        default=None,
        help="AWS CLI profile name (default: current env credentials)",
    )
    parser.add_argument(
        "--region",
        default=None,
        help="AWS region to audit (default: profile/env default)",
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable ANSI colour output",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"infrabaseline-audit {__version__}",
    )

    args = parser.parse_args()
    use_colour = not args.no_color and sys.stdout.isatty()

    print_banner(use_colour)

    try:
        session = build_session(args.profile, args.region)
        sts = session.client("sts")
        identity = sts.get_caller_identity()
        account_id = identity["Account"]
        region = session.region_name or "us-east-1"
        print(f"  {_c('Account:', BOLD, use_colour)} {account_id}")
        print(f"  {_c('Region: ', BOLD, use_colour)} {region}")
        print(f"  {_c('Profile:', BOLD, use_colour)} {args.profile or 'default'}")
    except ProfileNotFound as e:
        print(_c(f"\n  AWS profile not found: {e}\n", RED, use_colour))
        sys.exit(1)
    except NoCredentialsError:
        print(_c(
            "\n  No AWS credentials found.\n"
            "  Run 'aws configure' or set AWS_PROFILE.\n",
            RED, use_colour,
        ))
        sys.exit(1)
    except Exception as e:
        print(_c(f"\n  Failed to connect to AWS: {e}\n", RED, use_colour))
        sys.exit(1)

    framework_label = args.framework.upper() if args.framework != "all" else "HIPAA + SOC2"
    print(f"\n  Running {framework_label} audit across 20 controls ...\n")

    start = time.time()
    results = run_all(session, framework=args.framework)
    elapsed = time.time() - start

    hipaa_results = [r for r in results if r.framework.value == "HIPAA"]
    soc2_results  = [r for r in results if r.framework.value == "SOC2"]

    if hipaa_results:
        print_header("HIPAA Controls", use_colour)
        for result in hipaa_results:
            render_result(result, use_colour)

    if soc2_results:
        print_header("SOC 2 Controls", use_colour)
        for result in soc2_results:
            render_result(result, use_colour)

    print_summary(results, elapsed, use_colour)


if __name__ == "__main__":
    main()
