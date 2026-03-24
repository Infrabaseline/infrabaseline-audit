"""
Core data models for infrabaseline-audit.
Every check returns a CheckResult. No exceptions.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class Status(Enum):
    PASSING = "PASSING"
    FAILING = "FAILING"
    WARNING = "WARNING"   # check ran but result is ambiguous (e.g. no resources found)
    ERROR   = "ERROR"     # check could not run (permissions, boto3 error)


class Framework(Enum):
    HIPAA = "HIPAA"
    SOC2  = "SOC2"


@dataclass
class Fix:
    """
    Maps a failing control directly to the Infrabaseline module and
    variable that remediates it.
    """
    kit: str            # e.g. "HIPAA Kit" or "SOC 2 Kit"
    module: str         # e.g. "modules/cloudtrail"
    variable: str       # e.g. "var.enable_log_delivery"
    value: str          # e.g. "true"
    description: str    # one-line human explanation

    def render(self) -> str:
        return (
            f"  Fix: infrabaseline {self.kit} → {self.module}\n"
            f"       {self.variable} = {self.value}\n"
            f"       {self.description}"
        )


@dataclass
class CheckResult:
    """
    Returned by every check function.
    check_id    : unique slug, e.g. "hipaa-cloudtrail-enabled"
    control_id  : framework control ref, e.g. "164.312(b)" or "CC7.1"
    title       : short human label shown in terminal output
    framework   : HIPAA or SOC2
    status      : PASSING | FAILING | WARNING | ERROR
    issue       : non-None when status is FAILING or WARNING — explains what's wrong
    fix         : non-None when status is FAILING — points to the kit module
    detail      : optional extra context (resource ARNs, counts, etc.)
    error_msg   : populated when status is ERROR
    """
    check_id:   str
    control_id: str
    title:      str
    framework:  Framework
    status:     Status
    issue:      Optional[str]       = None
    fix:        Optional[Fix]       = None
    detail:     Optional[str]       = None
    error_msg:  Optional[str]       = None

    def is_failing(self) -> bool:
        return self.status in (Status.FAILING, Status.WARNING)

    def render(self) -> str:
        icon = {
            Status.PASSING: "✅",
            Status.FAILING: "❌",
            Status.WARNING: "⚠️ ",
            Status.ERROR:   "🔴",
        }[self.status]

        fw   = self.framework.value
        line = f"{icon} {fw} {self.control_id} — {self.title}"
        out  = [line, f"   Status: {self.status.value}"]

        if self.issue:
            out.append(f"   Issue:  {self.issue}")
        if self.detail:
            out.append(f"   Detail: {self.detail}")
        if self.fix:
            out.append(self.fix.render())
        if self.error_msg:
            out.append(f"   Error:  {self.error_msg}")

        return "\n".join(out)
