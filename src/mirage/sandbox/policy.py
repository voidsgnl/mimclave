"""Declarative sandbox policy models and validation.

This module defines policy intent only. It does not create namespaces, cgroups,
seccomp filters, virtual machines, or network rules.
"""

from dataclasses import dataclass
from enum import StrEnum
import re


class SandboxTier(StrEnum):
    SIMULATION = "simulation"
    ISOLATED_WORKER = "isolated_worker"
    DISPOSABLE_VM = "disposable_vm"


class NetworkMode(StrEnum):
    DENY_ALL = "deny_all"
    ESTABLISHED_CLIENT_STREAM = "established_client_stream"


@dataclass(frozen=True, slots=True)
class SandboxLimits:
    """Hard upper bounds requested for one sandbox policy."""

    cpu_quota_percent: int = 100
    memory_bytes: int = 256 * 1024 * 1024
    process_count: int = 32
    open_file_limit: int = 128
    scratch_bytes: int = 64 * 1024 * 1024
    max_sessions: int = 1
    wall_time_seconds: int = 300

    def __post_init__(self) -> None:
        bounds = {
            "cpu_quota_percent": (self.cpu_quota_percent, 1, 1600),
            "memory_bytes": (self.memory_bytes, 16 * 1024 * 1024, 16 * 1024**3),
            "process_count": (self.process_count, 1, 1024),
            "open_file_limit": (self.open_file_limit, 8, 4096),
            "scratch_bytes": (self.scratch_bytes, 1024 * 1024, 16 * 1024**3),
            "max_sessions": (self.max_sessions, 1, 256),
            "wall_time_seconds": (self.wall_time_seconds, 1, 86400),
        }
        for name, (value, minimum, maximum) in bounds.items():
            if isinstance(value, bool) or not isinstance(value, int):
                raise ValueError(f"{name} must be an integer")
            if not minimum <= value <= maximum:
                raise ValueError(f"{name} must be between {minimum} and {maximum}")


@dataclass(frozen=True, slots=True)
class SandboxPolicy:
    """Immutable desired isolation policy for a deception workload."""

    policy_id: str
    tier: SandboxTier = SandboxTier.SIMULATION
    limits: SandboxLimits = SandboxLimits()
    network_mode: NetworkMode = NetworkMode.DENY_ALL
    namespaces: tuple[str, ...] = ()
    seccomp_profile: str | None = None
    no_new_privs: bool = True
    drop_capabilities: bool = True
    capabilities: tuple[str, ...] = ()
    allow_host_mounts: bool = False
    allow_host_credentials: bool = False
    allow_privileged: bool = False
    allow_process_execution: bool = False
    snapshot_before_run: bool = False
    destroy_after_run: bool = False


@dataclass(frozen=True, slots=True)
class SandboxPolicyIssue:
    code: str
    message: str


_POLICY_ID = re.compile(r"[a-z0-9][a-z0-9._-]{0,63}")
_SECCOMP_PROFILE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")
_ALLOWED_NAMESPACES = frozenset({"user", "mount", "pid", "ipc", "uts", "net"})
_REQUIRED_WORKER_NAMESPACES = frozenset({"user", "mount", "pid", "ipc", "uts", "net"})


def validate_sandbox_policy(policy: SandboxPolicy) -> list[SandboxPolicyIssue]:
    """Return policy violations; no host or kernel state is changed."""

    issues: list[SandboxPolicyIssue] = []

    if not isinstance(policy.policy_id, str) or not _POLICY_ID.fullmatch(policy.policy_id):
        issues.append(
            SandboxPolicyIssue(
                "invalid_policy_id",
                "policy_id must be 1-64 lowercase letters, digits, dots, underscores, or hyphens",
            )
        )

    namespace_names = tuple(name for name in policy.namespaces if isinstance(name, str))
    if len(namespace_names) != len(policy.namespaces):
        issues.append(
            SandboxPolicyIssue("invalid_namespace_name", "namespace names must be strings")
        )
    unknown_namespaces = set(namespace_names) - _ALLOWED_NAMESPACES
    if unknown_namespaces:
        issues.append(
            SandboxPolicyIssue(
                "unknown_namespace",
                f"unsupported namespace names: {', '.join(sorted(unknown_namespaces))}",
            )
        )
    if len(namespace_names) != len(set(namespace_names)):
        issues.append(
            SandboxPolicyIssue("duplicate_namespace", "namespace names must be unique")
        )

    if policy.allow_host_mounts:
        issues.append(
            SandboxPolicyIssue("host_mounts_forbidden", "sandbox policies cannot allow host mounts")
        )
    if policy.allow_host_credentials:
        issues.append(
            SandboxPolicyIssue(
                "host_credentials_forbidden",
                "sandbox policies cannot receive host credentials",
            )
        )
    if policy.allow_privileged:
        issues.append(
            SandboxPolicyIssue("privileged_forbidden", "privileged sandbox workloads are forbidden")
        )
    if policy.capabilities:
        issues.append(
            SandboxPolicyIssue(
                "capabilities_forbidden",
                "sandbox workloads must drop all Linux capabilities",
            )
        )

    if policy.network_mode not in tuple(NetworkMode):
        issues.append(
            SandboxPolicyIssue(
                "unknown_network_mode",
                f"unsupported network mode: {policy.network_mode!r}",
            )
        )

    if not isinstance(policy.limits, SandboxLimits):
        issues.append(
            SandboxPolicyIssue("invalid_resource_limits", "limits must be a SandboxLimits instance")
        )

    if policy.tier == SandboxTier.SIMULATION:
        if policy.allow_process_execution:
            issues.append(
                SandboxPolicyIssue(
                    "simulation_process_execution",
                    "simulation tier cannot execute operating-system processes",
                )
            )
        if policy.network_mode != NetworkMode.DENY_ALL:
            issues.append(
                SandboxPolicyIssue(
                    "simulation_network_access",
                    "simulation tier must deny network egress",
                )
            )
        if policy.namespaces or policy.seccomp_profile is not None:
            issues.append(
                SandboxPolicyIssue(
                    "simulation_runtime_controls",
                    "simulation tier does not claim operating-system namespace "
                    "or seccomp isolation",
                )
            )

    elif policy.tier == SandboxTier.ISOLATED_WORKER:
        missing = _REQUIRED_WORKER_NAMESPACES - set(policy.namespaces)
        if missing:
            issues.append(
                SandboxPolicyIssue(
                    "missing_namespaces",
                    f"isolated worker requires namespaces: {', '.join(sorted(missing))}",
                )
            )
        if (
            not isinstance(policy.seccomp_profile, str)
            or not _SECCOMP_PROFILE.fullmatch(policy.seccomp_profile)
        ):
            issues.append(
                SandboxPolicyIssue(
                    "invalid_seccomp_profile",
                    "isolated worker requires a named seccomp profile (not a filesystem path)",
                )
            )
        if not policy.no_new_privs:
            issues.append(
                SandboxPolicyIssue(
                    "no_new_privs_required",
                    "isolated worker requires no_new_privs",
                )
            )
        if not policy.drop_capabilities:
            issues.append(
                SandboxPolicyIssue(
                    "capability_drop_required",
                    "isolated worker must drop all Linux capabilities",
                )
            )

    elif policy.tier == SandboxTier.DISPOSABLE_VM:
        if not policy.snapshot_before_run or not policy.destroy_after_run:
            issues.append(
                SandboxPolicyIssue(
                    "vm_lifecycle_required",
                    "disposable VM policy requires snapshot_before_run and destroy_after_run",
                )
            )
        if policy.network_mode != NetworkMode.DENY_ALL:
            issues.append(
                SandboxPolicyIssue(
                    "vm_network_egress_forbidden",
                    "disposable VM policy must deny network egress by default",
                )
            )
        if not policy.allow_process_execution:
            issues.append(
                SandboxPolicyIssue(
                    "vm_execution_required",
                    "disposable VM tier must explicitly enable workload execution",
                )
            )

    else:
        issues.append(
            SandboxPolicyIssue("unknown_tier", f"unsupported sandbox tier: {policy.tier!r}")
        )

    return issues
