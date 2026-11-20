import pytest

from mirage.sandbox.policy import (
    NetworkMode,
    SandboxLimits,
    SandboxPolicy,
    SandboxTier,
    validate_sandbox_policy,
)


def codes(policy: SandboxPolicy) -> set[str]:
    return {issue.code for issue in validate_sandbox_policy(policy)}


def test_default_policy_is_safe_simulation_only() -> None:
    policy = SandboxPolicy(policy_id="http-decoy")
    assert validate_sandbox_policy(policy) == []
    assert policy.tier is SandboxTier.SIMULATION
    assert policy.network_mode is NetworkMode.DENY_ALL
    assert policy.allow_process_execution is False
    assert policy.allow_host_mounts is False
    assert policy.allow_host_credentials is False


@pytest.mark.parametrize(
    "kwargs, expected",
    [
        ({"allow_process_execution": True}, "simulation_process_execution"),
        (
            {"network_mode": NetworkMode.ESTABLISHED_CLIENT_STREAM},
            "simulation_network_access",
        ),
        ({"namespaces": ("net",)}, "simulation_runtime_controls"),
        ({"seccomp_profile": "default"}, "simulation_runtime_controls"),
    ],
)
def test_simulation_rejects_claims_of_os_isolation_or_execution(
    kwargs: dict[str, object], expected: str
) -> None:
    assert expected in codes(SandboxPolicy(policy_id="sim", **kwargs))


def test_isolated_worker_requires_complete_security_controls() -> None:
    policy = SandboxPolicy(
        policy_id="ssh-worker",
        tier=SandboxTier.ISOLATED_WORKER,
        namespaces=("user", "mount", "pid", "ipc", "uts", "net"),
        seccomp_profile="mirage-worker-v1",
        network_mode=NetworkMode.ESTABLISHED_CLIENT_STREAM,
    )
    assert validate_sandbox_policy(policy) == []


def test_isolated_worker_rejects_missing_namespaces_and_seccomp() -> None:
    policy = SandboxPolicy(
        policy_id="weak-worker",
        tier=SandboxTier.ISOLATED_WORKER,
        namespaces=("user", "mount", "pid"),
    )
    assert {
        "missing_namespaces",
        "invalid_seccomp_profile",
    }.issubset(codes(policy))


@pytest.mark.parametrize(
    "kwargs, expected",
    [
        ({"no_new_privs": False}, "no_new_privs_required"),
        ({"drop_capabilities": False}, "capability_drop_required"),
        ({"capabilities": ("CAP_NET_ADMIN",)}, "capabilities_forbidden"),
        ({"allow_host_mounts": True}, "host_mounts_forbidden"),
        ({"allow_host_credentials": True}, "host_credentials_forbidden"),
        ({"allow_privileged": True}, "privileged_forbidden"),
    ],
)
def test_isolated_worker_rejects_unsafe_privileges(kwargs, expected: str) -> None:
    policy = SandboxPolicy(
        policy_id="worker",
        tier=SandboxTier.ISOLATED_WORKER,
        namespaces=("user", "mount", "pid", "ipc", "uts", "net"),
        seccomp_profile="worker",
        **kwargs,
    )
    assert expected in codes(policy)


def test_disposable_vm_requires_snapshot_destruction_and_no_egress() -> None:
    safe = SandboxPolicy(
        policy_id="research-vm",
        tier=SandboxTier.DISPOSABLE_VM,
        allow_process_execution=True,
        snapshot_before_run=True,
        destroy_after_run=True,
    )
    assert validate_sandbox_policy(safe) == []

    unsafe = SandboxPolicy(
        policy_id="research-vm",
        tier=SandboxTier.DISPOSABLE_VM,
        allow_process_execution=True,
    )
    assert {"vm_lifecycle_required"}.issubset(codes(unsafe))


@pytest.mark.parametrize(
    "field, value",
    [
        ("cpu_quota_percent", 0),
        ("memory_bytes", 1),
        ("process_count", 0),
        ("open_file_limit", 2),
        ("scratch_bytes", 0),
        ("max_sessions", 0),
        ("wall_time_seconds", 0),
        ("memory_bytes", 32 * 1024**3),
    ],
)
def test_resource_limits_are_bounded(field: str, value: int) -> None:
    with pytest.raises(ValueError, match=field):
        SandboxLimits(**{field: value})


def test_resource_limits_reject_boolean_values() -> None:
    with pytest.raises(ValueError, match="max_sessions"):
        SandboxLimits(max_sessions=True)


def test_policy_identifier_and_namespace_names_are_validated() -> None:
    policy = SandboxPolicy(
        policy_id="../bad",
        tier=SandboxTier.ISOLATED_WORKER,
        namespaces=("user", "host", "user"),
        seccomp_profile="../profile",
    )
    assert {
        "invalid_policy_id",
        "unknown_namespace",
        "duplicate_namespace",
        "invalid_seccomp_profile",
        "missing_namespaces",
    }.issubset(codes(policy))


def test_unknown_network_mode_is_rejected_for_worker() -> None:
    policy = SandboxPolicy(
        policy_id="worker",
        tier=SandboxTier.ISOLATED_WORKER,
        namespaces=("user", "mount", "pid", "ipc", "uts", "net"),
        seccomp_profile="worker",
        network_mode="allow_all",  # type: ignore[arg-type]
    )
    assert "unknown_network_mode" in codes(policy)


def test_malformed_namespace_and_policy_types_return_issues() -> None:
    policy = SandboxPolicy(
        policy_id=None,  # type: ignore[arg-type]
        tier=SandboxTier.ISOLATED_WORKER,
        namespaces=("user", None),  # type: ignore[arg-type]
        seccomp_profile=123,  # type: ignore[arg-type]
    )
    assert {
        "invalid_policy_id",
        "invalid_namespace_name",
        "missing_namespaces",
        "invalid_seccomp_profile",
    }.issubset(codes(policy))
