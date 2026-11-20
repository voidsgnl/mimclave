"""Conservative analysis of verified MIMCLAVE HTTP evidence."""

from collections import Counter
from datetime import datetime
from ipaddress import ip_address
from typing import Any

SENSITIVE_PATHS = (
    "/.env", "/.git", "/wp-admin", "/wp-login.php", "/phpmyadmin",
    "/actuator", "/server-status", "/config.php", "/backup",
)


def _timestamp(event: dict[str, Any]) -> datetime:
    value = event.get("occurred_at")
    if not isinstance(value, str):
        raise ValueError("evidence event has no valid occurred_at timestamp")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as exc:
        raise ValueError("evidence event has an invalid occurred_at timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("evidence event timestamp must include a timezone")
    return parsed


def _is_sensitive_path(path: str) -> bool:
    lowered = path.lower()
    return any(lowered == prefix or lowered.startswith(prefix + "/") for prefix in SENSITIVE_PATHS)


def _signals(events: list[dict[str, Any]], times: list[datetime]) -> list[dict[str, str]]:
    signals: list[dict[str, str]] = []
    paths = [str(event["path"]) for event in events]
    path_counts = Counter(paths)
    not_found_paths = {str(event["path"]) for event in events if event["status_code"] == 404}
    sensitive = sorted({path for path in paths if _is_sensitive_path(path)})

    if sensitive:
        signals.append({
            "code": "sensitive-path-probe",
            "severity": "medium",
            "description": (
                "Requests targeted paths commonly associated with exposed files "
                "or administration endpoints."
            ),
            "observations": ", ".join(sensitive[:8]),
        })
    if len(not_found_paths) >= 3:
        signals.append({
            "code": "not-found-sweep",
            "severity": "low",
            "description": (
                "Three or more distinct paths returned HTTP 404 in this activity cluster."
            ),
            "observations": f"{len(not_found_paths)} distinct 404 paths",
        })
    repeated = sorted(path for path, count in path_counts.items() if count >= 5)
    if repeated:
        signals.append({
            "code": "repeated-path",
            "severity": "low",
            "description": "A path was requested at least five times in one activity cluster.",
            "observations": ", ".join(repeated[:8]),
        })

    left = 0
    burst = 0
    for right, current in enumerate(times):
        while (current - times[left]).total_seconds() > 10:
            left += 1
        burst = max(burst, right - left + 1)
    if burst >= 10:
        signals.append({
            "code": "high-request-rate",
            "severity": "medium",
            "description": "At least ten requests occurred within a rolling ten-second window.",
            "observations": f"peak {burst} requests / 10 seconds",
        })
    return signals


def build_activity_report(
    events: list[dict[str, Any]], *, idle_timeout_seconds: int = 1800
) -> dict[str, Any]:
    """Group events by source IP, profile, and inactivity; this is not identity attribution."""
    if idle_timeout_seconds < 1:
        raise ValueError("idle_timeout_seconds must be at least 1")

    ordered = sorted(events, key=lambda item: (_timestamp(item), str(item.get("event_id", ""))))
    clusters: list[dict[str, Any]] = []
    last_by_source: dict[tuple[str | None, str], int] = {}

    for event in ordered:
        timestamp = _timestamp(event)
        source_ip = event.get("source_ip")
        if source_ip is not None and not isinstance(source_ip, str):
            raise ValueError("evidence event source_ip must be a string or null")
        profile_id = event.get("profile_id")
        path = event.get("path")
        method = event.get("method")
        status_code = event.get("status_code")
        event_id = event.get("event_id")
        if not all(
            isinstance(value, str) and value
            for value in (profile_id, path, method, event_id)
        ):
            raise ValueError("evidence event is missing required text fields")
        if (
            not path.startswith("/")
            or "?" in path
            or "#" in path
            or len(path) > 2048
            or any(ord(char) < 32 for char in path)
        ):
            raise ValueError("evidence event path is not a sanitized origin-form path")
        if (
            not isinstance(status_code, int)
            or isinstance(status_code, bool)
            or not 100 <= status_code <= 599
        ):
            raise ValueError("evidence event status_code must be between 100 and 599")
        if source_ip is not None:
            try:
                ip_address(source_ip)
            except ValueError as exc:
                raise ValueError("evidence event source_ip is not a valid IP address") from exc

        key = (source_ip, profile_id) if source_ip is not None else (None, event_id)
        cluster_index = last_by_source.get(key)
        if cluster_index is not None:
            gap = (timestamp - clusters[cluster_index]["_last_time"]).total_seconds()
            if gap > idle_timeout_seconds:
                cluster_index = None

        if cluster_index is None:
            cluster_index = len(clusters)
            clusters.append({
                "activity_id": f"activity-{event_id[:8]}",
                "source_ip": source_ip,
                "profile_id": profile_id,
                "first_seen": timestamp.isoformat(),
                "last_seen": timestamp.isoformat(),
                "request_count": 0,
                "timeline": [],
                "_last_time": timestamp,
                "_times": [],
                "_events": [],
            })
        last_by_source[key] = cluster_index
        cluster = clusters[cluster_index]
        cluster["last_seen"] = timestamp.isoformat()
        cluster["_last_time"] = timestamp
        cluster["_times"].append(timestamp)
        cluster["_events"].append(event)
        cluster["request_count"] += 1
        cluster["timeline"].append({
            "occurred_at": timestamp.isoformat(),
            "method": method,
            "path": path,
            "status_code": status_code,
            "event_id": event_id,
        })

    for cluster in clusters:
        cluster_events = cluster.pop("_events")
        times = cluster.pop("_times")
        cluster.pop("_last_time")
        cluster["methods"] = dict(
            sorted(Counter(str(event["method"]) for event in cluster_events).items())
        )
        cluster["paths"] = dict(
            sorted(Counter(str(event["path"]) for event in cluster_events).items())
        )
        cluster["status_codes"] = dict(
            sorted(Counter(str(event["status_code"]) for event in cluster_events).items())
        )
        cluster["indicators"] = _signals(cluster_events, times)

    return {
        "evidence_records": len(ordered),
        "activity_clusters": len(clusters),
        "idle_timeout_seconds": idle_timeout_seconds,
        "clusters": clusters,
        "interpretation": (
            "Clusters are heuristically grouped by source IP, profile, and inactivity. "
            "They are not authenticated sessions or proof of a person's identity. "
            "Indicators are triage signals, not verdicts."
        ),
    }


def render_activity_report(report: dict[str, Any]) -> str:
    """Render a concise human-readable inspection report."""
    lines = [
        "MIMCLAVE — Session Intelligence",
        "-----------------------------",
        f"Verified evidence records: {report['evidence_records']}",
        f"Activity clusters: {report['activity_clusters']}",
        f"Idle timeout: {report['idle_timeout_seconds']} seconds",
    ]
    for cluster in report["clusters"]:
        lines.extend([
            "",
            f"{cluster['activity_id']}  |  profile: {cluster['profile_id']}",
            f"Source: {cluster['source_ip'] or 'unknown'}",
            f"First seen: {cluster['first_seen']}",
            f"Last seen:  {cluster['last_seen']}",
            f"Requests: {cluster['request_count']}",
            "Paths: " + ", ".join(
                f"{path} ({count})" for path, count in cluster["paths"].items()
            ),
        ])
        if cluster["indicators"]:
            lines.append("Indicators:")
            for indicator in cluster["indicators"]:
                lines.append(
                    f"  [{indicator['severity']}] {indicator['code']}: "
                    f"{indicator['description']} ({indicator['observations']})"
                )
        else:
            lines.append("Indicators: none from the current rules")
        lines.append("Timeline:")
        for item in cluster["timeline"]:
            lines.append(
                f"  {item['occurred_at']}  {item['method']} {item['path']} "
                f"-> {item['status_code']}"
            )
    lines.extend(["", report["interpretation"]])
    return "\n".join(lines)
