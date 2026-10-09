"""Validate synthetic events and apply explainable local SOC detection rules."""
from __future__ import annotations
from collections import defaultdict
from datetime import datetime, timezone
from ipaddress import ip_address
from typing import Any, Iterable

REQUIRED = {"event_id", "timestamp", "event_type", "source"}
TYPES = {"authentication", "privilege_change", "network_connection", "endpoint_alert"}
FAILED = {"failed", "failure", "denied"}
SUCCESS = {"success", "succeeded", "allowed"}


class EventValidationError(ValueError):
    """Raised when an event does not satisfy the input schema."""


def _timestamp(value: Any) -> datetime:
    if not isinstance(value, str) or not value.strip():
        raise EventValidationError("timestamp must be a non-empty ISO-8601 string")
    value = value.strip()
    if value.endswith("Z"):
        value = value[:-1] + "+00:00"
    try:
        result = datetime.fromisoformat(value)
    except ValueError as exc:
        raise EventValidationError("timestamp must be valid ISO-8601") from exc
    if result.tzinfo is None:
        raise EventValidationError("timestamp must include a timezone")
    return result.astimezone(timezone.utc)


def validate_event(event: Any) -> dict[str, Any]:
    """Validate an event and return a copy with normalized values."""
    if not isinstance(event, dict):
        raise EventValidationError("each event must be a JSON object")
    missing = sorted(REQUIRED - event.keys())
    if missing:
        raise EventValidationError("missing required fields: " + ", ".join(missing))
    for key in ("event_id", "event_type", "source"):
        if not isinstance(event[key], str) or not event[key].strip():
            raise EventValidationError(key + " must be a non-empty string")
    clean = dict(event)
    clean["event_id"] = event["event_id"].strip()
    clean["event_type"] = event["event_type"].strip().lower()
    clean["source"] = event["source"].strip()
    if clean["event_type"] not in TYPES:
        raise EventValidationError("unsupported event_type: " + clean["event_type"])
    clean["_time"] = _timestamp(event["timestamp"])
    if clean.get("src_ip"):
        try:
            clean["src_ip"] = str(ip_address(str(clean["src_ip"])))
        except ValueError as exc:
            raise EventValidationError("src_ip must be a valid IP address") from exc
    for key in ("username", "outcome", "action", "destination", "details"):
        value = clean.get(key)
        if value is not None:
            if not isinstance(value, (str, int, float, bool)):
                raise EventValidationError(key + " must be a scalar value")
            if len(str(value)) > 2000:
                raise EventValidationError(key + " exceeds 2000 characters")
    return clean


def _alert(rule_id: str, title: str, severity: str, ids: list[str],
           evidence: str, recommendation: str, confidence: str = "medium") -> dict[str, Any]:
    return {"rule_id": rule_id, "title": title, "severity": severity,
            "event_ids": ids, "evidence": evidence, "recommendation": recommendation,
            "confidence": confidence, "requires_human_review": True}


def analyze_events(events: Iterable[dict[str, Any]], *,
                   threat_indicators: set[str] | None = None,
                   failed_login_threshold: int = 3) -> dict[str, Any]:
    """Run local, deterministic detections. No network calls or response actions."""
    if failed_login_threshold < 1:
        raise ValueError("failed_login_threshold must be >= 1")
    indicators = {str(x).strip() for x in (threat_indicators or set())}
    valid, errors, seen = [], [], set()
    for index, raw in enumerate(events):
        try:
            item = validate_event(raw)
            if item["event_id"] in seen:
                raise EventValidationError("duplicate event_id")
            seen.add(item["event_id"])
            valid.append(item)
        except EventValidationError as exc:
            errors.append({"index": str(index), "error": str(exc)})
    valid.sort(key=lambda x: (x["_time"], x["event_id"]))
    alerts = []
    accounts = defaultdict(list)
    for item in valid:
        if item["event_type"] == "authentication" and item.get("username"):
            accounts[str(item["username"]).lower()].append(item)
    for username, events_for_user in accounts.items():
        for pos, item in enumerate(events_for_user):
            if str(item.get("outcome", "")).lower() not in SUCCESS:
                continue
            failed = [x for x in events_for_user[:pos]
                      if str(x.get("outcome", "")).lower() in FAILED
                      and 0 <= (item["_time"] - x["_time"]).total_seconds() <= 900]
            if len(failed) >= failed_login_threshold:
                selected = failed[-failed_login_threshold:] + [item]
                alerts.append(_alert("AUTH-001", "Repeated failed logins followed by success",
                    "high", [x["event_id"] for x in selected],
                    f"Account {username} had repeated failures within 15 minutes before success.",
                    "Verify the sign-in, review MFA and source context, and inspect adjacent events.", "high"))
                break
    for item in valid:
        eid = item["event_id"]
        if item["event_type"] == "privilege_change":
            action = str(item.get("action", "")).lower()
            if action in {"add_to_admin", "grant_admin", "privilege_escalation", "added_to_privileged_group"}:
                alerts.append(_alert("IAM-001", "Privileged access change", "high", [eid],
                    f"Event records privileged action {action}.",
                    "Confirm an approved change and validate actor, target, and time."))
        if item["event_type"] == "network_connection":
            dest = str(item.get("destination", item.get("src_ip", ""))).strip()
            if dest and dest in indicators:
                alerts.append(_alert("NET-001", "Destination matched local test indicator", "high", [eid],
                    f"Destination {dest} matched the supplied local/mock indicator list.",
                    "Validate indicator provenance and review related network and endpoint telemetry."))
            try:
                byte_count = int(item.get("bytes_out", -1))
            except (TypeError, ValueError):
                byte_count = -1
            if byte_count >= 100_000_000:
                alerts.append(_alert("NET-002", "Large outbound transfer requires review", "medium", [eid],
                    f"Event reports {byte_count} outbound bytes; this heuristic is not proof of exfiltration.",
                    "Compare with asset baselines, approved transfers, destination, and business context.", "low"))
    safe_events = [{k: v for k, v in item.items() if k != "_time"} for item in valid]
    return {"summary": {"events_received": len(valid) + len(errors), "events_valid": len(valid),
        "events_rejected": len(errors), "alerts_generated": len(alerts),
        "mode": "deterministic-local-analysis"},
        "alerts": alerts, "errors": errors, "events": safe_events,
        "disclaimer": "Triage support only. Validate evidence and recommendations before taking action."}
