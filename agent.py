"""Find authentication failure bursts followed by a successful login."""

from collections import defaultdict, deque
from datetime import timedelta
from ipaddress import ip_address

from runtime import choice, cli, instant, integer, report, rows, text, utc


def analyze(data):
    threshold = integer(data.get("threshold", 3), "threshold", 1)
    seconds = integer(data.get("window_seconds", 300), "window_seconds", 1)
    events = rows(data.get("events"), "events")
    seen, normalized, duplicates = {}, [], 0
    for event in events:
        event_id = text(event.get("id"), "event.id")
        if event_id in seen:
            if seen[event_id] != event:
                raise ValueError(f"conflicting duplicate event id: {event_id}")
            duplicates += 1
            continue
        seen[event_id] = event
        timestamp = instant(event.get("timestamp"), "event.timestamp")
        key = (
            text(event.get("service"), "event.service"),
            text(event.get("user"), "event.user"),
            str(ip_address(text(event.get("src_ip"), "event.src_ip"))),
        )
        outcome = choice(event.get("outcome"), ["failure", "success"], "event.outcome")
        normalized.append((timestamp, event_id, key, outcome))
    normalized.sort(key=lambda row: (row[0], row[1]))
    failures = defaultdict(deque)
    findings = []
    for timestamp, event_id, key, outcome in normalized:
        bucket = failures[key]
        cutoff = timestamp - timedelta(seconds=seconds)
        while bucket and bucket[0][0] < cutoff:
            bucket.popleft()
        if outcome == "failure":
            bucket.append((timestamp, event_id))
            continue
        # Equal timestamps do not establish that the failure preceded the success.
        preceding = [(time, eid) for time, eid in bucket if time < timestamp]
        if len(preceding) >= threshold:
            findings.append(
                {
                    "status": "requires_investigation",
                    "service": key[0],
                    "user": key[1],
                    "src_ip": key[2],
                    "first_failure": utc(preceding[0][0]),
                    "success_at": utc(timestamp),
                    "failure_count": len(preceding),
                    "evidence_ids": [eid for _, eid in preceding] + [event_id],
                    "hypothesis": "A failure burst followed by success may indicate credential guessing.",
                }
            )
        # Each failure belongs to at most one success episode for this key.
        failures[key] = deque((time, eid) for time, eid in bucket if time >= timestamp)
    return report(
        "Threat Hunting Agent",
        {
            "unique_events": len(normalized),
            "duplicates_ignored": duplicates,
            "threshold": threshold,
            "window_seconds": seconds,
            "findings": len(findings),
            "assessment": "investigate"
            if findings
            else "no_pattern_in_supplied_events",
        },
        findings,
        [
            "This one hunt covers authentication bursts for the same service, user and IP; it does not cover all brute-force behavior.",
            "A matching sequence can also reflect mistyped passwords or automation; it does not prove compromise.",
            "No independent check of collection completeness, retention, clock accuracy or service identity was performed.",
            "Events at identical timestamps cannot establish sequence order. No pattern is not a clean bill of health.",
        ],
        [
            "Confirm collection coverage and the service/user identity mapping.",
            "Review MFA, device context, authorized activity and actions after the successful login.",
            "Document evidence supporting and contradicting the hypothesis before escalation.",
        ],
    )


if __name__ == "__main__":
    cli(analyze, __doc__)
