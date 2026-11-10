# Input and output contract

## Input

The root has events and optional integer threshold (default 3) and window_seconds (default 300). Every event requires id, timestamp with a UTC offset, service, user, src_ip (IPv4 or IPv6) and outcome (failure or success). The time window includes the lower boundary and excludes events at the same timestamp as the success. Identical repeated IDs are deduplicated; conflicting duplicates fail. Each failure can contribute to at most one success episode per service/user/IP.

See [example.json](example.json) for a complete fictional input. All demo identities, indicators, events, products and reputation providers are synthetic. Documentation IPs and example domains are not threat intelligence.

Input must be a UTF-8 JSON object no larger than 2 MiB. Duplicate JSON keys, malformed required fields, ambiguous timestamps and conflicting identifiers are rejected. Timestamps require an explicit UTC offset. Small local snapshots are the intended workload; there is no streaming, database or production connector in this version.

## Output

`python3 agent.py INPUT.json` emits Markdown. Add `--format json` for structured output. The JSON envelope contains schema_version, agent, summary, findings, limitations and next_steps. The tool writes to standard output and does not modify the source input. Input errors return exit code 2; a valid assessment returns 0 even when findings are present.

JSON preserves evidence text. Markdown renders evidence as literal escaped text, so input cannot inject links, headings or HTML into the report. Every result preserves substantive limitations.

## Example interpretation

One review candidate links three failures to the later success. The example is a hypothesis trigger, not a confirmed incident.

Background: [MITRE ATT&CK T1110 — Brute Force](https://attack.mitre.org/techniques/T1110/). The included hunt covers only one possible authentication pattern; it is not comprehensive T1110 coverage.
