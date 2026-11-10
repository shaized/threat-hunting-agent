# Threat Hunting Agent

## Summary

- **unique events:** 4
- **duplicates ignored:** 0
- **threshold:** 3
- **window seconds:** 300
- **findings:** 1
- **assessment:** investigate

## Findings

### Finding 1

- **status:** requires\_investigation
- **service:** lab-identity
- **user:** analyst-demo
- **src ip:** 192\.0\.2\.10
- **first failure:** 2026-01-15T10:01:00Z
- **success at:** 2026-01-15T10:04:00Z
- **failure count:** 3
- **evidence ids:** \["auth-1", "auth-2", "auth-3", "auth-4"\]
- **hypothesis:** A failure burst followed by success may indicate credential guessing\.


## Limitations

- This one hunt covers authentication bursts for the same service, user and IP; it does not cover all brute-force behavior\.
- A matching sequence can also reflect mistyped passwords or automation; it does not prove compromise\.
- No independent check of collection completeness, retention, clock accuracy or service identity was performed\.
- Events at identical timestamps cannot establish sequence order\. No pattern is not a clean bill of health\.

## Next Steps

- Confirm collection coverage and the service/user identity mapping\.
- Review MFA, device context, authorized activity and actions after the successful login\.
- Document evidence supporting and contradicting the hypothesis before escalation\.
