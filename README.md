# Threat Hunting Agent

**Investigate a hypothesis with ordered, traceable evidence.**

A model-agnostic AI agent skill paired with a working Python evidence tool. The skill guides an assistant's analysis; the deterministic tool validates and organizes a local evidence snapshot. The included demo runs offline with no API key or dependencies.

[Agent instructions](SKILL.md) · [Example report](example-report.md) · [Input contract](INPUT.md) · [Portfolio](https://shaized.github.io/)

## Try it in one minute

Requires Python 3.11 or newer.

```sh
git clone https://github.com/shaized/threat-hunting-agent.git
cd threat-hunting-agent
python3 agent.py example.json
python3 agent.py example.json --format json
python3 -m unittest discover -v
```

**Expected result:** One review candidate links three failures to the later success. The example is a hypothesis trigger, not a confirmed incident.

## Use it as an AI agent

Open the repository in an assistant that can read local files and run Python, then give it this request:

> Read SKILL.md and follow its workflow. Hunt for a failure burst followed by a successful authentication in example.json. Explain the exact event sequence, benign alternatives and visibility gaps. Do not declare compromise from the sequence alone.

SKILL.md is the agent entry point. INPUT.md defines the evidence contract. agent.py performs the domain-specific analysis; runtime.py handles bounded JSON input, validation and report rendering. The assistant can explain the results, investigate alternatives and identify missing evidence using the tools you authorize.

The Python command itself is **not an LLM runtime**. It makes no network calls and performs no operational actions. There is no bundled model, production connector, autonomous service or implied access to your environment.

## What the agent does

1. State a falsifiable hunt hypothesis, the entity keys, the observation window and the telemetry required to test it.
2. Check data availability, retention, time zones and field meaning. Missing telemetry is a coverage gap, not a negative result.
3. Run agent.py for the included authentication hunt. It correlates strictly earlier failures and a later success for the same service, user and source IP. Normalize service and tenant identity before supplying events.
4. Investigate alternative explanations, post-login activity and contradictory observations. Return the hypothesis, observations, evidence IDs, confidence, coverage and recommended pivots.

## Design

```text
Selected evidence → validated local tool → traceable report
                                             ↓
                         AI-assisted reasoning → analyst decision
```

The examples are original, vendor-neutral implementations. All bundled data is fictional. Results retain unknowns and evidence gaps rather than presenting missing data as reassurance. Read the input contract for exact matching, thresholds and limitations.

## Validate and extend

The test suite covers the example, meaningful boundary cases, invalid evidence references where applicable, timestamp handling, bounded input and safe Markdown output. GitHub Actions runs the same offline tests. To add a real integration, produce the documented input shape in a separately reviewed adapter; keep credentials and operational evidence outside this repository.

Background: [MITRE ATT&CK T1110 — Brute Force](https://attack.mitre.org/techniques/T1110/). The included hunt covers only one possible authentication pattern; it is not comprehensive T1110 coverage.

## Contributing and security

See [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md). Use synthetic fixtures in issues and pull requests. This is a focused reference implementation; validate it against your data and review workflow before operational use.

## License

[MIT](LICENSE) · Built by [Shai Zaidenberg](https://github.com/shaized)
