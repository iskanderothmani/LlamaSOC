# LlamaSOC — Local SOC Triage Lab

LlamaSOC is a defensive cybersecurity project that validates security events, runs explainable baseline detections, and produces a JSON triage report. This first implementation is deterministic and local; it does not call an external AI service or perform response actions.

## What it currently does

- Validates JSONL event records, required fields, supported event types, timezone-aware timestamps, selected field lengths, and IP address syntax.
- Detects repeated failed authentication attempts followed by a successful login within 15 minutes.
- Flags selected privileged-access changes.
- Matches network destinations against an optional local/mock indicator list.
- Flags large outbound transfers for analyst review.
- Produces JSON with event counts, evidence, severity, confidence, recommendations, and a human-review requirement.
- Includes synthetic events, unit tests, and a GitHub Actions workflow.

These rules are educational triage heuristics, not proof of compromise. The project does not yet implement LLM-based summarization, production SIEM integrations, or automated containment.

## Requirements

- Python 3.11 or later
- No third-party runtime dependencies

## Run locally

Clone the repository and enter its directory:

```bash
git clone https://github.com/iskanderothmani/LlamaSOC.git
cd LlamaSOC
```

Run the test suite:

```bash
PYTHONPATH=src python -m unittest discover -s tests -v
```

Analyze the included synthetic dataset:

```bash
PYTHONPATH=src python -m llamasoc.cli data/sample-events.jsonl --indicator 198.51.100.23
```

Write the report to a file:

```bash
PYTHONPATH=src python -m llamasoc.cli data/sample-events.jsonl --indicator 198.51.100.23 --output report.json
```

The CLI exits with a nonzero status if event validation or JSONL parsing errors are found. The sample dataset uses documentation-reserved IP ranges and fictional identities.

## Detection rules

| Rule ID | Detection | Default severity |
|---|---|---|
| AUTH-001 | Repeated failed logins followed by success within 15 minutes | High |
| IAM-001 | Selected privileged-access changes | High |
| NET-001 | Destination matches a supplied local/mock indicator | High |
| NET-002 | Outbound byte count reaches the triage threshold | Medium |

Adjust the failed-login threshold with `--failed-login-threshold 3`. Supply local test indicators with one or more `--indicator` arguments. The indicator matching is exact-string matching; it does not query an external threat-intelligence service.

## Repository layout

```text
.
├── .github/workflows/tests.yml
├── data/sample-events.jsonl
├── docs/
│   ├── architecture.md
│   └── threat-model.md
├── src/llamasoc/
│   ├── __init__.py
│   ├── cli.py
│   └── core.py
├── tests/test_core.py
├── pyproject.toml
└── requirements.txt
```

## Safety and privacy

- Use synthetic or sanitized data; never commit company logs, customer data, secrets, access tokens, or private keys.
- Keep experiments isolated and test only systems you own or are authorized to assess.
- Alerts are advisory. Validate evidence and recommendations before taking action.
- No containment, account lockout, host isolation, or other response action is implemented.
- Treat event content as untrusted and review generated reports for sensitive information before sharing.
- See [the architecture](docs/architecture.md) and [threat model](docs/threat-model.md).

## Roadmap

- [x] Establish the Python package and CLI
- [x] Add schema validation and deterministic baseline detections
- [x] Add synthetic data and unit tests
- [x] Add CI test workflow
- [ ] Execute and review CI results on GitHub
- [ ] Add structured analyst case records and audit trail
- [ ] Add an optional, isolated LLM summarization adapter with strict output validation and human approval
- [ ] Add a documented local demo and example report

## Status

**Prototype — initial implementation committed.** CI and test outcomes must be confirmed by running the workflow; no passing result is claimed until verified.

## Disclaimer

Educational defensive-security work only. This prototype is not production-ready and must not be connected to production systems without authorization, security review, and appropriate controls.
