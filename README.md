# LlamaSOC — AI-Assisted Security Operations Lab

LlamaSOC is an educational Security Operations Center (SOC) assistant concept that helps analysts summarize alerts, enrich events, and prioritize investigation steps. It is designed around human review, auditable outputs, and synthetic lab data.

## Problem

SOC teams receive high volumes of alerts with uneven context. Analysts need concise, explainable summaries without allowing an AI model to make unreviewed containment or remediation decisions.

## Proposed solution

- Normalize sample security events into a consistent schema.
- Enrich events with safe, local context and mock threat-intelligence records.
- Produce structured summaries: what happened, why it matters, evidence, confidence, and recommended next steps.
- Preserve the original event and record the model/prompt version used for analysis.
- Require analyst approval before any response action.
- Include deterministic rules and tests so model output is not the only detection mechanism.

## Architecture (initial design)

1. **Ingestion:** JSONL/CSV sample events from a local lab.
2. **Normalization:** Validate required fields and timestamps.
3. **Detection and enrichment:** Apply explicit rules and attach mock context.
4. **AI analysis:** Generate a structured summary from minimized event data.
5. **Analyst review:** Display evidence, confidence, uncertainty, and proposed actions.
6. **Audit:** Record input event ID, analysis timestamp, model configuration, and reviewer decision without storing secrets.

## Suggested repository layout

```text
.
├── README.md
├── docs/
│   ├── architecture.md
│   └── threat-model.md
├── data/
│   └── sample-events.jsonl
├── src/
│   └── llamasoc/
├── tests/
├── .env.example
├── .gitignore
└── requirements.txt
```

## Safety and privacy

- Use synthetic events only; do not upload real employer or customer logs.
- Never commit API keys, credentials, access tokens, or model-provider secrets.
- Keep model output advisory; do not execute commands or isolate hosts based solely on an LLM response.
- Minimize personal data and redact identifiers before sending event text to any external model.
- Validate and constrain structured model output; treat event content as untrusted input to reduce prompt-injection risk.
- Do not connect this prototype to production systems without a formal security review and explicit authorization.

## Initial milestones

- [ ] Define the event schema and JSONL sample dataset.
- [ ] Implement schema validation and deterministic baseline rules.
- [ ] Add an analysis interface with structured output and uncertainty fields.
- [ ] Add unit tests for malformed events, prompt injection attempts, and missing context.
- [ ] Add audit records and a clear human-approval workflow.
- [ ] Document limitations and a reproducible local demo.

## Status

**Stage:** Project scaffold and design documentation. Implementation and test results should be reported only after they exist.

## Disclaimer

For education and authorized defensive operations only. This repository does not claim production readiness.