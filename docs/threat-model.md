# Threat model

## Assets
- Integrity of event records and evidence
- Confidentiality of log data and credentials
- Analyst decisions and auditability
- Availability of the local tool

## Trust boundaries
JSONL inputs, free-text event fields, and caller-supplied mock indicators are untrusted. Reports can contain sensitive information if users replace the supplied synthetic data with real data.

## Risks and controls
- **Malformed input:** schema validation rejects invalid events.
- **Duplicate IDs:** duplicates are rejected within an analysis run.
- **Oversized selected fields:** values longer than 2,000 characters are rejected.
- **False positives/negatives:** rules include evidence and confidence; coverage is intentionally limited.
- **Unsafe automation:** this version implements no response actions.
- **Data exposure:** sample data is synthetic and processing is local, but users must sanitize their own input/output.
- **Stale indicators:** indicators are local/mock only and must be independently validated.

## Out of scope
Production SIEM integrations, automated containment, external threat-intelligence lookups, and claims of production readiness.

Use synthetic data by default. Run only on systems you own or are explicitly authorized to assess. Review all alerts before acting.
