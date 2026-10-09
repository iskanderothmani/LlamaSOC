# Architecture

This first version is a local deterministic triage tool. It makes no network requests, calls no external AI model, and executes no response actions.

1. **Ingest:** read JSON Lines events.
2. **Validate:** enforce required fields, supported event types, timezone-aware timestamps, bounded scalar fields, and valid IP syntax.
3. **Detect:** correlate repeated authentication failures followed by success; flag selected privileged-access changes; compare network destinations against caller-supplied mock indicators; flag large outbound-byte counts for review.
4. **Report:** output JSON containing evidence, severity, confidence, recommendations, and an explicit human-review requirement.
5. **Test:** unit tests exercise validation and representative detection rules; GitHub Actions runs the suite.

Rules are transparent triage heuristics, not proof of compromise. Tune and validate them against authorized telemetry before operational use.

## Future AI adapter

An optional LLM may summarize minimized event context, but should be isolated behind an interface, validate structured output, treat log content as untrusted, avoid sending sensitive identifiers externally, and never execute model-proposed actions.
