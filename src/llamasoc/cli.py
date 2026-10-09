"""Command-line entry point for LlamaSOC."""
import argparse
import json
from pathlib import Path
from .core import analyze_events


def main(argv=None):
    parser = argparse.ArgumentParser(description="Analyze JSONL security events locally.")
    parser.add_argument("input", type=Path, help="JSONL input file")
    parser.add_argument("--output", type=Path, help="Optional JSON report path")
    parser.add_argument("--failed-login-threshold", type=int, default=3)
    parser.add_argument("--indicator", action="append", default=[], help="Local/mock indicator; repeatable")
    args = parser.parse_args(argv)
    if not args.input.is_file():
        parser.error(f"input file does not exist: {args.input}")
    events, parse_errors = [], []
    with args.input.open(encoding="utf-8") as stream:
        for line_no, line in enumerate(stream, 1):
            if not line.strip() or line.lstrip().startswith("#"):
                continue
            try:
                value = json.loads(line)
                if not isinstance(value, dict):
                    raise ValueError("line must contain a JSON object")
                events.append(value)
            except (json.JSONDecodeError, ValueError) as exc:
                parse_errors.append({"line": str(line_no), "error": str(exc)})
    report = analyze_events(events, threat_indicators=set(args.indicator),
                            failed_login_threshold=args.failed_login_threshold)
    if parse_errors:
        report["parse_errors"] = parse_errors
        report["summary"]["events_rejected"] += len(parse_errors)
        report["summary"]["events_received"] += len(parse_errors)
    rendered = json.dumps(report, indent=2, sort_keys=True)
    if args.output:
        args.output.write_text(rendered + "\n", encoding="utf-8")
    else:
        print(rendered)
    return 1 if report["errors"] or parse_errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
