"""Command-line interface for the workload identity guard."""

from __future__ import annotations

import argparse
import json

from .analyzer import analyze_documents, load_documents


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate Kubernetes workload identity before GitOps merge")
    parser.add_argument("paths", nargs="+", help="YAML file or directory")
    parser.add_argument("--provider", required=True, choices=("aws", "gcp", "azure"))
    parser.add_argument("--output", choices=("json", "text"), default="text")
    args = parser.parse_args()
    report = analyze_documents(load_documents(args.paths), args.provider)
    if args.output == "json":
        print(json.dumps(report.to_dict(), indent=2, sort_keys=True))
    else:
        print(f"Decision: {report.decision} | Score: {report.score} | Workloads: {report.resources_checked}")
        for finding in report.findings:
            print(f"[{finding.severity}] {finding.rule_id} {finding.resource}: {finding.message}")
    return 0 if report.decision == "PASS" else 2


if __name__ == "__main__":
    raise SystemExit(main())
