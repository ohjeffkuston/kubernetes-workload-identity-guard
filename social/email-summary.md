# Day 19 — Kubernetes Workload Identity Guard

This project validates Kubernetes-to-cloud identity evidence before GitOps merge. It checks dedicated ServiceAccounts, AWS/GCP/Azure identity markers, token behavior, host-network risk, and static cloud credential variables.

Deploy it read-only in pull requests, begin with REVIEW, protect policy changes, retain reports, and validate provider-side trust and least privilege independently. AI can explain findings but cannot create IAM bindings, approve, merge, or deploy.

Interview story: explain the Kubernetes/cloud-IAM boundary, why deterministic rules own enforcement, how staged rollout manages false positives, and how identity coverage, static-key findings, remediation time, and incident blast radius measure value.

Repository: https://github.com/ohjeffkuston/kubernetes-workload-identity-guard
