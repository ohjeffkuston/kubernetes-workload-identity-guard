# Deployment and operations guide

## Safe rollout

1. Run the CLI read-only against changed YAML in pull requests.
2. Start with `REVIEW` findings non-blocking while measuring false positives.
3. Protect `policy/workload-identity-policy.json` with code owners and branch rules.
4. Promote `BLOCK` findings to required CI only after service-account and provider-binding inventory is complete.
5. Validate cloud-side IAM separately: trust policy, audience, subject/namespace conditions, and least-privilege permissions.
6. Retain JSON reports as CI artifacts for audit and trend analysis.

## Example

```bash
python -m pip install -e .
workload-identity-guard samples/compliant-aws.yaml --provider aws --output json
```

Docker:

```bash
docker build -t workload-identity-guard:local .
docker run --rm -v "$PWD:/repo:ro" workload-identity-guard:local /repo/manifests --provider aws
```

## Security boundaries

- The tool never calls a cloud API or mutates a cluster.
- YAML is parsed locally; reports should avoid secret values.
- Static credential variable names are blocked even when sourced from a Kubernetes Secret.
- Provider annotations prove declared intent, not that the external IAM binding is correct.
- AI output is untrusted advisory text. It cannot change policy, create IAM bindings, approve, merge, or deploy.
- Pin the container image and GitHub Actions dependencies in stricter production environments.

## Failure modes

- Missing ServiceAccount manifests fail closed because identity evidence is incomplete.
- Unsupported cloud providers fail closed.
- Out-of-band EKS Pod Identity associations require a reviewable marker; verify the real association independently.
- Custom admission webhooks may inject identity fields after merge; include their generated contract or policy evidence in review.
- Multi-cluster names are not globally unique; cloud-side trust policies must include cluster, namespace, and service-account context.

## Measurable outcomes

- Percentage of workloads using dedicated service accounts.
- Percentage of cloud-enabled workloads using federated identity rather than static keys.
- Static credential findings per 100 changes.
- Median remediation time for identity-policy failures.
- False-positive rate and approved policy exceptions.
- Identity-related incident rate and blast-radius reduction.
