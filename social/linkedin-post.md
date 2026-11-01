Imagine an AI inference workload reaching production with a default Kubernetes ServiceAccount and static cloud keys mounted from a Secret.

The deployment may work, but one compromised Pod can inherit a much larger blast radius than the application needs. For platform teams, workload identity is not only an IAM configuration detail; it is part of release safety, auditability, and incident containment.

The security issues are familiar: default identities, unnecessary token mounts, long-lived credentials, incomplete cloud bindings, and provider-specific settings that are difficult to review consistently.

I built Kubernetes Workload Identity Guard to move those checks into the GitOps pull request:

- Correlates Deployments, Jobs, and other workloads with dedicated ServiceAccounts.
- Validates workload-identity evidence for AWS, GCP, and Azure.
- Blocks static cloud credential variables and missing identity bindings.
- Reviews token automount, projected-token lifetime, audience, and host-network risk.
- Produces deterministic PASS, REVIEW, or BLOCK decisions while keeping AI remediation advisory only.

What makes this useful is the control boundary: AI can explain a finding or draft a patch, but it cannot change policy, create IAM bindings, approve a merge, or deploy. The result is testable policy-as-code with a human-controlled path to production.

Architecture:
https://raw.githubusercontent.com/ohjeffkuston/kubernetes-workload-identity-guard/main/docs/architecture.png

Project:
https://github.com/ohjeffkuston/kubernetes-workload-identity-guard

How does your platform team verify workload identity before a Kubernetes change reaches production?
