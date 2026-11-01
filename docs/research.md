# Demand validation

Checked: 2026-11-01 (America/Detroit)

## Production demand

Current platform, infrastructure-security, and AI-infrastructure roles repeatedly combine Kubernetes, cloud IAM, identity, GitOps, Terraform, observability, and secure multi-cloud operations. This project turns that recurring requirement into demonstrable engineering evidence: a deterministic pre-merge control for workload identity rather than a generic AI demo.

Live postings reviewed:

- Deepgram, Platform Engineer — AI/ML Infrastructure: Kubernetes, Terraform, remote U.S., $136K–$240K base. https://jobs.ashbyhq.com/Deepgram/f424ef6a-c27f-4984-9e77-40a1ad16ae28/
- P-1 AI, Platform Engineer: Kubernetes, multi-cloud, identity, encryption, GitOps, and AI-assisted engineering; remote U.S./Canada, $200K–$275K. https://jobs.ashbyhq.com/p-1%20ai/d34e1c45-e51d-47bf-a0ee-064e6ca3467b
- OpenRouter, Software Engineer — Identity Platform: identity and authorization for AI infrastructure; remote U.S., $215K–$285K. https://jobs.ashbyhq.com/openrouter/8930eaba-071f-4b08-b598-306cb691b0d4
- OpenAI, Software Engineer — Infrastructure Security: remote U.S., infrastructure security, $266K–$445K. https://jobs.ashbyhq.com/openai/98ad9beb-4f91-496c-bd16-ac0b2a8d5bb2

These postings validate the problem domain, not candidate fit or application eligibility.

## Authoritative technical sources

- Kubernetes ServiceAccounts: dedicated identities, short-lived projected tokens, and disabling unnecessary automount. https://kubernetes.io/docs/concepts/security/service-accounts/
- Amazon EKS IAM best practices: dedicated service accounts, Pod Identity/IRSA, ABAC conditions, and disabling unnecessary token automount. https://docs.aws.amazon.com/eks/latest/best-practices/identity-and-access-management.html
- Amazon EKS Pod Identity: temporary credentials and service-account-to-role associations. https://docs.aws.amazon.com/eks/latest/userguide/pod-identities.html
- GKE service accounts and Workload Identity Federation: dedicated minimally privileged service accounts and Pod-to-cloud identity federation. https://docs.cloud.google.com/kubernetes-engine/docs/how-to/service-accounts

## Design conclusion

The guard enforces only facts visible in the GitOps bundle. Provider-side IAM policy depth remains outside its authority and must be validated separately. AI may explain findings or draft a patch, but deterministic rules own the decision and humans own IAM changes and merge approval.
