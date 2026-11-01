"""Deterministic workload-identity policy analysis for Kubernetes YAML."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Iterable

import yaml

WORKLOAD_KINDS = {"Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob"}
STATIC_CREDENTIAL_ENV = {
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN",
    "AZURE_CLIENT_SECRET",
    "GOOGLE_APPLICATION_CREDENTIALS",
}
PROVIDER_ANNOTATIONS = {
    "aws": ("eks.amazonaws.com/role-arn", "platform.example.com/eks-pod-identity-association"),
    "gcp": ("iam.gke.io/gcp-service-account",),
    "azure": ("azure.workload.identity/client-id",),
}


@dataclass(frozen=True)
class Finding:
    rule_id: str
    severity: str
    resource: str
    message: str
    remediation: str


@dataclass(frozen=True)
class AnalysisReport:
    decision: str
    score: int
    resources_checked: int
    findings: tuple[Finding, ...]
    advisory_ai_prompt: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "decision": self.decision,
            "score": self.score,
            "resources_checked": self.resources_checked,
            "findings": [asdict(item) for item in self.findings],
            "advisory_ai_prompt": self.advisory_ai_prompt,
        }


def load_documents(paths: Iterable[str | Path]) -> list[dict[str, Any]]:
    documents: list[dict[str, Any]] = []
    for raw_path in paths:
        path = Path(raw_path)
        for candidate in sorted(path.rglob("*.y*ml")) if path.is_dir() else [path]:
            with candidate.open("r", encoding="utf-8") as handle:
                for document in yaml.safe_load_all(handle):
                    if isinstance(document, dict):
                        documents.append(document)
    return documents


def _resource_id(document: dict[str, Any]) -> str:
    metadata = document.get("metadata") or {}
    namespace = metadata.get("namespace", "default")
    return f"{document.get('kind', 'Unknown')}/{namespace}/{metadata.get('name', 'unnamed')}"


def _pod_spec(document: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    kind = document.get("kind")
    spec = document.get("spec") or {}
    if kind == "CronJob":
        template = (((spec.get("jobTemplate") or {}).get("spec") or {}).get("template") or {})
    elif kind in {"Deployment", "StatefulSet", "DaemonSet", "Job"}:
        template = spec.get("template") or {}
    else:
        return {}, {}
    return template.get("metadata") or {}, template.get("spec") or {}


def _finding(rule: str, severity: str, resource: str, message: str, remediation: str) -> Finding:
    return Finding(rule, severity, resource, message, remediation)


def analyze_documents(documents: list[dict[str, Any]], provider: str) -> AnalysisReport:
    provider = provider.lower()
    if provider not in PROVIDER_ANNOTATIONS:
        raise ValueError(f"unsupported provider: {provider}")

    service_accounts: dict[tuple[str, str], dict[str, Any]] = {}
    workloads: list[dict[str, Any]] = []
    for document in documents:
        kind = document.get("kind")
        metadata = document.get("metadata") or {}
        namespace = metadata.get("namespace", "default")
        name = metadata.get("name", "unnamed")
        if kind == "ServiceAccount":
            service_accounts[(namespace, name)] = document
        elif kind in WORKLOAD_KINDS:
            workloads.append(document)

    findings: list[Finding] = []
    for workload in workloads:
        resource = _resource_id(workload)
        metadata = workload.get("metadata") or {}
        namespace = metadata.get("namespace", "default")
        pod_metadata, pod_spec = _pod_spec(workload)
        service_account_name = pod_spec.get("serviceAccountName")

        if not service_account_name:
            findings.append(_finding(
                "WI001", "BLOCK", resource,
                "Workload does not declare serviceAccountName.",
                "Create a dedicated ServiceAccount and reference it explicitly.",
            ))
            continue
        if service_account_name == "default":
            findings.append(_finding(
                "WI002", "BLOCK", resource,
                "Workload uses the namespace default ServiceAccount.",
                "Use a dedicated least-privilege ServiceAccount per application.",
            ))
            continue

        service_account = service_accounts.get((namespace, service_account_name))
        if service_account is None:
            findings.append(_finding(
                "WI003", "BLOCK", resource,
                f"Referenced ServiceAccount {service_account_name!r} is absent from the review bundle.",
                "Include the ServiceAccount in the GitOps change so identity evidence is reviewable.",
            ))
            continue

        annotations = (service_account.get("metadata") or {}).get("annotations") or {}
        accepted = PROVIDER_ANNOTATIONS[provider]
        if not any(str(annotations.get(key, "")).strip() for key in accepted):
            findings.append(_finding(
                "WI004", "BLOCK", resource,
                f"ServiceAccount lacks an approved {provider.upper()} workload-identity binding marker.",
                f"Configure workload identity and add one approved annotation: {', '.join(accepted)}.",
            ))

        requires_api = str((pod_metadata.get("annotations") or {}).get(
            "platform.example.com/requires-kubernetes-api", "false"
        )).lower() == "true"
        automount = pod_spec.get("automountServiceAccountToken", service_account.get("automountServiceAccountToken"))
        if not requires_api and automount is not False:
            findings.append(_finding(
                "WI005", "REVIEW", resource,
                "Kubernetes API token automount is not explicitly disabled.",
                "Set automountServiceAccountToken: false when the workload does not call the Kubernetes API.",
            ))

        if provider == "azure":
            labels = pod_metadata.get("labels") or {}
            if str(labels.get("azure.workload.identity/use", "")).lower() != "true":
                findings.append(_finding(
                    "WI006", "BLOCK", resource,
                    "Azure workload identity opt-in label is missing from the Pod template.",
                    "Set azure.workload.identity/use: 'true' on the Pod template.",
                ))

        if pod_spec.get("hostNetwork") is True:
            findings.append(_finding(
                "WI007", "REVIEW", resource,
                "hostNetwork is enabled, increasing node metadata credential exposure risk.",
                "Avoid host networking or document IMDS isolation and network controls.",
            ))

        containers = list(pod_spec.get("containers") or []) + list(pod_spec.get("initContainers") or [])
        for container in containers:
            for env in container.get("env") or []:
                name = env.get("name")
                if name in STATIC_CREDENTIAL_ENV:
                    findings.append(_finding(
                        "WI008", "BLOCK", resource,
                        f"Container {container.get('name', 'unnamed')!r} declares static credential variable {name}.",
                        "Remove long-lived cloud credentials and use the provider workload-identity chain.",
                    ))

        for volume in pod_spec.get("volumes") or []:
            projected = volume.get("projected") or {}
            for source in projected.get("sources") or []:
                token = source.get("serviceAccountToken") or {}
                if token:
                    expiration = int(token.get("expirationSeconds", 3600))
                    audience = str(token.get("audience", "")).strip()
                    if expiration > 3600 or not audience:
                        findings.append(_finding(
                            "WI009", "REVIEW", resource,
                            "Projected service-account token lacks a bounded audience or exceeds one hour.",
                            "Set an explicit audience and expirationSeconds no greater than 3600.",
                        ))

    block_count = sum(item.severity == "BLOCK" for item in findings)
    review_count = sum(item.severity == "REVIEW" for item in findings)
    decision = "BLOCK" if block_count else "REVIEW" if review_count else "PASS"
    score = max(0, 100 - block_count * 25 - review_count * 10)
    prompt = (
        "Explain the findings and propose a minimal manifest patch. Do not change policy thresholds, "
        "approve a merge, create cloud IAM bindings, or claim the deployment is safe."
    )
    return AnalysisReport(decision, score, len(workloads), tuple(findings), prompt)
