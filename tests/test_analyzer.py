from pathlib import Path

import pytest

from workload_identity_guard.analyzer import analyze_documents, load_documents


SAMPLES = Path(__file__).parents[1] / "samples"


def test_compliant_aws_bundle_passes():
    report = analyze_documents(load_documents([SAMPLES / "compliant-aws.yaml"]), "aws")
    assert report.decision == "PASS"
    assert report.score == 100
    assert report.resources_checked == 1


def test_default_service_account_blocks():
    documents = [{"apiVersion": "apps/v1", "kind": "Deployment", "metadata": {"name": "api"},
                  "spec": {"template": {"metadata": {}, "spec": {"serviceAccountName": "default"}}}}]
    report = analyze_documents(documents, "aws")
    assert report.decision == "BLOCK"
    assert report.findings[0].rule_id == "WI002"


def test_missing_service_account_name_blocks():
    documents = [{"apiVersion": "batch/v1", "kind": "Job", "metadata": {"name": "worker"},
                  "spec": {"template": {"metadata": {}, "spec": {}}}}]
    assert analyze_documents(documents, "gcp").findings[0].rule_id == "WI001"


def test_missing_identity_annotation_blocks():
    documents = load_documents([SAMPLES / "compliant-aws.yaml"])
    documents[0]["metadata"]["annotations"] = {}
    report = analyze_documents(documents, "aws")
    assert any(item.rule_id == "WI004" for item in report.findings)


def test_static_credentials_block():
    documents = load_documents([SAMPLES / "compliant-aws.yaml"])
    container = documents[1]["spec"]["template"]["spec"]["containers"][0]
    container["env"] = [{"name": "AWS_SECRET_ACCESS_KEY", "valueFrom": {"secretKeyRef": {"name": "aws", "key": "secret"}}}]
    report = analyze_documents(documents, "aws")
    assert any(item.rule_id == "WI008" for item in report.findings)


def test_unnecessary_automount_requires_review():
    documents = load_documents([SAMPLES / "compliant-aws.yaml"])
    del documents[1]["spec"]["template"]["spec"]["automountServiceAccountToken"]
    del documents[0]["automountServiceAccountToken"]
    report = analyze_documents(documents, "aws")
    assert report.decision == "REVIEW"
    assert any(item.rule_id == "WI005" for item in report.findings)


def test_azure_requires_opt_in_label():
    documents = load_documents([SAMPLES / "compliant-azure.yaml"])
    del documents[1]["spec"]["template"]["metadata"]["labels"]
    report = analyze_documents(documents, "azure")
    assert any(item.rule_id == "WI006" for item in report.findings)


def test_host_network_requires_review():
    documents = load_documents([SAMPLES / "compliant-aws.yaml"])
    documents[1]["spec"]["template"]["spec"]["hostNetwork"] = True
    assert any(item.rule_id == "WI007" for item in analyze_documents(documents, "aws").findings)


def test_long_lived_projected_token_requires_review():
    documents = load_documents([SAMPLES / "compliant-aws.yaml"])
    documents[1]["spec"]["template"]["spec"]["volumes"] = [{
        "name": "token", "projected": {"sources": [{"serviceAccountToken": {"expirationSeconds": 7200}}]}
    }]
    assert any(item.rule_id == "WI009" for item in analyze_documents(documents, "aws").findings)


def test_unsupported_provider_fails_closed():
    with pytest.raises(ValueError):
        analyze_documents([], "other")
