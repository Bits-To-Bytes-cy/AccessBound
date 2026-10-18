"""Automated tests for the tamper-evident evidence bundle system."""

import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519

from benchmark.evidence import (
    canonicalize_manifest,
    create_evidence_bundle,
    export_public_key_pem,
    generate_keypair,
    verify_evidence_bundle,
)


@pytest.fixture
def keypair():
    """Generate ephemeral Ed25519 keys for testing only."""
    return generate_keypair()


@pytest.fixture
def synthetic_evidence(tmp_path):
    """Create synthetic evidence files for testing."""
    evidence_src = tmp_path / "src_evidence"
    evidence_src.mkdir()

    f1 = evidence_src / "findings.json"
    f1.write_text('{"summary": {"vulnerabilities": 2}}', encoding="utf-8")

    f2 = evidence_src / "junit.xml"
    f2.write_text('<testsuite tests="4" failures="2"/>', encoding="utf-8")

    f3 = evidence_src / "nested" / "report.html"
    f3.parent.mkdir()
    f3.write_text("<html><body>Test Report</body></html>", encoding="utf-8")

    return {
        "findings.json": f1,
        "junit.xml": f2,
        "nested/report.html": f3,
    }


@pytest.fixture
def sample_bundle(tmp_path, keypair, synthetic_evidence):
    """Create a valid sample evidence bundle."""
    priv, pub = keypair
    bundle_dir = tmp_path / "test_bundle"

    tool_info = {
        "name": "overstep",
        "version": "1.7.0",
        "python_version": "3.11.9",
        "target": "http://127.0.0.1:8000",
        "mode": "read-only",
    }
    test_cases = [
        {"id": "TEST-001", "outcome": "TP", "status": 200},
        {"id": "TEST-002", "outcome": "TN", "status": 403},
    ]

    create_evidence_bundle(
        bundle_dir=bundle_dir,
        run_id="run-test-001",
        tool_info=tool_info,
        test_cases=test_cases,
        source_evidence_files=synthetic_evidence,
        private_key=priv,
        public_key=pub,
    )
    return bundle_dir, keypair


def test_valid_bundle_passes_verification(sample_bundle):
    """Requirement 1: A newly created valid bundle passes verification."""
    bundle_dir, (_, pub) = sample_bundle
    res = verify_evidence_bundle(bundle_dir)
    assert res.valid is True
    assert "signature verified" in res.message
    assert res.details["run_id"] == "run-test-001"
    assert res.details["verified_files_count"] == 3


def test_modifying_one_evidence_file_fails_verification(sample_bundle):
    """Requirement 2: Modifying one evidence file fails verification."""
    bundle_dir, _ = sample_bundle
    findings_file = bundle_dir / "evidence" / "findings.json"

    # Tamper with evidence file content
    findings_file.write_text('{"summary": {"tampered": true}}', encoding="utf-8")

    res = verify_evidence_bundle(bundle_dir)
    assert res.valid is False
    assert "Hash mismatch" in res.message
    assert "findings.json" in res.message


def test_modifying_signed_manifest_fails_verification(sample_bundle):
    """Requirement 3: Modifying signed manifest content fails verification."""
    bundle_dir, _ = sample_bundle
    manifest_file = bundle_dir / "manifest.json"

    manifest_data = json.loads(manifest_file.read_text(encoding="utf-8"))
    # Tamper with run_id inside manifest
    manifest_data["run_id"] = "tampered-run-id"
    manifest_file.write_bytes(canonicalize_manifest(manifest_data))

    res = verify_evidence_bundle(bundle_dir)
    assert res.valid is False
    assert "Digital signature verification failed" in res.message


def test_incorrect_public_key_fails_signature_verification(sample_bundle, tmp_path):
    """Requirement 4: Using an incorrect public key fails signature verification."""
    bundle_dir, _ = sample_bundle

    # Generate an unrelated keypair
    _, wrong_pub = generate_keypair()
    wrong_pub_file = tmp_path / "wrong_pub.pem"
    wrong_pub_file.write_text(export_public_key_pem(wrong_pub), encoding="utf-8")

    res = verify_evidence_bundle(bundle_dir, trusted_public_key_path=wrong_pub_file)
    assert res.valid is False
    assert "Digital signature verification failed" in res.message


def test_removing_required_file_fails_verification(sample_bundle):
    """Requirement 5: Removing a required file fails verification."""
    bundle_dir, _ = sample_bundle

    # 1. Missing evidence file
    evidence_file = bundle_dir / "evidence" / "junit.xml"
    evidence_file.unlink()
    res = verify_evidence_bundle(bundle_dir)
    assert res.valid is False
    assert "Missing evidence file" in res.message

    # 2. Missing signature file
    sig_file = bundle_dir / "signature.sig"
    sig_file.unlink()
    res = verify_evidence_bundle(bundle_dir)
    assert res.valid is False
    assert "missing required file: signature.sig" in res.message


def test_malformed_manifest_data_is_rejected(sample_bundle):
    """Requirement 6: Malformed manifest data is rejected."""
    bundle_dir, _ = sample_bundle
    manifest_file = bundle_dir / "manifest.json"

    # Case A: Invalid JSON syntax
    manifest_file.write_text("NOT_VALID_JSON{", encoding="utf-8")
    res = verify_evidence_bundle(bundle_dir)
    assert res.valid is False
    assert "Malformed manifest JSON" in res.message

    # Case B: Missing required top-level key
    manifest_file.write_text(json.dumps({"format_version": "1.0"}), encoding="utf-8")
    res = verify_evidence_bundle(bundle_dir)
    assert res.valid is False
    assert "missing required key" in res.message


def test_path_traversal_is_detected_and_rejected(sample_bundle):
    """Security check: Prevent path traversal attempts declared in manifest."""
    bundle_dir, (priv, _) = sample_bundle
    manifest_file = bundle_dir / "manifest.json"

    manifest_data = json.loads(manifest_file.read_text(encoding="utf-8"))
    manifest_data["files"]["../secret.txt"] = {"sha256": "abcdef", "size_bytes": 10}
    manifest_file.write_bytes(canonicalize_manifest(manifest_data))

    # Re-sign with valid key so signature passes and file path validation is reached
    from benchmark.evidence import sign_manifest
    sig_b64 = sign_manifest(manifest_data, priv)
    (bundle_dir / "signature.sig").write_text(sig_b64 + "\n", encoding="utf-8")

    res = verify_evidence_bundle(bundle_dir)
    assert res.valid is False
    assert "traversal" in res.message.lower()


def test_unexpected_untracked_file_is_detected(sample_bundle):
    """Integrity check: Detect untracked files added to evidence directory."""
    bundle_dir, _ = sample_bundle
    extra_file = bundle_dir / "evidence" / "untracked.txt"
    extra_file.write_text("untracked evidence file", encoding="utf-8")

    res = verify_evidence_bundle(bundle_dir)
    assert res.valid is False
    assert "Unexpected untracked file" in res.message
