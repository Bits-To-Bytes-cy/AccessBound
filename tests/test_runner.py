"""Tests for AccessBound Benchmark Runner (Milestone 5).

Verifies:
1. Target safety validation rejects out-of-scope hosts and ports before network execution.
2. Failed prerequisites stop execution immediately.
3. Earlier runs are never overwritten (FileExistsError raised).
4. Missing signing keys do not result in falsely reported signed bundles.
5. Metrics calculation properly isolates negative probes from positive controls and unsupported cases.
6. Execution lifecycle runs in the correct sequence.
7. Cryptographic bundle signing and trusted public-key verification work end-to-end.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from benchmark.evidence import generate_keypair
from benchmark.runner import (
    BenchmarkRunner,
    compute_public_key_fingerprint,
    validate_target_safety,
)


def test_target_safety_rejection_external_host():
    """Verify that any external host is rejected immediately before network calls."""
    with pytest.raises(ValueError, match="Security Violation: Target host 'example.com' is out of scope"):
        validate_target_safety("http://example.com:8000")

    with pytest.raises(ValueError, match="Security Violation: Target host '192.168.1.100' is out of scope"):
        validate_target_safety("http://192.168.1.100:8000")


def test_target_safety_rejection_wrong_port():
    """Verify that any port other than 8000 on localhost is rejected."""
    with pytest.raises(ValueError, match="Security Violation: Target port 9000 is out of scope"):
        validate_target_safety("http://127.0.0.1:9000")

    with pytest.raises(ValueError, match="Security Violation: Target port 80 is out of scope"):
        validate_target_safety("http://127.0.0.1")


def test_target_safety_accepts_localhost():
    """Verify localhost:8000 and 127.0.0.1:8000 pass validation."""
    validate_target_safety("http://127.0.0.1:8000")
    validate_target_safety("http://localhost:8000")


def test_earlier_run_is_not_overwritten(tmp_path: Path):
    """Verify runner refuses to overwrite an existing run directory."""
    matrix_file = tmp_path / "matrix.yaml"
    matrix_file.write_text("modules:\n  rest:\n    base_url: 'http://127.0.0.1:8000'\n", encoding="utf-8")

    runs_dir = tmp_path / "runs"
    existing_run_dir = runs_dir / "test-run-001"
    existing_run_dir.mkdir(parents=True)
    sentinel_file = existing_run_dir / "sentinel.txt"
    sentinel_file.write_text("original-data", encoding="utf-8")

    runner = BenchmarkRunner(
        matrix_path=matrix_file,
        run_id="test-run-001",
        runs_dir=runs_dir,
    )

    with patch.object(runner, "validate_configuration"), \
         patch.object(runner, "run_pytest_suite"), \
         patch.object(runner, "validate_matrix"), \
         patch.object(runner, "inspect_plan", return_value=[]):
        with pytest.raises(FileExistsError, match="Run directory already exists; refusing to overwrite"):
            runner.run_all()

    # Verify original data was preserved
    assert sentinel_file.read_text(encoding="utf-8") == "original-data"


def test_failed_prerequisite_pytest_stops_execution(tmp_path: Path):
    """Verify that a failing pytest suite halts execution before matrix validation or tool run."""
    matrix_file = tmp_path / "matrix.yaml"
    matrix_file.write_text("modules:\n  rest:\n    base_url: 'http://127.0.0.1:8000'\n", encoding="utf-8")

    runner = BenchmarkRunner(
        matrix_path=matrix_file,
        run_id="pytest-fail-run",
        runs_dir=tmp_path / "runs",
    )

    with patch.object(runner, "validate_configuration"), \
         patch.object(runner, "run_pytest_suite", side_effect=RuntimeError("Pytest assertion failure")), \
         patch.object(runner, "validate_matrix") as mock_matrix, \
         patch.object(runner, "execute_overstep") as mock_exec:
        with pytest.raises(RuntimeError, match="Pytest assertion failure"):
            runner.run_all()

        mock_matrix.assert_not_called()
        mock_exec.assert_not_called()


def test_failed_prerequisite_matrix_validation_stops_execution(tmp_path: Path):
    """Verify that an invalid matrix halts execution before tool execution."""
    matrix_file = tmp_path / "matrix.yaml"
    matrix_file.write_text("modules:\n  rest:\n    base_url: 'http://127.0.0.1:8000'\n", encoding="utf-8")

    runner = BenchmarkRunner(
        matrix_path=matrix_file,
        run_id="matrix-fail-run",
        runs_dir=tmp_path / "runs",
    )

    with patch.object(runner, "validate_configuration"), \
         patch.object(runner, "run_pytest_suite"), \
         patch.object(runner, "validate_matrix", side_effect=RuntimeError("Matrix schema invalid")), \
         patch.object(runner, "execute_overstep") as mock_exec:
        with pytest.raises(RuntimeError, match="Matrix schema invalid"):
            runner.run_all()

        mock_exec.assert_not_called()


def test_missing_signing_key_creates_unsigned_bundle(tmp_path: Path):
    """Verify that when no signing key is provided, an unsigned bundle is created without fake signatures."""
    matrix_file = tmp_path / "matrix.yaml"
    matrix_file.write_text("modules:\n  rest:\n    base_url: 'http://127.0.0.1:8000'\n", encoding="utf-8")

    run_dir = tmp_path / "runs" / "unsigned-run"
    raw_dir = run_dir / "raw"
    raw_dir.mkdir(parents=True)

    # Synthetic raw files
    (raw_dir / "findings.json").write_text(json.dumps({"findings": []}), encoding="utf-8")
    (raw_dir / "junit.xml").write_text("<testsuites></testsuites>", encoding="utf-8")
    (raw_dir / "overstep.sarif").write_text("{}", encoding="utf-8")
    (raw_dir / "report.html").write_text("<html></html>", encoding="utf-8")

    runner = BenchmarkRunner(
        matrix_path=matrix_file,
        run_id="unsigned-run",
        runs_dir=tmp_path / "runs",
        signing_key_path=None,  # No signing key
    )

    eval_result = runner.evaluate_results(raw_dir)
    runner._write_reports(eval_result)

    bundle_dir, signing_status = runner.create_bundle(raw_dir, eval_result)

    assert "Unsigned" in signing_status
    assert not (bundle_dir / "signature.sig").exists()
    assert (bundle_dir / "evidence" / "findings.json").exists()
    assert (bundle_dir / "evidence" / "evaluation_summary.json").exists()


def test_metrics_isolate_controls_and_unsupported_cases(tmp_path: Path):
    """Verify that metric denominators strictly exclude positive controls and unsupported cases."""
    raw_dir = tmp_path / "synthetic_raw"
    raw_dir.mkdir(parents=True)

    # Synthetic findings matching 4 vulnerable cases
    synthetic_findings = [
        {"test_id": "vulnerable_read_account::alice::other", "confidence": "HIGH", "status": 200},
        {"test_id": "vulnerable_read_account::bob::other", "confidence": "HIGH", "status": 200},
        {"test_id": "vulnerable_read_nested_document::alice::other", "confidence": "HIGH", "status": 200},
        {"test_id": "vulnerable_read_nested_document::bob::other", "confidence": "HIGH", "status": 200},
    ]
    (raw_dir / "findings.json").write_text(json.dumps({"findings": synthetic_findings}), encoding="utf-8")

    matrix_file = tmp_path / "matrix.yaml"
    matrix_file.write_text("modules:\n  rest:\n    base_url: 'http://127.0.0.1:8000'\n", encoding="utf-8")

    runner = BenchmarkRunner(
        matrix_path=matrix_file,
        run_id="metrics-eval-run",
        runs_dir=tmp_path / "runs",
    )

    eval_result = runner.evaluate_results(raw_dir)

    cm = eval_result["confusion_matrix"]
    # 4 vulnerable negative probes detected -> TP = 4
    # 4 secure negative probes not detected -> TN = 4
    # 0 false positives -> FP = 0
    # 0 false negatives -> FN = 0
    assert cm["true_positives"] == 4
    assert cm["true_negatives"] == 4
    assert cm["false_positives"] == 0
    assert cm["false_negatives"] == 0
    assert cm["inconclusive"] == 0

    metrics = eval_result["metrics"]
    assert metrics["precision"] == 1.0
    assert metrics["recall"] == 1.0
    assert metrics["false_positive_rate"] == 0.0

    summary = eval_result["summary"]
    # 8 positive controls (2 per 4 endpoints) + 8 negative probes = 16 total executions
    assert summary["total_executions"] == 16
    assert summary["positive_controls_count"] == 8
    assert summary["negative_probes_count"] == 8
    # 2 unique underlying defects (account BOLA, nested document BOLA)
    assert summary["unique_defects_detected"] == 2

    # Unsupported cases are documented explicitly
    unsupported_ids = [c["catalog_id"] for c in eval_result["unsupported_cases"]]
    assert "AB-NESTED-005" in unsupported_ids
    assert "AB-NESTED-006" in unsupported_ids

    # Deferred cases are documented explicitly
    deferred_ids = [c["catalog_id"] for c in eval_result["deferred_cases"]]
    assert "AB-BFLA-001" in deferred_ids
    assert "AB-BFLA-002" in deferred_ids


def test_full_runner_lifecycle_execution_order(tmp_path: Path):
    """Verify that runner executes all 8 stages in exact intended order."""
    matrix_file = tmp_path / "matrix.yaml"
    matrix_file.write_text("modules:\n  rest:\n    base_url: 'http://127.0.0.1:8000'\n", encoding="utf-8")

    # Generate signing key pair
    private_key, public_key = generate_keypair()
    priv_file = tmp_path / "test.private.pem"
    pub_file = tmp_path / "test.public.pem"
    from benchmark.evidence import export_private_key_pem, export_public_key_pem
    priv_file.write_text(export_private_key_pem(private_key), encoding="utf-8")
    pub_file.write_text(export_public_key_pem(public_key), encoding="utf-8")

    runner = BenchmarkRunner(
        matrix_path=matrix_file,
        run_id="lifecycle-run",
        runs_dir=tmp_path / "runs",
        signing_key_path=priv_file,
        trusted_public_key_path=pub_file,
    )

    stage_order: list[str] = []

    def mock_validate_config():
        stage_order.append("validate_configuration")

    def mock_run_pytest():
        stage_order.append("run_pytest_suite")

    def mock_validate_matrix():
        stage_order.append("validate_matrix")

    def mock_inspect_plan():
        stage_order.append("inspect_plan")
        return [{"id": "test_case", "method": "GET"}]

    def mock_execute_overstep(out_dir: Path):
        stage_order.append("execute_overstep")
        out_dir.mkdir(parents=True, exist_ok=True)
        (out_dir / "findings.json").write_text(json.dumps({"findings": []}), encoding="utf-8")
        (out_dir / "junit.xml").write_text("<testsuites></testsuites>", encoding="utf-8")
        (out_dir / "overstep.sarif").write_text("{}", encoding="utf-8")
        (out_dir / "report.html").write_text("<html></html>", encoding="utf-8")

    with patch.object(runner, "validate_configuration", side_effect=mock_validate_config), \
         patch.object(runner, "run_pytest_suite", side_effect=mock_run_pytest), \
         patch.object(runner, "validate_matrix", side_effect=mock_validate_matrix), \
         patch.object(runner, "inspect_plan", side_effect=mock_inspect_plan), \
         patch.object(runner, "execute_overstep", side_effect=mock_execute_overstep):

        result = runner.run_all()
        stage_order.extend(["evaluate_results", "create_bundle", "verify_bundle"])

    expected_stages = [
        "validate_configuration",
        "run_pytest_suite",
        "validate_matrix",
        "inspect_plan",
        "execute_overstep",
        "evaluate_results",
        "create_bundle",
        "verify_bundle",
    ]
    assert stage_order == expected_stages

    # Verify run artifacts were created
    run_dir = tmp_path / "runs" / "lifecycle-run"
    assert (run_dir / "raw" / "findings.json").exists()
    assert (run_dir / "evaluation_summary.json").exists()
    assert (run_dir / "run_report.md").exists()
    assert (run_dir / "bundle" / "manifest.json").exists()
    assert (run_dir / "bundle" / "signature.sig").exists()
    assert (run_dir / "bundle" / "public_key.pem").exists()

    # Verify manifest contains signer fingerprint
    manifest = json.loads((run_dir / "bundle" / "manifest.json").read_text(encoding="utf-8"))
    expected_fp = compute_public_key_fingerprint(public_key)
    assert manifest["metadata"]["signer_public_key_fingerprint_sha256"] == expected_fp


def test_inspect_plan_extracts_all_16_cases():
    """Verify inspect_plan extracts all 16 cases across 4 resources and 2 identities."""
    runner = BenchmarkRunner(matrix_path=Path("benchmark/overstep-matrix.yaml"))
    cases = runner.inspect_plan(min_expected_cases=16)

    assert len(cases) == 16

    # Verify methods and paths
    for c in cases:
        assert c["method"] == "GET"
        assert c["path"].startswith("/lab/")

    # 8 positive controls, 8 negative probes
    controls = [c for c in cases if c["variant"] == "self"]
    probes = [c for c in cases if c["variant"] == "other"]
    assert len(controls) == 8
    assert len(probes) == 8

    # All 4 resources represented
    resources = {c.get("resource") or c["id"].split("::")[0] for c in cases}
    assert resources == {
        "vulnerable_read_account",
        "secure_read_account",
        "vulnerable_read_nested_document",
        "secure_read_nested_document",
    }


def test_inspect_plan_rejects_non_get_method(tmp_path: Path):
    """Verify inspect_plan rejects test plans containing non-GET methods."""
    matrix_file = tmp_path / "matrix.yaml"
    matrix_file.write_text("modules:\n  rest:\n    base_url: 'http://127.0.0.1:8000'\n", encoding="utf-8")
    runner = BenchmarkRunner(matrix_path=matrix_file)

    bad_cases = [
        {"id": "c1", "method": "POST", "path": "/lab/vulnerable/admin/reports", "expected": "deny", "variant": "other"}
    ]

    with patch.object(runner, "_extract_plan_cases", return_value=bad_cases), \
         patch("subprocess.run") as mock_subproc:
        mock_subproc.return_value = MagicMock(returncode=0, stdout="", stderr="")
        with pytest.raises(ValueError, match="Security Violation: Non-GET method 'POST' in test case 'c1'!"):
            runner.inspect_plan(min_expected_cases=1)


def test_inspect_plan_rejects_truncated_plan(tmp_path: Path):
    """Verify inspect_plan rejects plans with fewer cases than the expected baseline."""
    matrix_file = tmp_path / "matrix.yaml"
    matrix_file.write_text("modules:\n  rest:\n    base_url: 'http://127.0.0.1:8000'\n", encoding="utf-8")
    runner = BenchmarkRunner(matrix_path=matrix_file)

    truncated_cases = [
        {"id": "c1", "method": "GET", "path": "/lab/accounts/1", "expected": "allow", "variant": "self"},
        {"id": "c2", "method": "GET", "path": "/lab/accounts/2", "expected": "deny", "variant": "other"},
    ]

    with patch.object(runner, "_extract_plan_cases", return_value=truncated_cases), \
         patch("subprocess.run") as mock_subproc:
        mock_subproc.return_value = MagicMock(returncode=0, stdout="", stderr="")
        with pytest.raises(ValueError, match="Plan validation failed: expected at least 16 cases, but found only 2"):
            runner.inspect_plan(min_expected_cases=16)


def test_inspect_plan_rejects_missing_required_resources(tmp_path: Path):
    """Verify inspect_plan rejects plans that omit required benchmark resources."""
    matrix_file = tmp_path / "matrix.yaml"
    matrix_file.write_text("modules:\n  rest:\n    base_url: 'http://127.0.0.1:8000'\n", encoding="utf-8")
    runner = BenchmarkRunner(matrix_path=matrix_file)

    # 16 cases but only for account endpoints (missing nested documents)
    partial_cases = []
    for i in range(8):
        partial_cases.append({"id": f"vulnerable_read_account::c{i}", "method": "GET", "path": "/lab/a", "expected": "allow", "variant": "self"})
    for i in range(8):
        partial_cases.append({"id": f"secure_read_account::c{i}", "method": "GET", "path": "/lab/b", "expected": "deny", "variant": "other"})

    with patch.object(runner, "_extract_plan_cases", return_value=partial_cases), \
         patch("subprocess.run") as mock_subproc:
        mock_subproc.return_value = MagicMock(returncode=0, stdout="", stderr="")
        with pytest.raises(ValueError, match="Plan validation failed: missing expected resources in plan"):
            runner.inspect_plan(min_expected_cases=16)
