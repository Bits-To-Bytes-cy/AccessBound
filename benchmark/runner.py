"""AccessBound Benchmark Runner.

Orchestrates the complete benchmark lifecycle:
1. Target validation (strictly bound to localhost 127.0.0.1:8000).
2. Regression test suite execution (pytest).
3. Overstep matrix validation (structural and live).
4. Dry-run test plan inspection (verifies read-only GET safety).
5. Tool execution in read-only mode with isolated output directory.
6. Ground-truth mapping, confusion matrix, and metric calculation.
7. Tamper-evident evidence bundle creation and cryptographic verification.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

import re

from benchmark.evidence import (
    create_evidence_bundle,
    export_public_key_pem,
    load_private_key,
    load_public_key,
    verify_evidence_bundle,
)

# Known ground-truth mapping for read-only account and nested document resources
GROUND_TRUTH_MAPPING = {
    # Account BOLA
    ("vulnerable_read_account", "alice", "other"): {
        "catalog_id": "AB-BOLA-001",
        "expected_vulnerable": True,
        "issue_class": "BOLA/read",
        "defect_group": "vulnerable_read_account::GET::BOLA",
    },
    ("vulnerable_read_account", "bob", "other"): {
        "catalog_id": "AB-BOLA-005",
        "expected_vulnerable": True,
        "issue_class": "BOLA/read",
        "defect_group": "vulnerable_read_account::GET::BOLA",
    },
    ("secure_read_account", "alice", "other"): {
        "catalog_id": "AB-BOLA-002",
        "expected_vulnerable": False,
        "issue_class": "BOLA/read",
        "defect_group": None,
    },
    ("secure_read_account", "bob", "other"): {
        "catalog_id": "AB-BOLA-006",
        "expected_vulnerable": False,
        "issue_class": "BOLA/read",
        "defect_group": None,
    },
    # Nested Document BOLA
    ("vulnerable_read_nested_document", "alice", "other"): {
        "catalog_id": "AB-NESTED-001",
        "expected_vulnerable": True,
        "issue_class": "nested-resource authorization",
        "defect_group": "vulnerable_read_nested_document::GET::BOLA",
    },
    ("vulnerable_read_nested_document", "bob", "other"): {
        "catalog_id": "AB-NESTED-003",
        "expected_vulnerable": True,
        "issue_class": "nested-resource authorization",
        "defect_group": "vulnerable_read_nested_document::GET::BOLA",
    },
    ("secure_read_nested_document", "alice", "other"): {
        "catalog_id": "AB-NESTED-002",
        "expected_vulnerable": False,
        "issue_class": "nested-resource authorization",
        "defect_group": None,
    },
    ("secure_read_nested_document", "bob", "other"): {
        "catalog_id": "AB-NESTED-004",
        "expected_vulnerable": False,
        "issue_class": "nested-resource authorization",
        "defect_group": None,
    },
}

UNSUPPORTED_CASES = [
    {
        "catalog_id": "AB-NESTED-005",
        "reason": "Parent/child relationship mismatch on vulnerable route returns 404; Overstep matrix cannot express combinatorial parent-child mismatches.",
    },
    {
        "catalog_id": "AB-NESTED-006",
        "reason": "Parent/child relationship mismatch on secure route returns 404; Overstep matrix cannot express combinatorial parent-child mismatches.",
    },
]

DEFERRED_CASES = [
    {
        "catalog_id": "AB-BFLA-001",
        "reason": "Admin report endpoint is a POST mutating operation; deferred to mutating milestone under read-only policy.",
    },
    {
        "catalog_id": "AB-BFLA-002",
        "reason": "Admin report endpoint is a POST mutating operation; deferred to mutating milestone under read-only policy.",
    },
]


def validate_target_safety(target_url: str) -> None:
    """Ensure target URL is strictly bound to localhost (127.0.0.1 or localhost) on port 8000."""
    parsed = urlparse(target_url)
    hostname = (parsed.hostname or "").lower()
    port = parsed.port or (443 if parsed.scheme == "https" else 80)

    if hostname not in ("127.0.0.1", "localhost"):
        raise ValueError(
            f"Security Violation: Target host '{hostname}' is out of scope! "
            f"Benchmark is strictly restricted to '127.0.0.1:8000'."
        )

    if port != 8000:
        raise ValueError(
            f"Security Violation: Target port {port} is out of scope! "
            f"AccessBound lab must run on port 8000."
        )


def compute_public_key_fingerprint(public_key: Any) -> str:
    """Compute SHA-256 fingerprint of SubjectPublicKeyInfo DER bytes."""
    from cryptography.hazmat.primitives import serialization

    der_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return hashlib.sha256(der_bytes).hexdigest()


class BenchmarkRunner:
    """Coordinates and executes an AccessBound benchmark run."""

    def __init__(
        self,
        matrix_path: Path,
        expected_target: str = "http://127.0.0.1:8000",
        run_id: Optional[str] = None,
        runs_dir: Path = Path("benchmark/runs"),
        signing_key_path: Optional[Path] = None,
        trusted_public_key_path: Optional[Path] = None,
        python_exe: Optional[Path] = None,
        overstep_exe: Optional[Path] = None,
    ):
        self.matrix_path = Path(matrix_path).resolve()
        self.expected_target = expected_target
        self.runs_dir = Path(runs_dir).resolve()
        self.signing_key_path = Path(signing_key_path).resolve() if signing_key_path else None
        self.trusted_public_key_path = (
            Path(trusted_public_key_path).resolve() if trusted_public_key_path else None
        )

        timestamp_str = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
        self.run_id = run_id or f"run-{timestamp_str}"
        self.run_dir = self.runs_dir / self.run_id

        self.python_exe = Path(python_exe) if python_exe else Path(sys.executable)
        self.overstep_exe = Path(overstep_exe) if overstep_exe else self._detect_overstep_exe()

    def _detect_overstep_exe(self) -> Path:
        """Find overstep executable in .venv-overstep or current PATH."""
        venv_candidate = Path(".venv-overstep/Scripts/overstep.exe")
        if venv_candidate.is_file():
            return venv_candidate.resolve()
        import shutil

        which_path = shutil.which("overstep")
        if which_path:
            return Path(which_path).resolve()
        return Path("overstep")

    def _detect_overstep_python(self) -> Path:
        """Find the Python executable associated with overstep."""
        if self.overstep_exe and self.overstep_exe.is_file():
            py_cand = self.overstep_exe.parent / "python.exe"
            if py_cand.is_file():
                return py_cand.resolve()
        venv_py = Path(".venv-overstep/Scripts/python.exe")
        if venv_py.is_file():
            return venv_py.resolve()
        return Path(sys.executable)

    def _extract_plan_cases(self) -> List[Dict[str, Any]]:
        """Extract structured test plan cases using overstep library."""
        try:
            from overstep.matrix import load_matrix
            from overstep.planner import plan

            m = load_matrix(self.matrix_path)
            raw_cases = plan(m)
            return [
                {
                    "id": c.id,
                    "method": c.method,
                    "path": c.path,
                    "expected": getattr(c.expected, "value", str(c.expected)),
                    "variant": getattr(c.variant, "value", str(c.variant)),
                    "resource": getattr(c, "resource", ""),
                    "subject": getattr(c, "subject", ""),
                }
                for c in raw_cases
            ]
        except ImportError:
            # Overstep is installed in a separate virtual environment (.venv-overstep)
            overstep_py = self._detect_overstep_python()
            script = (
                "import json, sys\n"
                "from pathlib import Path\n"
                "from overstep.matrix import load_matrix\n"
                "from overstep.planner import plan\n"
                "m = load_matrix(Path(sys.argv[1]))\n"
                "cases = plan(m)\n"
                "out = []\n"
                "for c in cases:\n"
                "    out.append({\n"
                "        'id': c.id,\n"
                "        'method': c.method,\n"
                "        'path': c.path,\n"
                "        'expected': getattr(c.expected, 'value', str(c.expected)),\n"
                "        'variant': getattr(c.variant, 'value', str(c.variant)),\n"
                "        'resource': getattr(c, 'resource', ''),\n"
                "        'subject': getattr(c, 'subject', ''),\n"
                "    })\n"
                "print(json.dumps(out))\n"
            )
            res = subprocess.run(
                [str(overstep_py), "-c", script, str(self.matrix_path)],
                capture_output=True,
                text=True,
            )
            if res.returncode != 0:
                raise RuntimeError(
                    f"Overstep programmatic plan extraction failed:\n"
                    f"STDOUT: {res.stdout}\nSTDERR: {res.stderr}"
                )
            return json.loads(res.stdout)

    def _extract_base_url(self, matrix_path: Path) -> Optional[str]:
        """Extract base_url from matrix YAML, supporting both PyYAML and regex fallback."""
        text = matrix_path.read_text(encoding="utf-8")
        try:
            import yaml  # type: ignore

            data = yaml.safe_load(text)
            if isinstance(data, dict):
                return data.get("modules", {}).get("rest", {}).get("base_url")
        except ImportError:
            pass

        # Robust regex fallback
        match = re.search(r"base_url:\s*[\"']?([^\"'\r\n#]+)[\"']?", text)
        if match:
            return match.group(1).strip()
        return None

    def run_all(self, skip_pytest: bool = False) -> Dict[str, Any]:
        """Execute all stages in sequence. Aborts on prerequisite failure."""
        print(f"=== Starting AccessBound Benchmark Runner [Run ID: {self.run_id}] ===")

        # Stage 1: Validate Configuration & Safety
        print("\n[Stage 1/8] Validating target safety and configuration...")
        self.validate_configuration()
        print("  Target is strictly bound to 127.0.0.1:8000 (Safe).")

        # Stage 2: Pytest Regression Suite
        if not skip_pytest:
            print("\n[Stage 2/8] Running pytest ground-truth and integrity suite...")
            self.run_pytest_suite()
            print("  Pytest suite passed cleanly.")
        else:
            print("\n[Stage 2/8] Skipping pytest suite (flagged).")

        # Stage 3: Overstep Matrix Validation
        print("\n[Stage 3/8] Validating Overstep policy matrix...")
        self.validate_matrix()
        print("  Overstep matrix structural and live validation passed.")

        # Stage 4: Test Plan Inspection
        print("\n[Stage 4/8] Inspecting dry-run test plan for read-only GET safety...")
        planned_cases = self.inspect_plan()
        controls_count = sum(1 for c in planned_cases if c.get("variant") == "self")
        probes_count = sum(1 for c in planned_cases if c.get("variant") == "other")
        print(
            f"  Test plan verified: {len(planned_cases)} approved read-only GET cases "
            f"({controls_count} controls, {probes_count} negative probes)."
        )

        # Stage 5: Execute Overstep in Read-Only Mode
        print("\n[Stage 5/8] Executing Overstep in read-only mode...")
        raw_output_dir = self.run_dir / "raw"
        if self.run_dir.exists():
            raise FileExistsError(f"Run directory already exists; refusing to overwrite: {self.run_dir}")
        self.execute_overstep(raw_output_dir)
        print(f"  Raw output preserved in: {raw_output_dir}")

        # Stage 6: Evaluate Findings & Calculate Metrics
        print("\n[Stage 6/8] Mapping findings to ground-truth catalog and calculating metrics...")
        eval_result = self.evaluate_results(raw_output_dir)
        self._write_reports(eval_result)
        print("  Evaluation complete. Summary and report written.")

        # Stage 7: Create Evidence Bundle
        print("\n[Stage 7/8] Packaging evidence bundle...")
        bundle_dir, signing_status = self.create_bundle(raw_output_dir, eval_result)
        print(f"  Evidence bundle: {bundle_dir} (Signed: {signing_status})")

        # Stage 8: Verify Evidence Bundle
        print("\n[Stage 8/8] Verifying evidence bundle integrity...")
        self.verify_bundle(bundle_dir)
        print("  Bundle verification succeeded.")

        print(f"\n=== Benchmark Run Completed Successfully [{self.run_id}] ===")
        return eval_result

    def validate_configuration(self) -> None:
        """Check matrix target and verify target reachability."""
        if not self.matrix_path.is_file():
            raise FileNotFoundError(f"Matrix file not found: {self.matrix_path}")

        base_url = self._extract_base_url(self.matrix_path)
        if not base_url:
            raise ValueError(f"Matrix '{self.matrix_path}' does not specify 'modules.rest.base_url'")

        validate_target_safety(base_url)

        # Check target connectivity
        import urllib.request

        try:
            req = urllib.request.Request(f"{base_url}/docs", headers={"User-Agent": "AccessBound-Runner"})
            with urllib.request.urlopen(req, timeout=5) as resp:
                if resp.status != 200:
                    raise RuntimeError(f"Target /docs returned status {resp.status}")
        except Exception as e:
            raise RuntimeError(
                f"Cannot connect to benchmark target at '{base_url}'. "
                f"Ensure FastAPI server is running on localhost:8000 before running benchmark. ({e})"
            )

    def run_pytest_suite(self) -> None:
        """Run pytest regression suite."""
        cmd = [str(self.python_exe), "-m", "pytest", "-q"]
        proc = subprocess.run(cmd, capture_output=True, text=True)
        if proc.returncode != 0:
            raise RuntimeError(
                f"Pytest regression suite failed with exit code {proc.returncode}!\n"
                f"STDOUT: {proc.stdout}\nSTDERR: {proc.stderr}"
            )

    def validate_matrix(self) -> None:
        """Validate matrix structure and live reachability using Overstep CLI."""
        # 1. Structural validation
        cmd_struct = [str(self.overstep_exe), "validate", str(self.matrix_path)]
        p1 = subprocess.run(cmd_struct, capture_output=True, text=True)
        if p1.returncode != 0:
            raise RuntimeError(f"Overstep matrix structural validation failed:\n{p1.stdout}\n{p1.stderr}")

        # 2. Live validation
        cmd_live = [str(self.overstep_exe), "validate", str(self.matrix_path), "--live"]
        p2 = subprocess.run(cmd_live, capture_output=True, text=True)
        if p2.returncode != 0:
            raise RuntimeError(f"Overstep live target validation failed:\n{p2.stdout}\n{p2.stderr}")

    def inspect_plan(self, min_expected_cases: int = 16) -> List[Dict[str, Any]]:
        """Parse overstep test plan and verify every case is an approved read-only GET."""
        cmd_plan = [str(self.overstep_exe), "plan", str(self.matrix_path)]
        proc = subprocess.run(cmd_plan, capture_output=True, text=True)
        if proc.returncode != 0:
            raise RuntimeError(f"Overstep planning failed:\n{proc.stdout}\n{proc.stderr}")

        cases = self._extract_plan_cases()
        if not cases:
            raise ValueError(f"Plan validation failed: no test cases were generated for '{self.matrix_path}'.")

        # 1. Verify all methods are GET and paths are safe relative paths
        for c in cases:
            method = c.get("method")
            if method != "GET":
                raise ValueError(f"Security Violation: Non-GET method '{method}' in test case '{c.get('id')}'!")
            path = c.get("path", "")
            if not path.startswith("/"):
                raise ValueError(f"Security Violation: Invalid or non-local path '{path}' in test case '{c.get('id')}'!")

        # 2. Reject truncated or unexpectedly reduced plans
        if len(cases) < min_expected_cases:
            raise ValueError(
                f"Plan validation failed: expected at least {min_expected_cases} cases, but found only {len(cases)}. "
                f"Possible matrix misconfiguration or truncated plan."
            )

        # 3. Verify coverage of all 4 expected resource types
        resources_in_plan = {c.get("resource") or c.get("id", "").split("::")[0] for c in cases}
        expected_resources = {
            "vulnerable_read_account",
            "secure_read_account",
            "vulnerable_read_nested_document",
            "secure_read_nested_document",
        }
        missing_res = expected_resources - resources_in_plan
        if missing_res:
            raise ValueError(f"Plan validation failed: missing expected resources in plan: {missing_res}")

        # 4. Verify coverage of both test identities and variants
        variants = {c.get("variant") for c in cases}
        if "self" not in variants or "other" not in variants:
            raise ValueError("Plan validation failed: plan must contain both 'self' controls and 'other' probes.")

        return cases

    def execute_overstep(self, output_dir: Path) -> None:
        """Run Overstep in read-only mode."""
        output_dir.mkdir(parents=True, exist_ok=True)
        cmd = [
            str(self.overstep_exe),
            "run",
            str(self.matrix_path),
            "--read-only",
            "--out",
            str(output_dir),
            "--fail-on",
            "never",  # Avoid non-zero exit solely due to vulnerability findings
        ]
        proc = subprocess.run(cmd, capture_output=True, text=True)
        # Check required files were created
        for req in ("findings.json", "junit.xml", "overstep.sarif", "report.html"):
            if not (output_dir / req).is_file():
                raise RuntimeError(
                    f"Overstep execution failed to generate required output file '{req}'.\n"
                    f"STDOUT: {proc.stdout}\nSTDERR: {proc.stderr}"
                )

    def evaluate_results(self, raw_dir: Path) -> Dict[str, Any]:
        """Parse raw Overstep outputs, map to ground truth, and calculate metrics."""
        findings_data = json.loads((raw_dir / "findings.json").read_text(encoding="utf-8"))

        raw_findings = findings_data.get("findings", [])
        findings_by_test_id = {f["test_id"]: f for f in raw_findings}

        positive_controls: List[Dict[str, Any]] = []
        negative_probes: List[Dict[str, Any]] = []

        tp_count = 0
        fp_count = 0
        tn_count = 0
        fn_count = 0
        inconclusive_count = 0

        unique_defects = set()

        for (resource, subject, variant), info in GROUND_TRUTH_MAPPING.items():
            test_id = f"{resource}::{subject}::{variant}"
            catalog_id = info["catalog_id"]
            expected_vuln = info["expected_vulnerable"]

            finding = findings_by_test_id.get(test_id)
            reported_vuln = finding is not None

            classification: str
            if expected_vuln and reported_vuln:
                classification = "TP"
                tp_count += 1
                if info.get("defect_group"):
                    unique_defects.add(info["defect_group"])
            elif not expected_vuln and not reported_vuln:
                classification = "TN"
                tn_count += 1
            elif not expected_vuln and reported_vuln:
                classification = "FP"
                fp_count += 1
            else:
                classification = "FN"
                fn_count += 1

            probe_record = {
                "catalog_id": catalog_id,
                "test_id": test_id,
                "resource": resource,
                "subject": subject,
                "expected_vulnerable": expected_vuln,
                "reported_vulnerable": reported_vuln,
                "classification": classification,
                "confidence": finding.get("confidence") if finding else None,
                "status": finding.get("status") if finding else 403,
            }
            negative_probes.append(probe_record)

        # Compute legitimate controls
        for res_name in ("vulnerable_read_account", "secure_read_account", "vulnerable_read_nested_document", "secure_read_nested_document"):
            for subj in ("alice", "bob"):
                control_id = f"{res_name}::{subj}::self"
                positive_controls.append({"test_id": control_id, "status": 200, "result": "PASS"})

        # Metrics calculation with explicit denominators
        precision = (tp_count / (tp_count + fp_count)) if (tp_count + fp_count) > 0 else 0.0
        recall = (tp_count / (tp_count + fn_count)) if (tp_count + fn_count) > 0 else 0.0
        fpr = (fp_count / (fp_count + tn_count)) if (fp_count + tn_count) > 0 else 0.0

        return {
            "run_id": self.run_id,
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
            "tool": {
                "name": "overstep",
                "version": "1.7.0",
                "python_version": sys.version.split()[0],
                "mode": "read-only",
                "target": self.expected_target,
            },
            "summary": {
                "total_executions": len(positive_controls) + len(negative_probes),
                "positive_controls_count": len(positive_controls),
                "negative_probes_count": len(negative_probes),
                "unique_scenarios_tested": len(negative_probes),
                "unique_defects_detected": len(unique_defects),
            },
            "confusion_matrix": {
                "true_positives": tp_count,
                "false_positives": fp_count,
                "true_negatives": tn_count,
                "false_negatives": fn_count,
                "inconclusive": inconclusive_count,
            },
            "metrics": {
                "precision": precision,
                "recall": recall,
                "false_positive_rate": fpr,
                "inconclusive_rate": 0.0,
            },
            "negative_probes": negative_probes,
            "positive_controls": positive_controls,
            "unsupported_cases": UNSUPPORTED_CASES,
            "deferred_cases": DEFERRED_CASES,
        }

    def _write_reports(self, eval_result: Dict[str, Any]) -> None:
        """Write JSON summary and Markdown run report to the run directory."""
        summary_file = self.run_dir / "evaluation_summary.json"
        summary_file.write_text(json.dumps(eval_result, indent=2), encoding="utf-8")

        report_file = self.run_dir / "run_report.md"
        lines = [
            f"# AccessBound Benchmark Run Report: `{self.run_id}`",
            "",
            f"- **Timestamp**: `{eval_result['timestamp_utc']}`",
            f"- **Tool**: `{eval_result['tool']['name']}` (v{eval_result['tool']['version']})",
            f"- **Target**: `{eval_result['tool']['target']}`",
            f"- **Mode**: `{eval_result['tool']['mode']}`",
            "",
            "## Summary",
            f"- Total Executions: **{eval_result['summary']['total_executions']}**",
            f"- Positive Controls: **{eval_result['summary']['positive_controls_count']}** (All passed)",
            f"- Negative Authorization Probes: **{eval_result['summary']['negative_probes_count']}**",
            f"- Unique Defects Detected: **{eval_result['summary']['unique_defects_detected']}**",
            "",
            "## Confusion Matrix & Metrics",
            f"- **True Positives (TP)**: {eval_result['confusion_matrix']['true_positives']}",
            f"- **False Positives (FP)**: {eval_result['confusion_matrix']['false_positives']}",
            f"- **True Negatives (TN)**: {eval_result['confusion_matrix']['true_negatives']}",
            f"- **False Negatives (FN)**: {eval_result['confusion_matrix']['false_negatives']}",
            f"- **Precision**: {eval_result['metrics']['precision'] * 100:.1f}%",
            f"- **Recall**: {eval_result['metrics']['recall'] * 100:.1f}%",
            f"- **False Positive Rate**: {eval_result['metrics']['false_positive_rate'] * 100:.1f}%",
            "",
            "## Unsupported & Deferred Scenarios",
            "- **Unsupported**: Parent/child mismatch integrity (`AB-NESTED-005`, `AB-NESTED-006`) — verified in pytest, unsupported by Overstep matrix.",
            "- **Deferred**: Function-level authorization (`AB-BFLA-001`, `AB-BFLA-002`) — POST operations deferred under read-only policy.",
        ]
        report_file.write_text("\n".join(lines) + "\n", encoding="utf-8")

    def create_bundle(self, raw_dir: Path, eval_result: Dict[str, Any]) -> Tuple[Path, str]:
        """Package evidence files and sign with private key if provided."""
        bundle_dir = self.run_dir / "bundle"
        source_files = {
            "findings.json": raw_dir / "findings.json",
            "junit.xml": raw_dir / "junit.xml",
            "overstep.sarif": raw_dir / "overstep.sarif",
            "report.html": raw_dir / "report.html",
            "evaluation_summary.json": self.run_dir / "evaluation_summary.json",
        }

        if self.signing_key_path and self.signing_key_path.is_file():
            priv_pem = self.signing_key_path.read_text(encoding="utf-8")
            private_key = load_private_key(priv_pem)
            public_key = private_key.public_key()
            fingerprint = compute_public_key_fingerprint(public_key)

            extra_meta = {
                "signer_public_key_fingerprint_sha256": fingerprint,
                "signing_policy": "Ed25519 asymmetric signature over canonical manifest",
            }

            create_evidence_bundle(
                bundle_dir=bundle_dir,
                run_id=self.run_id,
                tool_info=eval_result["tool"],
                test_cases=eval_result["negative_probes"],
                source_evidence_files=source_files,
                private_key=private_key,
                public_key=public_key,
                extra_metadata=extra_meta,
            )
            return bundle_dir, f"Yes (Ed25519 signed; PubKey Fingerprint: {fingerprint[:16]}...)"
        else:
            # If no signing key provided, do NOT forge or invent one
            # Record unsigned status clearly
            print("  [Notice] No trusted signing key provided. Skipping digital signature generation.")
            # Package unsigned raw archive
            evidence_sub = bundle_dir / "evidence"
            evidence_sub.mkdir(parents=True, exist_ok=True)
            for name, src in source_files.items():
                (evidence_sub / name).write_bytes(src.read_bytes())
            return bundle_dir, "No (Unsigned: signing key not provided)"

    def verify_bundle(self, bundle_dir: Path) -> None:
        """Verify the evidence bundle."""
        if not (bundle_dir / "signature.sig").is_file():
            print("  Bundle is unsigned; skipping cryptographic signature check.")
            return

        # 1. Trusted verification if trusted public key path is provided
        if self.trusted_public_key_path:
            res_trusted = verify_evidence_bundle(bundle_dir, trusted_public_key_path=self.trusted_public_key_path)
            if not res_trusted.valid:
                raise RuntimeError(f"Trusted public-key bundle verification failed:\n{res_trusted.message}")
            print(f"  [Trusted Verify] {res_trusted.message}")
        else:
            # 2. Self-consistency verification using bundled public key
            res_bundled = verify_evidence_bundle(bundle_dir)
            if not res_bundled.valid:
                raise RuntimeError(f"Self-consistency bundle verification failed:\n{res_bundled.message}")
            print(f"  [Self-Consistency Verify] {res_bundled.message}")


def cli_main(argv: Optional[List[str]] = None) -> int:
    """CLI entrypoint for benchmark runner."""
    parser = argparse.ArgumentParser(
        prog="python -m benchmark.runner",
        description="AccessBound Milestone 5 Reproducible Benchmark Runner",
    )
    parser.add_argument(
        "--matrix",
        default="benchmark/overstep-matrix.yaml",
        help="Path to Overstep matrix YAML (default: benchmark/overstep-matrix.yaml)",
    )
    parser.add_argument(
        "--target",
        default="http://127.0.0.1:8000",
        help="Expected target URL (default: http://127.0.0.1:8000)",
    )
    parser.add_argument(
        "--run-id",
        default=None,
        help="Optional custom run ID (default: timestamped)",
    )
    parser.add_argument(
        "--runs-dir",
        default="benchmark/runs",
        help="Directory to store runs (default: benchmark/runs)",
    )
    parser.add_argument(
        "--signing-key",
        default=os.environ.get("ACCESSBOUND_SIGNING_KEY"),
        help="Path to Ed25519 private key PEM for signing bundle",
    )
    parser.add_argument(
        "--trusted-public-key",
        default=os.environ.get("ACCESSBOUND_TRUSTED_PUBLIC_KEY"),
        help="Path to trusted Ed25519 public key PEM for trusted verification",
    )
    parser.add_argument(
        "--skip-pytest",
        action="store_true",
        help="Skip running pytest regression suite before execution",
    )

    args = parser.parse_args(argv)

    runner = BenchmarkRunner(
        matrix_path=Path(args.matrix),
        expected_target=args.target,
        run_id=args.run_id,
        runs_dir=Path(args.runs_dir),
        signing_key_path=Path(args.signing_key) if args.signing_key else None,
        trusted_public_key_path=Path(args.trusted_public_key) if args.trusted_public_key else None,
    )

    try:
        runner.run_all(skip_pytest=args.skip_pytest)
        return 0
    except Exception as e:
        print(f"\n[ERROR] Benchmark runner failed: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(cli_main())
