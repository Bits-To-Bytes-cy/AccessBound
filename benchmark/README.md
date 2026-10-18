# AccessBound — Benchmark Suite

This directory contains configuration, test matrices, raw evaluation reports, and tamper-evident cryptographic evidence bundles for benchmarking API authorization-testing tools against the controlled AccessBound research lab.

---

## Table of Contents

- [Tool Paradigm: Declarative Engine vs. General-Purpose Scanner](#tool-paradigm-declarative-engine-vs-general-purpose-scanner)
- [Milestone Evolution](#milestone-evolution)
- [Directory Structure](#directory-structure)
- [Evaluation Results Comparison](#evaluation-results-comparison-milestones-2--3)
- [Tamper-Evident Evidence Bundles](#milestone-4-tamper-evident-evidence-bundles)
- [Milestone 5: Reproducible Benchmark Runner](#milestone-5-reproducible-benchmark-runner)
- [Reproducing the Benchmark Runs](#reproducing-the-benchmark-runs)
- [Unsupported and Deferred Scenarios](#unsupported-and-deferred-scenarios)

---

## Tool Paradigm: Declarative Engine vs. General-Purpose Scanner

Before reviewing the results, it is critical to distinguish between the two primary classes of API security testing tools:

- **Declarative Authorization Test Engine (e.g., Overstep)**:
  - Operates via an explicit, user-declared policy matrix mapping **Subjects** (identities/roles) to **Resources** (endpoints) and **Access Rules** (e.g., `scope: own`).
  - Automatically synthesizes deterministic positive controls (`self` access) and negative boundary probes (`other` cross-user access).
  - Evaluates whether the target *refuses* requests that should be denied according to the declared policy.
  - **Does not** autonomously crawl endpoints, guess parameter names, or deduce ownership logic on its own.
- **General-Purpose Security Scanner (e.g., DAST tools)**:
  - Operates via autonomous spidering, specification ingestion (OpenAPI), and heuristic fuzzing (syntax errors, crashes, injections).
  - Struggles with authorization flaws (BOLA/BFLA) because a cross-user read returns a valid HTTP `200 OK` with well-formed JSON, which looks syntactically indistinguishable from legitimate data.

The 100% precision and recall metrics achieved in this benchmark reflect Overstep's adherence to a properly specified declarative matrix, not autonomous scanner intelligence.

---

## Milestone Evolution

- **Milestone 2**: Initial tool adapter baseline on read-only account endpoints.
- **Milestone 3**: Expanded read-only coverage to nested project/document hierarchies.
- **Milestone 4**: Tamper-evident evidence bundles with SHA-256 hashing and Ed25519 digital signatures.

### Candidate Tool: Overstep (`kabiri-labs/overstep`)
- **Version**: `1.7.0`
- **Installation Environment**: Dedicated virtual environment `.venv-overstep` (Python `3.11.9`)
- **Target**: `http://127.0.0.1:8000` (Localhost-only)
- **Active Policy Matrix**: [`benchmark/overstep-matrix.yaml`](overstep-matrix.yaml)

---

## Directory Structure

```text
benchmark/
├── README.md                           # Benchmark overview, taxonomy, and instructions
├── evidence.py                         # Evidence bundle creator, verifier, and keygen CLI
├── overstep-matrix.yaml                # Active declarative matrix (Accounts + Nested Documents)
├── comparison-report.md                # Full comparative analysis across Milestones 2 & 3
├── bundles/                            # Cryptographically signed evidence bundles (Milestone 4)
│   ├── milestone-2-account-bola/       # Signed bundle for Milestone 2 run
│   │   ├── manifest.json               # Deterministic canonical manifest with SHA-256 hashes
│   │   ├── signature.sig               # Ed25519 signature over canonical manifest
│   │   ├── public_key.pem              # Public key for bundle verification
│   │   └── evidence/                   # Raw outputs (findings.json, junit.xml, SARIF, HTML)
│   └── milestone-3-nested-bola/        # Signed bundle for Milestone 3 run
│       ├── manifest.json
│       ├── signature.sig
│       ├── public_key.pem
│       └── evidence/
└── results/                            # Raw tool execution outputs
    ├── findings.json                   # Milestone 2 Baseline: Account-level findings
    ├── junit.xml                       # Milestone 2 Baseline: JUnit record
    ├── overstep.sarif                  # Milestone 2 Baseline: SARIF report
    ├── report.html                     # Milestone 2 Baseline: HTML report
    └── milestone-3-run-001/            # Milestone 3 Expanded: Account + Nested Documents
        ├── findings.json               # Milestone 3: 4 BOLA findings across 2 defect groups
        ├── junit.xml                   # Milestone 3: 16 test execution records
        ├── overstep.sarif              # Milestone 3: SARIF report with CWE-639 / API1:2023
        └── report.html                 # Milestone 3: Standalone HTML report
```

---

## Evaluation Results Comparison (Milestones 2 & 3)

| Metric / Dimension | Milestone 2 (Account BOLA) | Milestone 3 (Account + Nested Documents) |
|---|---|---|
| **Raw Results Location** | `benchmark/results/` | `benchmark/results/milestone-3-run-001/` |
| **Signed Evidence Bundle** | `benchmark/bundles/milestone-2-account-bola` | `benchmark/bundles/milestone-3-nested-bola` |
| **Resources Evaluated** | 2 (`/lab/{vuln,sec}/accounts/{id}`) | 4 (Accounts + Project/Document pairs) |
| **Total Test Executions** | 8 | 16 |
| **Legitimate Positive Controls** | 4 (All passed `200 OK`) | 8 (All passed `200 OK`) |
| **Negative Authorization Probes** | 4 (`AB-BOLA-001, 002, 005, 006`) | 8 (`AB-BOLA-*` + `AB-NESTED-001..004`) |
| **True Positives (TP)** | 2 | 4 |
| **True Negatives (TN)** | 2 | 4 |
| **False Positives (FP)** | 0 | 0 |
| **False Negatives (FN)** | 0 | 0 |
| **Unique Code Defects Detected** | 1 (`vulnerable_read_account`) | 2 (`vulnerable_read_account` + `vulnerable_read_nested_document`) |
| **Precision** | 100% (2 / 2) | 100% (4 / 4) |
| **Recall** | 100% (2 / 2) | 100% (4 / 4) |
| **False Positive Rate (FPR)** | 0% (0 / 2) | 0% (0 / 4) |
| **Inconclusive Rate** | 0% | 0% |

For full derivations, confusion matrices, and case mapping, consult [`benchmark/comparison-report.md`](comparison-report.md).

---

## Milestone 4: Tamper-Evident Evidence Bundles

The evidence-bundle system ensures that benchmark runs cannot be modified, re-ordered, or forged undetected.

### Bundle Anatomy

Each bundle in `benchmark/bundles/<bundle-id>/` contains:
1. `manifest.json`: Structured metadata containing run ID, timestamp, tool versions, test case mapping, and the SHA-256 digest of every file in `evidence/`.
   - **Deterministic Serialization**: The manifest is serialized into canonical JSON (UTF-8, keys sorted alphabetically, compact delimiters `,` and `:` without extra whitespace) before signing and hashing.
   - **Path Normalization**: File paths are strictly relative, normalized with forward slashes (`/`), and restricted to the `evidence/` directory. Path traversal attempts (`..` or absolute paths) are rejected.
2. `signature.sig`: Ed25519 digital signature computed directly over the exact canonical UTF-8 bytes of `manifest.json`, encoded in Base64.
3. `public_key.pem`: SubjectPublicKeyInfo PEM public key corresponding to the private signing key used to sign the manifest.
4. `evidence/`: Subdirectory containing raw artifacts (`findings.json`, `junit.xml`, `overstep.sarif`, `report.html`).

### Distinction: Hash Verification vs. Signature Verification

- **Hash Verification**: Compares the SHA-256 checksum of each physical file in `evidence/` against the `sha256` entry recorded in `manifest.json`. This proves that the raw evidence files have not been modified, replaced, truncated, or appended to.
- **Signature Verification**: Verifies the Ed25519 cryptographic signature of the canonical `manifest.json` against a trusted public key. This proves that the manifest itself (which binds the hashes, run configuration, test cases, and timestamp) was signed by the holder of the private key and has not been altered since signing.

> [!IMPORTANT]
> **Trust Boundary Notice**:
> Digital signature verification confirms that the manifest has not been modified since it was signed with a specific private key. It does **not** prove who operated the tool or that the tool was unbiased unless the signer's identity and public key are independently verified and trusted out-of-band.

### Key Management Procedure

1. **Private Keys Outside Repository**: Private signing keys must **never** be checked into version control. In our setup, private keys are generated outside the repository (e.g., in `$HOME/.accessbound/keys/`):
   ```powershell
   .\.venv\Scripts\python.exe -m benchmark.evidence keygen `
       --priv "$HOME\.accessbound\keys\lab_signer.private.pem" `
       --pub "$HOME\.accessbound\keys\lab_signer.public.pem"
   ```
2. **Defensive Git Exclusions**: The root `.gitignore` defensively excludes `*.key`, `*.pem`, `*.private.pem`, and `keys/private*`.
3. **Public Key Availability**: Public keys are exported into SubjectPublicKeyInfo PEM format and stored alongside the bundle (`public_key.pem`) for verification. Users may also provide an external trusted public key file during verification.

---

## Verification Utility Commands

### 1. Verifying a Bundle with its Bundled Public Key
```powershell
.\.venv\Scripts\python.exe -m benchmark.evidence verify benchmark/bundles/milestone-3-nested-bola
```

**Expected Success Output**:
```text
[PASS] Bundle verification succeeded: signature verified and 4 evidence files intact
  Run ID:    run-milestone-3-nested-bola
  Timestamp: 2026-10-14T18:19:53.035026+00:00
  Files:     4 verified
```

### 2. Verifying a Bundle with an External Trusted Public Key
```powershell
.\.venv\Scripts\python.exe -m benchmark.evidence verify benchmark/bundles/milestone-3-nested-bola `
    --public-key "$HOME\.accessbound\keys\lab_signer.public.pem"
```

### 3. Failure Detection
If any file in `evidence/` is altered, `verify` exits with code `1`:
```text
[FAIL] Hash mismatch for 'findings.json': expected e3b0c44..., got a1b2c3d...
```
If `manifest.json` is tampered with, `verify` exits with code `1`:
```text
[FAIL] Digital signature verification failed: signature does not match manifest and public key
```

---

---

## Milestone 5: Reproducible Benchmark Runner

AccessBound includes a dedicated, repeatable orchestration runner (`benchmark/runner.py`) that automates the complete benchmark lifecycle end-to-end with strict result isolation and preflight safety verification.

### Workflow Stages

The runner executes 8 stages strictly in order. Any prerequisite failure immediately halts execution before subsequent steps:

1. **Target Safety & Local Configuration**: Validates matrix configuration and confirms target is strictly constrained to `127.0.0.1:8000`. Rejects external hostnames and out-of-scope ports before any network calls.
2. **Pytest Regression Suite**: Runs the full regression test suite (36 tests across ground-truth, evidence bundles, and runner lifecycle). Halts if any test fails.
3. **Matrix Validation**: Performs structural and live connectivity validation of the declarative policy matrix using Overstep CLI.
4. **Test Plan Inspection**: Performs a dry-run plan inspection to verify that every planned test case is an approved, non-mutating `GET` operation.
5. **Isolated Read-Only Execution**: Executes Overstep in `--read-only` mode with output preserved in a unique run directory (`benchmark/runs/<run-id>/raw`). Existing run directories are never overwritten (`FileExistsError`).
6. **Ground-Truth Mapping & Metric Evaluation**: Maps raw tool findings to ground-truth catalog IDs (`AB-BOLA-001..006`, `AB-NESTED-001..004`). Computes confusion matrix and metrics with explicit valid denominators, strictly separating positive controls, negative probes, and unsupported/deferred cases.
7. **Tamper-Evident Evidence Bundling**: Packages raw outputs and evaluation summary into an evidence bundle (`benchmark/runs/<run-id>/bundle/`). If a trusted signing key is provided via `--signing-key`, generates an Ed25519 digital signature over the canonical manifest. If no signing key is provided, archives an unsigned bundle without inventing or forging fake keys.
8. **Integrity & Cryptographic Verification**: Verifies bundle integrity. If `--trusted-public-key` is supplied, performs trusted verification against the independently stored external public key; otherwise, performs self-consistency verification using the bundled public key.

### Key Management & Git Hygiene

- **Private Signing Keys Stay External**: Private keys must be stored outside the repository (e.g. `~/.accessbound/keys/` or via `--signing-key`). The runner never generates temporary keys automatically for benchmark runs.
- **Git Protection**: `.gitignore` strictly excludes private keys (`*.key`, `*.private.pem`, `private_key.pem`, `keys/private*`) while narrowly allowing distribution of public keys (`!public_key.pem`, `!*.public.pem`).
- **Trusted vs. Self-Consistency Verification**:
  - **Self-consistency verification** (`verify <bundle>`): Verifies that the bundle matches its included `public_key.pem`. Proves the bundle has not been modified since it was signed, but does not prove *who* signed it.
  - **Trusted verification** (`verify <bundle> --trusted-public-key <path>`): Verifies the signature against an independently stored, trusted public key out-of-band.
  - Recording a public-key SHA-256 fingerprint in metadata documents the key used, but a fingerprint alone does not establish trust without an authoritative source.

### Run Directory Layout

Each benchmark execution creates an isolated timestamped directory:

```text
benchmark/runs/<run-id>/
├── raw/                            # Exact raw scanner artifacts
│   ├── findings.json
│   ├── junit.xml
│   ├── overstep.sarif
│   └── report.html
├── evaluation_summary.json         # Machine-readable evaluation summary & confusion matrix
├── run_report.md                   # Human-readable execution report
└── bundle/                         # Tamper-evident evidence bundle
    ├── manifest.json               # Deterministic manifest with file hashes & signer fingerprint
    ├── signature.sig               # Ed25519 signature (if signing key provided)
    ├── public_key.pem              # Public key corresponding to signature
    └── evidence/                   # Bit-for-bit preserved evidence files
        ├── findings.json
        ├── junit.xml
        ├── overstep.sarif
        ├── report.html
        └── evaluation_summary.json
```

Existing historical results in `benchmark/results/` and baseline signed bundles in `benchmark/bundles/` remain completely untouched.

---

## Reproducing the Benchmark Runs

### 1. Run the FastAPI Application
```powershell
.\.venv\Scripts\python.exe -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

### 2. Run the Benchmark Runner (Milestone 5 Repeatable Workflow)

**Standard run with external signing key and trusted verification:**
```powershell
.\.venv\Scripts\python.exe -m benchmark.runner `
    --signing-key "$env:USERPROFILE\.accessbound\keys\lab_signer.private.pem" `
    --trusted-public-key keys/trusted_lab_signer.pub.pem
```

**Unsigned run (when signing key is not available):**
```powershell
.\.venv\Scripts\python.exe -m benchmark.runner
```

### 3. Verify an Evidence Bundle

**Trusted verification with repository's trusted public key:**
```powershell
.\.venv\Scripts\python.exe -m benchmark.evidence verify benchmark/runs/<run-id>/bundle `
    --trusted-public-key keys/trusted_lab_signer.pub.pem
```

**Self-consistency verification (bundled key):**
```powershell
.\.venv\Scripts\python.exe -m benchmark.evidence verify benchmark/runs/<run-id>/bundle
```

### 4. Run Automated Regression and Integrity Tests
```powershell
.\.venv\Scripts\python.exe -m pytest -v -W default
```
*Executes all 40 automated tests across ground-truth, evidence bundles, and runner workflow.*

---

## Unsupported and Deferred Scenarios

1. **Parent/Child Relationship Mismatch (`AB-NESTED-005` & `006`)**:
   - The lab correctly enforces linkage: querying Alice's project (`201`) with Bob's document (`302`) returns `404 Document not found`. Verified in `tests/test_ground_truth.py`.
   - **Unsupported by Overstep**: Overstep binds path parameters to subject attribute pairs; its matrix schema cannot express deliberate cartesian mismatches of parent project and child document ownership.
2. **Function-Level Authorization (BFLA) (`AB-BFLA-001` & `002`)**:
   - Admin reporting endpoints in `app/main.py` are `POST` operations (`POST /lab/vulnerable/admin/reports`).
   - Milestone 3 strictly enforces a read-only policy (`--read-only`, GET only). Testing BFLA is deferred to a future mutating benchmark milestone to protect lab state.
