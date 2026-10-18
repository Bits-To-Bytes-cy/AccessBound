# AccessBound — 90-Second Demonstration Script

This script provides a concise, repeatable, step-by-step demonstration of the **AccessBound API Authorization Benchmark & Evidence Lab**. It is designed for portfolio presentations, technical walkthroughs, or video demonstrations.

---

## Pre-Demo Setup (Preflight)

Ensure the local API server is running on `127.0.0.1:8000`:

```powershell
.\.venv\Scripts\python.exe -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

Open a second terminal window in the project root.

---

## 90-Second Walkthrough Timeline

### Part 1: Purpose & Problem (0:00 – 0:15)

> **Speaker Script**:
>*"API authorization vulnerabilities like BOLA and IDOR are the #1 threat on the OWASP API Top 10, yet traditional DAST scanners struggle to detect them because unauthorized responses return valid `200 OK` JSON. AccessBound is an open, controlled research lab and benchmark harness with planted ground-truth outcomes to evaluate authorization-testing tools with cryptographic proof."*

---

### Part 2: Planted Vulnerability vs. Secure Control (0:15 – 0:35)

Demonstrate the difference between vulnerable and secure endpoint behavior using synthetic test identities (`alice` and `bob`).

#### 1. Deliberately Vulnerable Cross-User Read (BOLA)
Alice sends a cross-user request to read Bob's account (`102`):

```powershell
curl.exe -s -H "X-Lab-User: alice" http://127.0.0.1:8000/lab/vulnerable/accounts/102
```

**Observed Output**:
```json
{
  "account_id": 102,
  "owner": "bob",
  "nickname": "Bob Checking",
  "balance": 2500.0,
  "canary": "BOB_CANARY_ACCOUNT_102"
}
```
> **Speaker Note**: The API leaks Bob's account and synthetic canary marker to Alice with status `200 OK`.

#### 2. Deliberately Secure Cross-User Read
Alice sends the identical request against the secure route:

```powershell
curl.exe -s -i -H "X-Lab-User: alice" http://127.0.0.1:8000/lab/secure/accounts/102
```

**Observed Output**:
```http
HTTP/1.1 403 Forbidden
content-type: application/json

{"detail":"Forbidden: You do not have access to this account"}
```
> **Speaker Note**: Proper object-level access control denies Alice with `403 Forbidden`.

---

### Part 3: Automated Benchmark Execution & Confusion Matrix (0:35 – 0:60)

Execute the benchmark runner against candidate tool **Overstep** (v1.7.0):

```powershell
.\.venv\Scripts\python.exe -m benchmark.runner `
    --signing-key "$env:USERPROFILE\.accessbound\keys\lab_signer.private.pem" `
    --trusted-public-key keys/trusted_lab_signer.pub.pem
```

**Observed Stages in Terminal**:
```text
=== Starting AccessBound Benchmark Runner [Run ID: run-20261018-XXXXXX] ===
[Stage 1/8] Validating target safety and configuration... (Bound to 127.0.0.1:8000)
[Stage 2/8] Running pytest ground-truth and integrity suite... (40 passed cleanly)
[Stage 3/8] Validating Overstep policy matrix... (Passed)
[Stage 4/8] Inspecting dry-run test plan for read-only GET safety... (16 approved cases: 8 controls, 8 probes)
[Stage 5/8] Executing Overstep in read-only mode... (Raw output preserved in unique directory)
[Stage 6/8] Mapping findings to ground-truth catalog and calculating metrics...
[Stage 7/8] Packaging evidence bundle... (Ed25519 signed; PubKey Fingerprint: 487461557a51f039...)
[Stage 8/8] Verifying evidence bundle integrity... (Signature verified and 5 evidence files intact)
=== Benchmark Run Completed Successfully ===
```

> **Speaker Script**:
>*"The runner executes eight isolated stages. It preflights network safety, runs the 40-test regression suite, validates the test plan, executes Overstep in read-only mode, and maps results to ground-truth IDs. It separates eight legitimate positive controls from eight negative authorization probes, yielding 4 True Positives, 4 True Negatives, 0 False Positives, and 0 False Negatives across account and nested document hierarchies."*

---

### Part 4: Cryptographic Evidence Verification (0:60 – 0:75)

Verify the integrity of a signed evidence bundle using the repository's independently distributed trusted public key:

```powershell
.\.venv\Scripts\python.exe -m benchmark.evidence verify benchmark/runs/run-20261014-185014/bundle `
    --trusted-public-key keys/trusted_lab_signer.pub.pem
```

**Observed Output**:
```text
[PASS] Bundle verification succeeded: signature verified and 5 evidence files intact
  Run ID:    run-20261014-185014
  Timestamp: 2026-10-14T18:50:20.461905+00:00
  Files:     5 verified
```

> **Speaker Script**:
>*"Every run produces a tamper-evident evidence bundle. The manifest binds SHA-256 hashes of all raw tool artifacts, signed with an Ed25519 private key. Here, we verify the bundle against our independently stored repository public key. If a single byte in `findings.json` or `manifest.json` is altered, verification fails immediately."*

---

### Part 5: Critical Methodology & Limitations (0:75 – 0:90)

> **Speaker Script**:
>*"A crucial takeaway: Overstep achieved 100% precision and recall because it is a **declarative policy engine** conforming to a human-specified policy matrix, not an autonomous scanner guessing business logic. Furthermore, AccessBound isolates unsupported scenarios: for example, parent/child mismatch attacks (`AB-NESTED-005` & `006`) correctly return `404` in our lab tests, but cannot be expressed in Overstep's matrix syntax. We document these separately rather than inflating detection metrics."*

---

## Summary Command Sheet

| Step | Command | Expected Result |
|---|---|---|
| **1. Lab API** | `uvicorn app.main:app --host 127.0.0.1 --port 8000` | Server listening on port 8000 |
| **2. Vulnerable Probe** | `curl -s -H "X-Lab-User: alice" http://127.0.0.1:8000/lab/vulnerable/accounts/102` | `200 OK` leaking `BOB_CANARY_ACCOUNT_102` |
| **3. Secure Probe** | `curl -s -i -H "X-Lab-User: alice" http://127.0.0.1:8000/lab/secure/accounts/102` | `403 Forbidden` |
| **4. Benchmark Runner** | `python -m benchmark.runner --trusted-public-key keys/trusted_lab_signer.pub.pem` | 8 stages complete, unique run created |
| **5. Bundle Verification** | `python -m benchmark.evidence verify <bundle_path> --trusted-public-key keys/trusted_lab_signer.pub.pem` | `[PASS] Bundle verification succeeded` |
| **6. Full Test Suite** | `pytest -v -W default` | 40 passed |
