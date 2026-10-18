# AccessBound Benchmark Run Report: `run-20261014-185014`

- **Timestamp**: `2026-10-14T18:50:20.409765+00:00`
- **Tool**: `overstep` (v1.7.0)
- **Target**: `http://127.0.0.1:8000`
- **Mode**: `read-only`

## Summary
- Total Executions: **16**
- Positive Controls: **8** (All passed)
- Negative Authorization Probes: **8**
- Unique Defects Detected: **2**

## Confusion Matrix & Metrics
- **True Positives (TP)**: 4
- **False Positives (FP)**: 0
- **True Negatives (TN)**: 4
- **False Negatives (FN)**: 0
- **Precision**: 100.0%
- **Recall**: 100.0%
- **False Positive Rate**: 0.0%

## Unsupported & Deferred Scenarios
- **Unsupported**: Parent/child mismatch integrity (`AB-NESTED-005`, `AB-NESTED-006`) — verified in pytest, unsupported by Overstep matrix.
- **Deferred**: Function-level authorization (`AB-BFLA-001`, `AB-BFLA-002`) — POST operations deferred under read-only policy.
