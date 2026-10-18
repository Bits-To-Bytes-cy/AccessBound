"""Tamper-Evident Evidence Bundle System for AccessBound.

Provides deterministic manifest generation, SHA-256 file hashing,
Ed25519 asymmetric digital signing, and bundle verification.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519


def canonicalize_manifest(data: Dict[str, Any]) -> bytes:
    """Serialize manifest dictionary to deterministic, canonical UTF-8 bytes.

    Uses sorted keys and compact separators (no whitespace after ':' or ',')
    to ensure byte-identical serialization across all platforms and runtimes.
    """
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def compute_sha256(file_path: Path) -> str:
    """Compute the hex-encoded SHA-256 digest of a file in 64KB chunks."""
    hasher = hashlib.sha256()
    with open(file_path, "rb") as f:
        while chunk := f.read(65536):
            hasher.update(chunk)
    return hasher.hexdigest()


def generate_keypair() -> Tuple[ed25519.Ed25519PrivateKey, ed25519.Ed25519PublicKey]:
    """Generate a new Ed25519 keypair."""
    private_key = ed25519.Ed25519PrivateKey.generate()
    return private_key, private_key.public_key()


def export_public_key_pem(public_key: ed25519.Ed25519PublicKey) -> str:
    """Export public key to SubjectPublicKeyInfo PEM string."""
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")


def export_private_key_pem(private_key: ed25519.Ed25519PrivateKey) -> str:
    """Export private key to PKCS8 PEM string."""
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")


def load_public_key(pem_data: bytes | str) -> ed25519.Ed25519PublicKey:
    """Load an Ed25519 public key from PEM bytes or string."""
    if isinstance(pem_data, str):
        pem_data = pem_data.encode("utf-8")
    key = serialization.load_pem_public_key(pem_data)
    if not isinstance(key, ed25519.Ed25519PublicKey):
        raise ValueError("Provided key is not an Ed25519 public key")
    return key


def load_private_key(pem_data: bytes | str) -> ed25519.Ed25519PrivateKey:
    """Load an Ed25519 private key from PEM bytes or string."""
    if isinstance(pem_data, str):
        pem_data = pem_data.encode("utf-8")
    key = serialization.load_pem_private_key(pem_data, password=None)
    if not isinstance(key, ed25519.Ed25519PrivateKey):
        raise ValueError("Provided key is not an Ed25519 private key")
    return key


def sign_manifest(manifest: Dict[str, Any], private_key: ed25519.Ed25519PrivateKey) -> str:
    """Sign canonical manifest bytes with an Ed25519 private key and return Base64 signature."""
    canonical_bytes = canonicalize_manifest(manifest)
    signature_bytes = private_key.sign(canonical_bytes)
    return base64.b64encode(signature_bytes).decode("ascii")


def normalize_rel_path(path: str | Path) -> str:
    """Normalize relative path to use forward slashes and prevent directory traversal."""
    p = Path(path)
    if p.is_absolute():
        raise ValueError(f"Path must be relative, got absolute path: {path}")
    parts = p.parts
    if ".." in parts:
        raise ValueError(f"Directory traversal detected in path: {path}")
    return "/".join(parts)


def create_evidence_bundle(
    bundle_dir: Path,
    run_id: str,
    tool_info: Dict[str, Any],
    test_cases: List[Dict[str, Any]],
    source_evidence_files: Dict[str, Path],
    private_key: ed25519.Ed25519PrivateKey,
    public_key: Optional[ed25519.Ed25519PublicKey] = None,
    extra_metadata: Optional[Dict[str, Any]] = None,
) -> Path:
    """Create a tamper-evident evidence bundle directory.

    Args:
        bundle_dir: Target directory for the bundle (must not overwrite existing run).
        run_id: Unique benchmark run identifier.
        tool_info: Tool name, version, python version, runtime configuration.
        test_cases: List of test cases executed, outcomes, and observed statuses.
        source_evidence_files: Map of relative target names (e.g. 'findings.json') to source files.
        private_key: Ed25519 private key used to sign the manifest.
        public_key: Optional public key to store with the bundle.
        extra_metadata: Additional benchmark context.

    Returns:
        Path to the created bundle directory.
    """
    bundle_dir = Path(bundle_dir)
    if bundle_dir.exists() and any(bundle_dir.iterdir()):
        raise FileExistsError(f"Target bundle directory already exists and is not empty: {bundle_dir}")

    evidence_dir = bundle_dir / "evidence"
    evidence_dir.mkdir(parents=True, exist_ok=True)

    file_hashes: Dict[str, Dict[str, Any]] = {}

    for rel_name, src_path in sorted(source_evidence_files.items()):
        norm_name = normalize_rel_path(rel_name)
        dest_path = evidence_dir / norm_name
        dest_path.parent.mkdir(parents=True, exist_ok=True)

        content = src_path.read_bytes()
        dest_path.write_bytes(content)

        file_hashes[norm_name] = {
            "sha256": compute_sha256(dest_path),
            "size_bytes": len(content),
        }

    manifest: Dict[str, Any] = {
        "format_version": "1.0",
        "run_id": run_id,
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "tool": tool_info,
        "summary": {
            "total_files": len(file_hashes),
            "total_test_cases": len(test_cases),
        },
        "test_cases": test_cases,
        "files": file_hashes,
    }
    if extra_metadata:
        manifest["metadata"] = extra_metadata

    # 1. Write deterministic manifest
    canonical_bytes = canonicalize_manifest(manifest)
    (bundle_dir / "manifest.json").write_bytes(canonical_bytes)

    # 2. Sign canonical manifest
    signature_b64 = sign_manifest(manifest, private_key)
    (bundle_dir / "signature.sig").write_text(signature_b64 + "\n", encoding="utf-8")

    # 3. Store public key alongside bundle for verification
    if public_key is None:
        public_key = private_key.public_key()
    (bundle_dir / "public_key.pem").write_text(export_public_key_pem(public_key), encoding="utf-8")

    return bundle_dir


class VerificationResult:
    """Encapsulates the result of bundle verification."""

    def __init__(self, valid: bool, message: str, details: Optional[Dict[str, Any]] = None):
        self.valid = valid
        self.message = message
        self.details = details or {}

    def __bool__(self) -> bool:
        return self.valid

    def __str__(self) -> str:
        prefix = "PASS" if self.valid else "FAIL"
        return f"[{prefix}] {self.message}"


def verify_evidence_bundle(
    bundle_dir: Path,
    trusted_public_key_path: Optional[Path] = None,
) -> VerificationResult:
    """Verify the integrity, completeness, and signature of an evidence bundle.

    Detects:
    - Missing required bundle artifacts (manifest.json, signature.sig, public_key.pem).
    - Malformed or non-canonical manifest structure.
    - Invalid Ed25519 signature over the canonical manifest representation.
    - Missing or modified evidence files (SHA-256 mismatch).
    - Untracked / unexpected files inside the evidence directory.
    - Directory traversal attempts in manifest file references.

    Args:
        bundle_dir: Path to the evidence bundle directory.
        trusted_public_key_path: Optional path to an external trusted public key.
            If omitted, the bundle's included public_key.pem is used for signature validation.

    Returns:
        VerificationResult with status and details.
    """
    bundle_dir = Path(bundle_dir)
    if not bundle_dir.is_dir():
        return VerificationResult(False, f"Bundle directory does not exist: {bundle_dir}")

    manifest_file = bundle_dir / "manifest.json"
    signature_file = bundle_dir / "signature.sig"
    bundled_pubkey_file = bundle_dir / "public_key.pem"
    evidence_dir = bundle_dir / "evidence"

    # Step 1: Check required files
    for req_file, name in [
        (manifest_file, "manifest.json"),
        (signature_file, "signature.sig"),
    ]:
        if not req_file.is_file():
            return VerificationResult(False, f"Bundle is missing required file: {name}")

    if trusted_public_key_path:
        pubkey_file = Path(trusted_public_key_path)
        if not pubkey_file.is_file():
            return VerificationResult(False, f"Trusted public key file not found: {trusted_public_key_path}")
    else:
        if not bundled_pubkey_file.is_file():
            return VerificationResult(False, "No public key provided and bundle is missing public_key.pem")
        pubkey_file = bundled_pubkey_file

    # Step 2: Parse manifest JSON and check structure
    try:
        raw_manifest_bytes = manifest_file.read_bytes()
        manifest_data = json.loads(raw_manifest_bytes.decode("utf-8"))
        if not isinstance(manifest_data, dict):
            return VerificationResult(False, "Malformed manifest: root element is not a JSON object")
    except Exception as e:
        return VerificationResult(False, f"Malformed manifest JSON: {e}")

    for req_key in ("format_version", "run_id", "timestamp_utc", "files"):
        if req_key not in manifest_data:
            return VerificationResult(False, f"Malformed manifest: missing required key '{req_key}'")

    if not isinstance(manifest_data["files"], dict):
        return VerificationResult(False, "Malformed manifest: 'files' section is not a dictionary")

    # Step 3: Signature verification
    try:
        public_key = load_public_key(pubkey_file.read_bytes())
    except Exception as e:
        return VerificationResult(False, f"Failed to load public key: {e}")

    signature_str = signature_file.read_text(encoding="utf-8").strip()
    try:
        signature_bytes = base64.b64decode(signature_str, validate=True)
    except Exception as e:
        return VerificationResult(False, f"Malformed signature file (invalid Base64): {e}")

    canonical_bytes = canonicalize_manifest(manifest_data)
    try:
        public_key.verify(signature_bytes, canonical_bytes)
    except InvalidSignature:
        return VerificationResult(
            False,
            "Digital signature verification failed: signature does not match manifest and public key",
        )
    except Exception as e:
        return VerificationResult(False, f"Signature verification error: {e}")

    # Step 4: Verify evidence files and hashes
    if not evidence_dir.is_dir():
        return VerificationResult(False, "Bundle is missing the 'evidence' directory")

    verified_files: List[str] = []
    declared_files = set()

    for rel_name, file_info in manifest_data["files"].items():
        try:
            norm_name = normalize_rel_path(rel_name)
        except ValueError as e:
            return VerificationResult(False, f"Path traversal attempt in manifest: {e}")

        declared_files.add(norm_name)
        target_file = evidence_dir / norm_name

        # Ensure target file stays strictly inside evidence_dir
        try:
            resolved_target = target_file.resolve()
            resolved_evidence_dir = evidence_dir.resolve()
            resolved_target.relative_to(resolved_evidence_dir)
        except (ValueError, RuntimeError):
            return VerificationResult(False, f"Path traversal attack detected: {rel_name}")

        if not target_file.is_file():
            return VerificationResult(False, f"Missing evidence file declared in manifest: {norm_name}")

        expected_hash = file_info.get("sha256")
        if not expected_hash:
            return VerificationResult(False, f"Manifest entry for '{norm_name}' is missing 'sha256'")

        actual_hash = compute_sha256(target_file)
        if actual_hash.lower() != expected_hash.lower():
            return VerificationResult(
                False,
                f"Hash mismatch for '{norm_name}': expected {expected_hash}, got {actual_hash}",
            )

        verified_files.append(norm_name)

    # Step 5: Check for unexpected / untracked files in evidence directory
    for item in evidence_dir.rglob("*"):
        if item.is_file():
            rel_path = "/".join(item.relative_to(evidence_dir).parts)
            if rel_path not in declared_files:
                return VerificationResult(
                    False,
                    f"Unexpected untracked file found in evidence directory: {rel_path}",
                )

    return VerificationResult(
        True,
        f"Bundle verification succeeded: signature verified and {len(verified_files)} evidence files intact",
        details={
            "run_id": manifest_data.get("run_id"),
            "timestamp_utc": manifest_data.get("timestamp_utc"),
            "tool": manifest_data.get("tool"),
            "verified_files_count": len(verified_files),
        },
    )


def cli_main(argv: Optional[List[str]] = None) -> int:
    """Command-line interface for evidence bundle creation, verification, and keygen."""
    parser = argparse.ArgumentParser(
        prog="python -m benchmark.evidence",
        description="AccessBound Tamper-Evident Evidence Bundle Utility",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # keygen command
    keygen_p = subparsers.add_parser("keygen", help="Generate Ed25519 keypair for signing evidence")
    keygen_p.add_argument("--priv", required=True, help="Output path for private key (keep secret!)")
    keygen_p.add_argument("--pub", required=True, help="Output path for public key")

    # verify command
    verify_p = subparsers.add_parser("verify", help="Verify an evidence bundle")
    verify_p.add_argument("bundle_dir", help="Path to evidence bundle directory")
    verify_p.add_argument(
        "--public-key",
        "--trusted-public-key",
        dest="public_key",
        default=None,
        help="Optional path to trusted public key PEM (defaults to bundled public_key.pem for self-consistency)",
    )

    args = parser.parse_args(argv)

    if args.command == "keygen":
        priv, pub = generate_keypair()
        priv_path = Path(args.priv)
        pub_path = Path(args.pub)

        priv_path.parent.mkdir(parents=True, exist_ok=True)
        pub_path.parent.mkdir(parents=True, exist_ok=True)

        priv_path.write_text(export_private_key_pem(priv), encoding="utf-8")
        pub_path.write_text(export_public_key_pem(pub), encoding="utf-8")
        print(f"Generated Ed25519 keypair:\n  Private key: {priv_path}\n  Public key:  {pub_path}")
        return 0

    if args.command == "verify":
        res = verify_evidence_bundle(Path(args.bundle_dir), args.public_key)
        print(res)
        if res.valid:
            if res.details:
                print(f"  Run ID:    {res.details.get('run_id')}")
                print(f"  Timestamp: {res.details.get('timestamp_utc')}")
                print(f"  Files:     {res.details.get('verified_files_count')} verified")
            return 0
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(cli_main())
