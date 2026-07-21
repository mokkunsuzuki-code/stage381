import json
import hashlib
from pathlib import Path
from datetime import datetime, timezone

STAGE = 361

ROOT = Path(".")
DOCS = ROOT / "docs"
REVOCATION_DIR = DOCS / "revocation"

STAGE360_RESULT = DOCS / "timestamp-proof" / "stage360_external_timestamp_proof_result.json"
STAGE359_KEY_RESULT = DOCS / "keys" / "stage359_public_key_fingerprint_result.json"

OUT_JSON = REVOCATION_DIR / "stage361_revocation_proof_injection_result.json"
OUT_SUMMARY = REVOCATION_DIR / "stage361_revocation_proof_injection_summary.txt"

REVOCATION_DIR.mkdir(parents=True, exist_ok=True)


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def sha256_file(path: Path):
    if not path.exists():
        return None
    return hashlib.sha256(path.read_bytes()).hexdigest()


def read_json(path: Path):
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def contains_private_material(obj) -> bool:
    raw = json.dumps(obj, ensure_ascii=False).lower()
    dangerous = [
        "private key",
        "-----begin private key-----",
        "-----begin rsa private key-----",
        "-----begin ec private key-----",
        "secret",
        "seed",
        "raw_qkd_key",
        "raw secret",
    ]
    return any(x in raw for x in dangerous)


def has_fake_verified_claim(obj) -> bool:
    raw = json.dumps(obj, ensure_ascii=False).lower()
    suspicious_claims = [
        '"ocsp_verified": true',
        '"crl_verified": true',
        '"revocation_verified": true',
        '"verified": true',
    ]
    proof_markers = [
        "ocsp_response_der_sha256",
        "crl_der_sha256",
        "signed_revocation_metadata_sha256",
        "responder_certificate_fingerprint",
        "revocation_signature_algorithm",
    ]

    has_claim = any(x in raw for x in suspicious_claims)
    has_proof_marker = any(x in raw for x in proof_markers)

    return has_claim and not has_proof_marker


def main():
    now = datetime.now(timezone.utc).isoformat()

    stage360 = read_json(STAGE360_RESULT)
    stage359 = read_json(STAGE359_KEY_RESULT)

    previous_hash = sha256_file(STAGE360_RESULT)

    revocation_target = {
        "source": "stage359_public_key_fingerprint",
        "public_key_fingerprint": None,
        "note": "Stage359 fingerprint is used as revocation target when available."
    }

    if isinstance(stage359, dict):
        revocation_target["public_key_fingerprint"] = (
            stage359.get("public_key_fingerprint")
            or stage359.get("fingerprint")
            or stage359.get("key_fingerprint")
        )

    revocation_evidence = {
        "ocsp": {
            "provided": False,
            "status": "not_provided",
            "ocsp_response_der_sha256": None,
            "ocsp_verified": False,
            "note": "No real OCSP cryptographic verification is performed in Stage361."
        },
        "crl": {
            "provided": False,
            "status": "not_provided",
            "crl_der_sha256": None,
            "crl_verified": False,
            "note": "No real CRL cryptographic verification is performed in Stage361."
        },
        "signed_revocation_metadata": {
            "provided": False,
            "status": "not_provided",
            "metadata_sha256": None,
            "signature_verified": False,
            "note": "Stage361 creates the safe receiver for future signed revocation metadata."
        }
    }

    checks = {
        "stage360_result_present": stage360 is not None,
        "stage360_previous_hash_bound": previous_hash is not None,
        "stage359_revocation_target_present": revocation_target["public_key_fingerprint"] is not None,
        "private_material_detected": False,
        "fake_verified_claim_detected": False,
        "revoked_detected": False,
        "unknown_treated_as_good_detected": False,
        "real_ocsp_verification_performed": False,
        "real_crl_verification_performed": False,
    }

    candidate = {
        "revocation_evidence": revocation_evidence,
    }

    checks["private_material_detected"] = contains_private_material(candidate)
    checks["fake_verified_claim_detected"] = has_fake_verified_claim(candidate)

    # Stage361 default is intentionally pending because no real OCSP/CRL proof is injected yet.
    revocation_status = "pending"
    decision = "pending_revocation_proof"

    block_reasons = []

    if not checks["stage360_result_present"]:
        block_reasons.append("stage360_result_missing")

    if checks["private_material_detected"]:
        block_reasons.append("private_material_detected")

    if checks["fake_verified_claim_detected"]:
        block_reasons.append("fake_verified_claim_detected")

    if checks["revoked_detected"]:
        block_reasons.append("revoked_status_detected")

    if checks["unknown_treated_as_good_detected"]:
        block_reasons.append("unknown_treated_as_good_detected")

    if block_reasons:
        decision = "block"
        revocation_status = "blocked"

    result = {
        "stage": STAGE,
        "engine": "Revocation Proof Injection Gate with Stage360 External Timestamp Binding",
        "created_at": now,
        "source_stage": 360,
        "previous_hash": previous_hash,
        "revocation_target": revocation_target,
        "revocation_status": revocation_status,
        "decision": decision,
        "block_reasons": block_reasons,
        "checks": checks,
        "revocation_evidence": revocation_evidence,
        "safety_boundary": {
            "no_private_keys": True,
            "no_raw_secrets": True,
            "no_raw_qkd_key_material": True,
            "no_real_ocsp_verified_claim": True,
            "no_real_crl_verified_claim": True,
            "safe_metadata_only": True
        },
        "guarantee": {
            "what_stage361_guarantees": [
                "Stage360 result hash is bound as previous_hash when present.",
                "A revocation proof receiver is created for OCSP, CRL, and signed revocation metadata.",
                "The system does not falsely claim real OCSP or CRL verification.",
                "Missing proof remains pending_revocation_proof.",
                "Dangerous or false verified claims are blocked."
            ],
            "what_stage361_does_not_guarantee": [
                "It does not perform real OCSP response signature verification.",
                "It does not perform real CRL signature verification.",
                "It does not prove that the certificate is currently good.",
                "It does not handle private keys or raw secrets."
            ]
        }
    }

    canonical = json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2)
    result["result_sha256"] = sha256_text(canonical)

    OUT_JSON.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")

    OUT_SUMMARY.write_text(
        "\n".join([
            "Stage361: Revocation Proof Injection Gate",
            "with Stage360 External Timestamp Binding",
            "",
            f"Decision: {decision}",
            f"Revocation Status: {revocation_status}",
            f"Previous Hash: {previous_hash}",
            f"Result SHA256: {result['result_sha256']}",
            "",
            "Meaning:",
            "Stage361 adds a safe revocation proof receiver into the QSP evidence rail.",
            "It does not falsely claim real OCSP or CRL verification.",
            "Without real proof, the correct decision is pending_revocation_proof.",
        ]),
        encoding="utf-8"
    )

    print(f"decision={decision}")
    print(f"revocation_status={revocation_status}")
    print(f"previous_hash={previous_hash}")
    print(f"result_sha256={result['result_sha256']}")


if __name__ == "__main__":
    main()
