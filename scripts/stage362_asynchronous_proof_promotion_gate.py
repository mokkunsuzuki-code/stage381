import json
import hashlib
from pathlib import Path
from datetime import datetime, timezone

STAGE = 362

ROOT = Path(".")
DOCS = ROOT / "docs"
PROMOTION_DIR = DOCS / "promotion"

STAGE361_RESULT = DOCS / "revocation" / "stage361_revocation_proof_injection_result.json"
PROMOTION_REQUEST = PROMOTION_DIR / "stage362_promotion_request.json"

OUT_JSON = PROMOTION_DIR / "stage362_asynchronous_proof_promotion_result.json"
OUT_SUMMARY = PROMOTION_DIR / "stage362_asynchronous_proof_promotion_summary.txt"

PROMOTION_DIR.mkdir(parents=True, exist_ok=True)


def sha256_file(path: Path):
    if not path.exists():
        return None
    return hashlib.sha256(path.read_bytes()).hexdigest()


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def read_json(path: Path):
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def contains_private_material(obj) -> bool:
    raw = json.dumps(obj, ensure_ascii=False).lower()
    dangerous = [
        "-----begin private key-----",
        "-----begin rsa private key-----",
        "-----begin ec private key-----",
        "raw_private_key",
        "private_key_material",
        "raw_secret",
        "raw_qkd_key",
        "seed_phrase",
    ]
    return any(x in raw for x in dangerous)


def fake_verified_claim(obj) -> bool:
    raw = json.dumps(obj, ensure_ascii=False).lower()

    verified_claims = [
        '"ocsp_verified": true',
        '"crl_verified": true',
        '"timestamp_verified": true',
        '"rekor_verified": true',
        '"revocation_verified": true',
        '"verified": true',
    ]

    proof_markers = [
        "ocsp_response_der_sha256",
        "crl_der_sha256",
        "timestamp_token_sha256",
        "ots_proof_sha256",
        "rfc3161_token_sha256",
        "rekor_entry_uuid",
        "rekor_entry_sha256",
        "signed_revocation_metadata_sha256",
        "signature_verification_evidence_sha256",
    ]

    has_verified_claim = any(x in raw for x in verified_claims)
    has_proof_marker = any(x in raw for x in proof_markers)

    return has_verified_claim and not has_proof_marker


def main():
    now = datetime.now(timezone.utc).isoformat()

    stage361 = read_json(STAGE361_RESULT)
    previous_hash = sha256_file(STAGE361_RESULT)

    if PROMOTION_REQUEST.exists():
        promotion_request = read_json(PROMOTION_REQUEST)
    else:
        promotion_request = {
            "stage": 362,
            "promotion_target": "stage361_revocation_proof",
            "requested_promotion": "pending_to_accept",
            "proof_type": "none",
            "proof_sha256": None,
            "claimed_status": "pending",
            "verified_claim": False,
            "note": "Default placeholder. No real asynchronous proof has been injected yet."
        }
        PROMOTION_REQUEST.write_text(
            json.dumps(promotion_request, ensure_ascii=False, indent=2),
            encoding="utf-8"
        )

    checks = {
        "stage361_result_present": stage361 is not None,
        "stage361_previous_hash_bound": previous_hash is not None,
        "promotion_request_present": promotion_request is not None,
        "promotion_target_matches": promotion_request.get("promotion_target") == "stage361_revocation_proof",
        "proof_sha256_present": bool(promotion_request.get("proof_sha256")),
        "claimed_status": promotion_request.get("claimed_status"),
        "verified_claim": promotion_request.get("verified_claim") is True,
        "private_material_detected": contains_private_material(promotion_request),
        "fake_verified_claim_detected": fake_verified_claim(promotion_request),
        "revoked_detected": promotion_request.get("claimed_status") == "revoked",
        "unknown_treated_as_good_detected": (
            promotion_request.get("claimed_status") == "unknown"
            and promotion_request.get("requested_promotion") == "pending_to_accept"
        ),
    }

    decision = "keep_pending"
    promotion_status = "not_promoted"
    reasons = []

    if not checks["stage361_result_present"]:
        decision = "block"
        reasons.append("stage361_result_missing")

    elif stage361.get("decision") == "block":
        decision = "block"
        reasons.append("stage361_is_blocked")

    elif checks["private_material_detected"]:
        decision = "block"
        reasons.append("private_material_detected")

    elif checks["fake_verified_claim_detected"]:
        decision = "block"
        reasons.append("fake_verified_claim_detected")

    elif checks["revoked_detected"]:
        decision = "block"
        reasons.append("revoked_status_detected")

    elif checks["unknown_treated_as_good_detected"]:
        decision = "block"
        reasons.append("unknown_treated_as_good_detected")

    elif not checks["promotion_target_matches"]:
        decision = "reject_promotion"
        reasons.append("promotion_target_mismatch")

    elif not checks["proof_sha256_present"]:
        decision = "keep_pending"
        reasons.append("proof_missing")

    elif checks["proof_sha256_present"] and checks["verified_claim"]:
        decision = "promote"
        promotion_status = "promoted"
        reasons.append("promotion_evidence_present_and_verified_claim_declared")

    else:
        decision = "reject_promotion"
        reasons.append("proof_present_but_not_verified")

    result = {
        "stage": STAGE,
        "engine": "Asynchronous Proof Promotion Gate with Stage361 Revocation Proof Binding",
        "created_at": now,
        "source_stage": 361,
        "previous_hash": previous_hash,
        "stage361_decision": stage361.get("decision") if isinstance(stage361, dict) else None,
        "promotion_status": promotion_status,
        "decision": decision,
        "reasons": reasons,
        "checks": checks,
        "promotion_request": promotion_request,
        "safety_boundary": {
            "no_private_keys": True,
            "no_raw_secrets": True,
            "no_raw_qkd_key_material": True,
            "no_false_verified_claims": True,
            "pending_is_not_treated_as_accept": True,
            "unknown_is_not_treated_as_good": True
        },
        "guarantee": {
            "what_stage362_guarantees": [
                "Stage361 result is bound as previous_hash when present.",
                "Pending proof is not automatically accepted.",
                "A promotion request can be evaluated asynchronously.",
                "Missing proof remains keep_pending.",
                "Mismatched or insufficient proof becomes reject_promotion.",
                "Revoked status, fake verified claims, unknown-as-good, and secret leakage are blocked."
            ],
            "what_stage362_does_not_guarantee": [
                "It does not perform real OCSP cryptographic verification.",
                "It does not perform real CRL cryptographic verification.",
                "It does not perform real OpenTimestamps or RFC3161 verification.",
                "It does not perform real Rekor verification.",
                "It does not prove that a certificate is currently good."
            ]
        }
    }

    canonical = json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2)
    result["result_sha256"] = sha256_text(canonical)

    OUT_JSON.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")

    OUT_SUMMARY.write_text(
        "\n".join([
            "Stage362: Asynchronous Proof Promotion Gate",
            "with Stage361 Revocation Proof Binding",
            "",
            f"Decision: {decision}",
            f"Promotion Status: {promotion_status}",
            f"Previous Hash: {previous_hash}",
            f"Result SHA256: {result['result_sha256']}",
            "",
            "Meaning:",
            "Stage362 does not treat pending proof as acceptance.",
            "It creates a safe promotion gate for asynchronous proof updates.",
            "Without real proof, the correct decision is keep_pending.",
        ]),
        encoding="utf-8"
    )

    print(f"decision={decision}")
    print(f"promotion_status={promotion_status}")
    print(f"previous_hash={previous_hash}")
    print(f"result_sha256={result['result_sha256']}")


if __name__ == "__main__":
    main()
