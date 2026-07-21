import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional


STAGE = 373

ROOT = Path(".")
DOCS = ROOT / "docs"

STAGE372_DIR = DOCS / "timestamp-final-acceptance"
STAGE372_RESULT = (
    STAGE372_DIR
    / "stage372_timestamp_verification_final_acceptance_result.json"
)
STAGE372_MANIFEST = (
    STAGE372_DIR
    / "stage372_final_acceptance_manifest.json"
)

OUT_DIR = DOCS / "final-acceptance-attestation"

INPUT_JSON = (
    OUT_DIR
    / "stage373_external_transparency_input.json"
)
OUT_ATTESTATION = (
    OUT_DIR
    / "stage373_final_acceptance_attestation.json"
)
OUT_RESULT = (
    OUT_DIR
    / "stage373_external_transparency_binding_result.json"
)
OUT_SUMMARY = (
    OUT_DIR
    / "stage373_external_transparency_binding_summary.txt"
)

OUT_DIR.mkdir(parents=True, exist_ok=True)


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_text(text: str) -> str:
    return sha256_bytes(text.encode("utf-8"))


def read_json(path: Path) -> Optional[Dict[str, Any]]:
    if not path.exists():
        return None

    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None

    return value if isinstance(value, dict) else None


def canonical_json(value: Dict[str, Any]) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        indent=2,
    )


def recompute_self_hashed_json(
    value: Optional[Dict[str, Any]],
    self_hash_field: str,
) -> Optional[str]:
    if not isinstance(value, dict):
        return None

    copy_value = dict(value)
    copy_value.pop(self_hash_field, None)

    return sha256_text(canonical_json(copy_value))


def is_sha256(value: Any) -> bool:
    if not isinstance(value, str) or len(value) != 64:
        return False

    try:
        int(value, 16)
    except ValueError:
        return False

    return True


def contains_private_material(value: Any) -> bool:
    dangerous_exact_keys = {
        "private_key",
        "private_key_material",
        "raw_private_key",
        "raw_secret",
        "raw_qkd_key",
        "seed_phrase",
        "password",
        "api_key",
        "access_token",
        "id_token",
        "refresh_token",
        "client_secret",
        "secret_key",
        "oidc_token",
    }

    private_markers = {
        "-----begin private key-----",
        "-----begin rsa private key-----",
        "-----begin ec private key-----",
        "-----begin openssh private key-----",
        "-----begin encrypted private key-----",
    }

    def scan(item: Any) -> bool:
        if isinstance(item, dict):
            for key, child in item.items():
                normalized_key = str(key).strip().lower()

                if normalized_key in dangerous_exact_keys:
                    if child not in (None, "", False, [], {}):
                        return True

                if scan(child):
                    return True

            return False

        if isinstance(item, list):
            return any(scan(child) for child in item)

        if isinstance(item, str):
            lowered = item.lower()
            return any(marker in lowered for marker in private_markers)

        return False

    return scan(value)


def raw_private_or_timestamp_file_detected() -> bool:
    forbidden_suffixes = {
        ".ots",
        ".tsr",
        ".tsa",
        ".token",
        ".der",
        ".key",
        ".pem",
        ".p12",
        ".pfx",
        ".seed",
    }

    for path in DOCS.rglob("*"):
        if path.is_file() and path.suffix.lower() in forbidden_suffixes:
            return True

    return False


def non_empty(value: Any) -> bool:
    return value not in (None, "", False, [], {})


def main() -> None:
    now = datetime.now(timezone.utc).isoformat()

    stage372_result = read_json(STAGE372_RESULT)
    stage372_manifest = read_json(STAGE372_MANIFEST)
    external_input = read_json(INPUT_JSON)

    stage372_result_declared_sha256 = (
        stage372_result.get("result_sha256")
        if isinstance(stage372_result, dict)
        else None
    )

    stage372_result_recomputed_sha256 = recompute_self_hashed_json(
        stage372_result,
        "result_sha256",
    )

    stage372_manifest_declared_sha256 = (
        stage372_manifest.get("manifest_sha256")
        if isinstance(stage372_manifest, dict)
        else None
    )

    stage372_manifest_recomputed_sha256 = recompute_self_hashed_json(
        stage372_manifest,
        "manifest_sha256",
    )

    embedded_manifest = (
        stage372_result.get("final_acceptance_manifest")
        if isinstance(stage372_result, dict)
        else None
    )

    embedded_manifest_sha256 = (
        embedded_manifest.get("manifest_sha256")
        if isinstance(embedded_manifest, dict)
        else None
    )

    stage372_decision = (
        stage372_result.get("decision")
        if isinstance(stage372_result, dict)
        else None
    )

    stage372_timestamp_verified = (
        stage372_result.get("timestamp_verified")
        if isinstance(stage372_result, dict)
        else False
    )

    stage372_manifest_decision = (
        stage372_manifest.get("decision")
        if isinstance(stage372_manifest, dict)
        else None
    )

    stage372_manifest_timestamp_verified = (
        stage372_manifest.get("timestamp_verified")
        if isinstance(stage372_manifest, dict)
        else False
    )

    binding_payload = {
        "source_stage": 372,
        "stage372_result_sha256": stage372_result_declared_sha256,
        "stage372_manifest_sha256": stage372_manifest_declared_sha256,
        "stage372_decision": stage372_decision,
        "stage372_timestamp_verified": stage372_timestamp_verified,
    }

    stage372_binding_sha256 = sha256_text(
        canonical_json(binding_payload)
    )

    attestation = {
        "stage": STAGE,
        "attestation_type": (
            "stage372_final_acceptance_external_transparency_attestation"
        ),
        "created_at": now,
        "source_stage": 372,
        "previous_hash": stage372_result_declared_sha256,
        "stage372_result_sha256": stage372_result_declared_sha256,
        "stage372_manifest_sha256": stage372_manifest_declared_sha256,
        "stage372_binding_sha256": stage372_binding_sha256,
        "stage372_decision": stage372_decision,
        "stage372_timestamp_verified": stage372_timestamp_verified,
        "binding_payload": binding_payload,
    }

    attestation_sha256 = sha256_text(canonical_json(attestation))
    attestation["attestation_sha256"] = attestation_sha256

    sigstore = (
        external_input.get("sigstore", {})
        if isinstance(external_input, dict)
        else {}
    )

    rekor = (
        external_input.get("rekor", {})
        if isinstance(external_input, dict)
        else {}
    )

    pqc = (
        external_input.get("pqc", {})
        if isinstance(external_input, dict)
        else {}
    )

    execute_external_verification = bool(
        external_input.get("execute_external_verification", False)
        if isinstance(external_input, dict)
        else False
    )

    sigstore_claimed_verified = bool(
        sigstore.get("signature_verified")
    )
    identity_claimed_verified = bool(
        sigstore.get("identity_verified")
    )
    issuer_claimed_verified = bool(
        sigstore.get("oidc_issuer_verified")
    )

    rekor_set_claimed_verified = bool(
        rekor.get("signed_entry_timestamp_verified")
    )
    rekor_inclusion_claimed_verified = bool(
        rekor.get("inclusion_proof_verified")
    )
    rekor_digest_claimed_matching = bool(
        rekor.get("artifact_digest_matches")
    )

    pqc_claimed_verified = bool(
        pqc.get("verified")
    )

    sigstore_receipt_complete = all([
        sigstore.get("verification_exit_code") == 0,
        is_sha256(sigstore.get("verification_output_sha256")),
        is_sha256(sigstore.get("bundle_sha256")),
        sigstore.get("signed_attestation_sha256")
            == attestation_sha256,
        non_empty(sigstore.get("verified_identity")),
        non_empty(sigstore.get("verified_oidc_issuer")),
    ])

    rekor_log_index = rekor.get("log_index")

    rekor_metadata_complete = all([
        non_empty(rekor.get("log_id")),
        isinstance(rekor_log_index, int),
        (
            rekor_log_index >= 0
            if isinstance(rekor_log_index, int)
            else False
        ),
        non_empty(rekor.get("entry_uuid")),
        non_empty(rekor.get("integrated_time")),
        rekor.get("artifact_digest") == attestation_sha256,
    ])

    pqc_receipt_complete = all([
        pqc.get("status") == "verified",
        pqc.get("verification_exit_code") == 0,
        is_sha256(pqc.get("verification_output_sha256")),
        is_sha256(pqc.get("signature_sha256")),
        is_sha256(pqc.get("public_key_fingerprint")),
        pqc.get("signed_attestation_sha256")
            == attestation_sha256,
    ])

    sigstore_verified = all([
        execute_external_verification,
        sigstore_claimed_verified,
        identity_claimed_verified,
        issuer_claimed_verified,
        sigstore_receipt_complete,
    ])

    rekor_verified = all([
        execute_external_verification,
        rekor_set_claimed_verified,
        rekor_inclusion_claimed_verified,
        rekor_digest_claimed_matching,
        rekor_metadata_complete,
    ])

    pqc_verified = all([
        execute_external_verification,
        pqc_claimed_verified,
        pqc_receipt_complete,
    ])

    stage372_final_acceptance = all([
        stage372_decision == "timestamp_verified",
        stage372_timestamp_verified is True,
        stage372_manifest_decision == "timestamp_verified",
        stage372_manifest_timestamp_verified is True,
    ])

    checks = {
        "stage372_result_present": stage372_result is not None,
        "stage372_manifest_present": stage372_manifest is not None,
        "stage373_input_present": external_input is not None,

        "stage372_result_declared_sha256_valid":
            is_sha256(stage372_result_declared_sha256),
        "stage372_result_sha256_matches":
            stage372_result_declared_sha256
            == stage372_result_recomputed_sha256,

        "stage372_manifest_declared_sha256_valid":
            is_sha256(stage372_manifest_declared_sha256),
        "stage372_manifest_sha256_matches":
            stage372_manifest_declared_sha256
            == stage372_manifest_recomputed_sha256,

        "embedded_manifest_sha256_matches":
            embedded_manifest_sha256
            == stage372_manifest_declared_sha256,

        "stage372_result_manifest_decision_consistent":
            stage372_decision
            == stage372_manifest_decision,

        "stage372_result_manifest_timestamp_consistent":
            stage372_timestamp_verified
            == stage372_manifest_timestamp_verified,

        "stage372_binding_sha256_generated":
            is_sha256(stage372_binding_sha256),

        "attestation_sha256_generated":
            is_sha256(attestation_sha256),

        "execute_external_verification":
            execute_external_verification,

        "sigstore_receipt_complete":
            sigstore_receipt_complete,
        "sigstore_signature_verified":
            sigstore_verified,
        "sigstore_identity_verified":
            sigstore_verified and identity_claimed_verified,
        "sigstore_oidc_issuer_verified":
            sigstore_verified and issuer_claimed_verified,

        "rekor_metadata_complete":
            rekor_metadata_complete,
        "rekor_signed_entry_timestamp_verified":
            rekor_verified and rekor_set_claimed_verified,
        "rekor_inclusion_proof_verified":
            rekor_verified and rekor_inclusion_claimed_verified,
        "rekor_artifact_digest_matches":
            rekor_verified and rekor_digest_claimed_matching,

        "pqc_receipt_complete":
            pqc_receipt_complete,
        "pqc_signature_verified":
            pqc_verified,

        "private_material_detected":
            contains_private_material({
                "stage372_result": stage372_result,
                "stage372_manifest": stage372_manifest,
                "external_input": external_input,
            }),

        "raw_private_or_timestamp_file_detected":
            raw_private_or_timestamp_file_detected(),
    }

    fake_external_verified_claim = any([
        sigstore_claimed_verified,
        identity_claimed_verified,
        issuer_claimed_verified,
        rekor_set_claimed_verified,
        rekor_inclusion_claimed_verified,
        rekor_digest_claimed_matching,
    ]) and not all([
        execute_external_verification,
        sigstore_receipt_complete,
        rekor_metadata_complete,
    ])

    fake_pqc_verified_claim = (
        pqc_claimed_verified
        and not all([
            execute_external_verification,
            pqc_receipt_complete,
        ])
    )

    external_transparency_bound = all([
        sigstore_verified,
        rekor_verified,
    ])

    decision = "attestation_pending"
    reasons = []

    mandatory_integrity_checks = [
        "stage372_result_present",
        "stage372_manifest_present",
        "stage373_input_present",
        "stage372_result_declared_sha256_valid",
        "stage372_result_sha256_matches",
        "stage372_manifest_declared_sha256_valid",
        "stage372_manifest_sha256_matches",
        "embedded_manifest_sha256_matches",
        "stage372_result_manifest_decision_consistent",
        "stage372_result_manifest_timestamp_consistent",
        "stage372_binding_sha256_generated",
        "attestation_sha256_generated",
    ]

    failed_integrity_checks = [
        name
        for name in mandatory_integrity_checks
        if not checks[name]
    ]

    if failed_integrity_checks:
        decision = "block"
        reasons.extend(
            f"integrity_check_failed:{name}"
            for name in failed_integrity_checks
        )

    elif checks["private_material_detected"]:
        decision = "block"
        reasons.append("private_material_detected")

    elif checks["raw_private_or_timestamp_file_detected"]:
        decision = "block"
        reasons.append(
            "raw_private_or_timestamp_file_detected_in_public_docs"
        )

    elif fake_external_verified_claim:
        decision = "block"
        reasons.append(
            "unsubstantiated_sigstore_or_rekor_verified_claim"
        )

    elif fake_pqc_verified_claim:
        decision = "block"
        reasons.append(
            "unsubstantiated_pqc_verified_claim"
        )

    elif external_transparency_bound:
        if stage372_final_acceptance:
            if pqc_verified:
                decision = "final_acceptance_dual_signature_bound"
                reasons.append(
                    "final_acceptance_sigstore_rekor_and_pqc_verified"
                )
            else:
                decision = "final_acceptance_transparency_bound"
                reasons.append(
                    "final_acceptance_sigstore_and_rekor_verified"
                )
        else:
            decision = "pending_state_transparency_bound"
            reasons.append(
                "stage372_pending_state_sigstore_and_rekor_verified"
            )

    else:
        decision = "attestation_pending"

        if not execute_external_verification:
            reasons.append(
                "external_verification_not_executed"
            )

        if stage372_decision == "final_acceptance_pending":
            reasons.append(
                "stage372_final_acceptance_pending"
            )

        if not sigstore_verified:
            reasons.append(
                "sigstore_verification_pending"
            )

        if not rekor_verified:
            reasons.append(
                "rekor_inclusion_verification_pending"
            )

        if not pqc_verified:
            reasons.append(
                "pqc_signature_verification_pending"
            )

    result = {
        "stage": STAGE,
        "engine": (
            "Final Acceptance Attestation and "
            "External Transparency Binding Gate"
        ),
        "created_at": now,
        "source_stage": 372,

        "previous_hash": stage372_result_declared_sha256,
        "stage372_result_sha256": stage372_result_declared_sha256,
        "stage372_manifest_sha256": stage372_manifest_declared_sha256,
        "stage372_binding_sha256": stage372_binding_sha256,
        "attestation_sha256": attestation_sha256,

        "stage372_decision": stage372_decision,
        "stage372_timestamp_verified": stage372_timestamp_verified,
        "stage372_final_acceptance": stage372_final_acceptance,

        "decision": decision,
        "external_transparency_bound":
            external_transparency_bound,
        "pqc_signature_verified":
            pqc_verified,

        "reasons": reasons,
        "checks": checks,

        "external_verification": {
            "sigstore": {
                "status": sigstore.get("status"),
                "bundle_sha256":
                    sigstore.get("bundle_sha256"),
                "signature_verified":
                    sigstore_verified,
                "identity_verified":
                    sigstore_verified
                    and identity_claimed_verified,
                "oidc_issuer_verified":
                    sigstore_verified
                    and issuer_claimed_verified,
            },
            "rekor": {
                "status": rekor.get("status"),
                "log_id": rekor.get("log_id"),
                "log_index": rekor.get("log_index"),
                "entry_uuid": rekor.get("entry_uuid"),
                "integrated_time":
                    rekor.get("integrated_time"),
                "artifact_digest_matches":
                    rekor_verified
                    and rekor_digest_claimed_matching,
                "signed_entry_timestamp_verified":
                    rekor_verified
                    and rekor_set_claimed_verified,
                "inclusion_proof_verified":
                    rekor_verified
                    and rekor_inclusion_claimed_verified,
            },
            "pqc": {
                "algorithm": pqc.get("algorithm"),
                "algorithm_policy_status":
                    pqc.get("algorithm_policy_status"),
                "mode": pqc.get("mode"),
                "status": pqc.get("status"),
                "verified": pqc_verified,
            },
        },

        "safety_boundary": {
            "no_private_keys": True,
            "no_raw_secrets": True,
            "no_oidc_tokens": True,
            "no_raw_qkd_key_material": True,
            "no_raw_timestamp_binaries_in_public_docs": True,
            "public_keys_and_signatures_may_be_public":
                True,
            "sigstore_bundle_may_be_public":
                True,
            "metadata_only_until_real_verification":
                True,
        },

        "guarantee": {
            "what_stage373_guarantees": [
                (
                    "Stage372 result and manifest are independently "
                    "hash-validated."
                ),
                (
                    "Stage372 result and manifest are bound into one "
                    "canonical attestation."
                ),
                (
                    "Stage372 pending status is not converted into "
                    "final acceptance."
                ),
                (
                    "Sigstore and Rekor verification remain pending "
                    "until complete verification receipts exist."
                ),
                (
                    "ML-DSA remains unverified until real standalone "
                    "verification evidence exists."
                ),
                (
                    "Unsupported verified claims and public secret "
                    "material are blocked."
                ),
            ],
            "what_stage373_does_not_guarantee": [
                (
                    "It does not execute Cosign, Rekor, or ML-DSA "
                    "commands by default."
                ),
                (
                    "It does not claim Stage372 timestamp verification "
                    "has succeeded while Stage372 remains pending."
                ),
                (
                    "It does not claim native ML-DSA integration with "
                    "Sigstore or Rekor."
                ),
                (
                    "It does not publish private keys, OIDC tokens, "
                    "QKD raw keys, or raw timestamp binaries."
                ),
            ],
        },
    }

    result_sha256 = sha256_text(canonical_json(result))
    result["result_sha256"] = result_sha256

    OUT_ATTESTATION.write_text(
        json.dumps(
            attestation,
            ensure_ascii=False,
            indent=2,
        ),
        encoding="utf-8",
    )

    OUT_RESULT.write_text(
        json.dumps(
            result,
            ensure_ascii=False,
            indent=2,
        ),
        encoding="utf-8",
    )

    summary_lines = [
        "Stage373: Final Acceptance Attestation",
        "and External Transparency Binding Gate",
        "",
        f"Decision: {decision}",
        (
            "Stage372 Final Acceptance: "
            f"{stage372_final_acceptance}"
        ),
        (
            "External Transparency Bound: "
            f"{external_transparency_bound}"
        ),
        f"PQC Signature Verified: {pqc_verified}",
        "",
        (
            "Previous Hash: "
            f"{stage372_result_declared_sha256}"
        ),
        (
            "Stage372 Manifest SHA256: "
            f"{stage372_manifest_declared_sha256}"
        ),
        (
            "Stage372 Binding SHA256: "
            f"{stage372_binding_sha256}"
        ),
        (
            "Attestation SHA256: "
            f"{attestation_sha256}"
        ),
        f"Result SHA256: {result_sha256}",
        "",
        "Reasons:",
    ]

    summary_lines.extend(
        f"- {reason}" for reason in reasons
    )

    summary_lines.extend([
        "",
        "Meaning:",
        (
            "Stage373 binds the Stage372 result and manifest into "
            "one final-acceptance attestation."
        ),
        (
            "Because Stage372 is currently pending and no real "
            "Sigstore, Rekor, or ML-DSA verification has been "
            "executed, the correct initial decision is "
            "attestation_pending."
        ),
        (
            "Stage373 never converts a pending Stage372 result into "
            "a verified final acceptance."
        ),
    ])

    OUT_SUMMARY.write_text(
        "\n".join(summary_lines) + "\n",
        encoding="utf-8",
    )

    print(f"decision={decision}")
    print(
        "stage372_final_acceptance="
        f"{stage372_final_acceptance}"
    )
    print(
        "external_transparency_bound="
        f"{external_transparency_bound}"
    )
    print(
        "pqc_signature_verified="
        f"{pqc_verified}"
    )
    print(
        "stage372_binding_sha256="
        f"{stage372_binding_sha256}"
    )
    print(
        "attestation_sha256="
        f"{attestation_sha256}"
    )
    print(f"result_sha256={result_sha256}")


if __name__ == "__main__":
    main()
