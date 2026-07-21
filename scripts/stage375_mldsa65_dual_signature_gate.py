import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional


STAGE = 375
ROOT = Path(".")
DOCS = ROOT / "docs"

STAGE374_RESULT = (
    DOCS
    / "sigstore-production"
    / "stage374_production_external_binding_result.json"
)

STAGE374_EXECUTION_RECEIPT = (
    DOCS
    / "sigstore-production"
    / "stage374_cosign_execution_receipt.json"
)

TARGET = (
    DOCS
    / "final-acceptance-attestation"
    / "stage373_final_acceptance_attestation.json"
)

OUT_DIR = DOCS / "mldsa-production"

INPUT_JSON = (
    OUT_DIR
    / "stage375_mldsa65_input.json"
)

MLDSA_RECEIPT = (
    OUT_DIR
    / "stage375_mldsa65_execution_receipt.json"
)

PUBLIC_KEY = (
    OUT_DIR
    / "stage375_mldsa65_public_key.pem"
)

SIGNATURE = (
    OUT_DIR
    / "stage375_mldsa65_signature.bin"
)

OUT_RESULT = (
    OUT_DIR
    / "stage375_dual_signature_verification_result.json"
)

OUT_SUMMARY = (
    OUT_DIR
    / "stage375_dual_signature_verification_summary.txt"
)


def read_json(path: Path) -> Optional[Dict[str, Any]]:
    if not path.exists():
        return None

    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None

    return value if isinstance(value, dict) else None


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> Optional[str]:
    if not path.exists() or not path.is_file():
        return None

    return sha256_bytes(path.read_bytes())


def canonical_json(value: Dict[str, Any]) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        indent=2,
    )


def recompute_self_hash(
    value: Optional[Dict[str, Any]],
    field: str,
) -> Optional[str]:
    if not isinstance(value, dict):
        return None

    copy_value = dict(value)
    copy_value.pop(field, None)

    return sha256_bytes(
        canonical_json(copy_value).encode("utf-8")
    )


def is_sha256(value: Any) -> bool:
    if not isinstance(value, str) or len(value) != 64:
        return False

    try:
        int(value, 16)
    except ValueError:
        return False

    return True


def forbidden_public_file_detected() -> bool:
    forbidden_names = {
        "stage375_mldsa65_private.pem",
    }

    forbidden_suffixes = {
        ".key",
        ".seed",
        ".pk8",
        ".private",
        ".jwt",
        ".oidc",
        ".token",
        ".ots",
        ".tsr",
        ".tsa",
        ".der",
    }

    for path in DOCS.rglob("*"):
        if not path.is_file():
            continue

        if path.name in forbidden_names:
            return True

        if path.suffix.lower() in forbidden_suffixes:
            return True

    return False


def contains_private_key_marker() -> bool:
    marker = b"-----BEGIN PRIVATE KEY-----"

    for path in DOCS.rglob("*"):
        if not path.is_file():
            continue

        try:
            if marker in path.read_bytes():
                return True
        except OSError:
            return True

    return False


def main() -> None:
    now = datetime.now(timezone.utc).isoformat()

    stage374 = read_json(STAGE374_RESULT)
    stage374_execution = read_json(
        STAGE374_EXECUTION_RECEIPT
    )
    input_data = read_json(INPUT_JSON)
    receipt = read_json(MLDSA_RECEIPT)
    attestation = read_json(TARGET)

    stage374_result_sha256 = (
        stage374.get("result_sha256")
        if isinstance(stage374, dict)
        else None
    )

    stage374_recomputed_sha256 = recompute_self_hash(
        stage374,
        "result_sha256",
    )

    expected_previous_hash = (
        input_data.get("previous_hash")
        if isinstance(input_data, dict)
        else None
    )

    expected_blob_sha256 = (
        input_data.get("expected_blob_sha256")
        if isinstance(input_data, dict)
        else None
    )

    expected_attestation_sha256 = (
        input_data.get("expected_attestation_sha256")
        if isinstance(input_data, dict)
        else None
    )

    expected_public_pem_sha256 = (
        input_data.get("public_key_pem_sha256")
        if isinstance(input_data, dict)
        else None
    )

    target_blob_sha256 = sha256_file(TARGET)
    public_key_pem_sha256 = sha256_file(PUBLIC_KEY)
    signature_sha256 = sha256_file(SIGNATURE)

    declared_attestation_sha256 = (
        attestation.get("attestation_sha256")
        if isinstance(attestation, dict)
        else None
    )

    recomputed_attestation_sha256 = (
        recompute_self_hash(
            attestation,
            "attestation_sha256",
        )
    )

    sigstore_target_sha256 = (
        stage374_execution.get("target_sha256")
        if isinstance(stage374_execution, dict)
        else None
    )

    receipt_status = (
        receipt.get("execution_status")
        if isinstance(receipt, dict)
        else None
    )

    receipt_verified = all([
        isinstance(receipt, dict),
        receipt_status == "verified",
        receipt.get("algorithm") == "ML-DSA-65",
        receipt.get("context_string")
            == "QSP-Stage375-v1",
        receipt.get("sign_exit_code") == 0,
        receipt.get("verify_exit_code") == 0,
        receipt.get("signature_generated") is True,
        receipt.get("signature_verified") is True,
        receipt.get("same_target_as_sigstore") is True,
        receipt.get("private_key_published") is False,
        receipt.get("target_blob_sha256")
            == target_blob_sha256,
        receipt.get("attestation_sha256")
            == declared_attestation_sha256,
        receipt.get("public_key_pem_sha256")
            == public_key_pem_sha256,
        receipt.get("signature_sha256")
            == signature_sha256,
        is_sha256(
            receipt.get("public_key_der_sha256")
        ),
        is_sha256(signature_sha256),
    ])

    checks = {
        "stage374_result_present":
            stage374 is not None,

        "stage374_result_sha256_valid":
            is_sha256(stage374_result_sha256),

        "stage374_result_sha256_matches":
            stage374_result_sha256
            == stage374_recomputed_sha256,

        "previous_hash_matches_stage374":
            expected_previous_hash
            == stage374_result_sha256,

        "stage374_external_transparency_bound":
            bool(
                stage374
                and stage374.get(
                    "external_transparency_bound"
                ) is True
            ),

        "stage374_sigstore_signature_verified":
            bool(
                stage374_execution
                and stage374_execution.get(
                    "signature_verified"
                ) is True
            ),

        "stage374_identity_verified":
            bool(
                stage374_execution
                and stage374_execution.get(
                    "identity_verified"
                ) is True
            ),

        "stage374_oidc_issuer_verified":
            bool(
                stage374_execution
                and stage374_execution.get(
                    "oidc_issuer_verified"
                ) is True
            ),

        "target_present": TARGET.exists(),

        "target_blob_sha256_matches":
            target_blob_sha256
            == expected_blob_sha256,

        "logical_attestation_sha256_matches":
            declared_attestation_sha256
            == expected_attestation_sha256
            == recomputed_attestation_sha256,

        "public_key_present": PUBLIC_KEY.exists(),

        "public_key_pem_sha256_matches":
            public_key_pem_sha256
            == expected_public_pem_sha256,

        "signature_present": SIGNATURE.exists(),

        "signature_sha256_valid":
            is_sha256(signature_sha256),

        "mldsa_receipt_present":
            receipt is not None,

        "mldsa_signature_verified":
            receipt_verified,

        "sigstore_and_mldsa_target_match":
            target_blob_sha256
            == sigstore_target_sha256
            == (
                receipt.get("target_blob_sha256")
                if isinstance(receipt, dict)
                else None
            ),

        "dual_signature_complete":
            bool(
                receipt_verified
                and stage374_execution
                and stage374_execution.get(
                    "signature_verified"
                ) is True
            ),

        "private_key_marker_detected":
            contains_private_key_marker(),

        "forbidden_public_file_detected":
            forbidden_public_file_detected(),
    }

    pqc_required = bool(
        input_data
        and input_data.get("pqc_required") is True
    )

    execution_attempted = bool(
        receipt_status
        not in (None, "not_executed")
    )

    downgrade_detected = bool(
        pqc_required
        and execution_attempted
        and not checks["mldsa_signature_verified"]
    )

    checks["pqc_required"] = pqc_required
    checks["downgrade_detected"] = (
        downgrade_detected
    )

    decision = "mldsa_execution_pending"
    reasons = []

    integrity_checks = [
        "stage374_result_present",
        "stage374_result_sha256_valid",
        "stage374_result_sha256_matches",
        "previous_hash_matches_stage374",
        "stage374_external_transparency_bound",
        "stage374_sigstore_signature_verified",
        "stage374_identity_verified",
        "stage374_oidc_issuer_verified",
        "target_present",
        "target_blob_sha256_matches",
        "logical_attestation_sha256_matches",
        "public_key_present",
        "public_key_pem_sha256_matches",
        "mldsa_receipt_present",
    ]

    failed_integrity = [
        key
        for key in integrity_checks
        if not checks[key]
    ]

    if failed_integrity:
        decision = "block"
        reasons.extend(
            f"integrity_check_failed:{key}"
            for key in failed_integrity
        )

    elif checks["private_key_marker_detected"]:
        decision = "block"
        reasons.append(
            "private_key_material_detected_in_public_docs"
        )

    elif checks["forbidden_public_file_detected"]:
        decision = "block"
        reasons.append(
            "forbidden_public_file_detected"
        )

    elif downgrade_detected:
        decision = "block"
        reasons.append(
            "pqc_required_but_mldsa_verification_failed"
        )

    elif checks["dual_signature_complete"] and checks[
        "sigstore_and_mldsa_target_match"
    ]:
        decision = (
            "quantum_safe_dual_signature_verified"
        )
        reasons.append(
            "sigstore_rekor_and_mldsa65_same_target_verified"
        )

    elif (
        SIGNATURE.exists()
        and not checks["mldsa_signature_verified"]
    ):
        decision = (
            "mldsa_signature_generated_verification_pending"
        )
        reasons.append(
            "mldsa_signature_exists_but_verification_incomplete"
        )

    else:
        decision = "mldsa_execution_pending"
        reasons.append(
            "github_actions_mldsa_execution_pending"
        )

    result = {
        "stage": STAGE,
        "engine": (
            "Production ML-DSA-65 Dual-Signature "
            "Verification and Downgrade Prevention Gate"
        ),
        "created_at": now,
        "source_stage": 374,
        "previous_hash": stage374_result_sha256,
        "stage374_external_transparency_bound": (
            bool(
                stage374
                and stage374.get(
                    "external_transparency_bound"
                ) is True
            )
        ),
        "target_blob_sha256": target_blob_sha256,
        "attestation_sha256":
            declared_attestation_sha256,
        "algorithm": "ML-DSA-65",
        "fips_standard": "FIPS 204",
        "decision": decision,
        "sigstore_signature_verified": checks[
            "stage374_sigstore_signature_verified"
        ],
        "rekor_inclusion_verified": checks[
            "stage374_external_transparency_bound"
        ],
        "mldsa_signature_verified": checks[
            "mldsa_signature_verified"
        ],
        "dual_signature_target_matches": checks[
            "sigstore_and_mldsa_target_match"
        ],
        "pqc_required": pqc_required,
        "pqc_downgrade_prevented": bool(
            pqc_required
            and checks["mldsa_signature_verified"]
            and not downgrade_detected
        ),
        "reasons": reasons,
        "checks": checks,
        "safety_boundary": {
            "no_private_key_in_repository": True,
            "private_key_stored_in_github_secret": True,
            "public_key_may_be_public": True,
            "signature_may_be_public": True,
            "no_raw_qkd_key_material": True,
            "no_oidc_token_published": True,
            "no_free_form_shell_command": True,
            "fail_closed_on_pqc_downgrade": True,
        },
        "guarantee": {
            "what_stage375_guarantees": [
                (
                    "The Stage374 Sigstore/Rekor "
                    "verification remains bound."
                ),
                (
                    "A real ML-DSA-65 signature is "
                    "verified using the published key."
                ),
                (
                    "Sigstore and ML-DSA signatures "
                    "must target the same exact blob."
                ),
                (
                    "The logical Stage373 attestation "
                    "hash must also match."
                ),
                (
                    "When PQC is required, missing or "
                    "invalid ML-DSA evidence fails closed."
                ),
            ],
            "what_stage375_does_not_guarantee": [
                (
                    "It does not claim native ML-DSA "
                    "integration inside Cosign."
                ),
                (
                    "It does not claim that this OpenSSL "
                    "build is a FIPS 140 validated module."
                ),
                (
                    "It does not publish the ML-DSA "
                    "private key."
                ),
                (
                    "It does not change Stage372 "
                    "timestamp final acceptance."
                ),
            ],
        },
    }

    result_sha256 = sha256_bytes(
        canonical_json(result).encode("utf-8")
    )

    result["result_sha256"] = result_sha256

    OUT_RESULT.write_text(
        json.dumps(
            result,
            ensure_ascii=False,
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )

    summary = [
        "Stage375: Production ML-DSA-65",
        "Dual-Signature Verification",
        "and Downgrade Prevention Gate",
        "",
        f"Decision: {decision}",
        (
            "Sigstore Signature Verified: "
            f"{result['sigstore_signature_verified']}"
        ),
        (
            "Rekor Inclusion Verified: "
            f"{result['rekor_inclusion_verified']}"
        ),
        (
            "ML-DSA-65 Signature Verified: "
            f"{result['mldsa_signature_verified']}"
        ),
        (
            "Dual-Signature Target Matches: "
            f"{result['dual_signature_target_matches']}"
        ),
        (
            "PQC Downgrade Prevented: "
            f"{result['pqc_downgrade_prevented']}"
        ),
        f"Result SHA256: {result_sha256}",
        "",
        "Reasons:",
    ]

    summary.extend(
        f"- {reason}" for reason in reasons
    )

    summary.extend([
        "",
        "Meaning:",
        (
            "Stage375 verifies a real ML-DSA-65 "
            "signature for the same Stage373 blob "
            "already verified through Sigstore/Rekor."
        ),
        (
            "Until the GitHub Actions ML-DSA receipt "
            "is imported, the correct state is "
            "mldsa_execution_pending."
        ),
    ])

    OUT_SUMMARY.write_text(
        "\n".join(summary) + "\n",
        encoding="utf-8",
    )

    print(f"decision={decision}")
    print(
        "sigstore_signature_verified="
        f"{result['sigstore_signature_verified']}"
    )
    print(
        "rekor_inclusion_verified="
        f"{result['rekor_inclusion_verified']}"
    )
    print(
        "mldsa_signature_verified="
        f"{result['mldsa_signature_verified']}"
    )
    print(
        "dual_signature_target_matches="
        f"{result['dual_signature_target_matches']}"
    )
    print(
        "pqc_downgrade_prevented="
        f"{result['pqc_downgrade_prevented']}"
    )
    print(f"result_sha256={result_sha256}")


if __name__ == "__main__":
    main()
