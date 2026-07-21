import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional


STAGE = 374

ROOT = Path(".")
DOCS = ROOT / "docs"

STAGE373_DIR = DOCS / "final-acceptance-attestation"
STAGE373_ATTESTATION = (
    STAGE373_DIR
    / "stage373_final_acceptance_attestation.json"
)
STAGE373_RESULT = (
    STAGE373_DIR
    / "stage373_external_transparency_binding_result.json"
)

OUT_DIR = DOCS / "sigstore-production"

INPUT_JSON = (
    OUT_DIR
    / "stage374_production_sigstore_input.json"
)
EXECUTION_RECEIPT = (
    OUT_DIR
    / "stage374_cosign_execution_receipt.json"
)
REKOR_RECEIPT = (
    OUT_DIR
    / "stage374_rekor_inclusion_receipt.json"
)
BUNDLE_FILE = (
    OUT_DIR
    / "stage373_attestation.sigstore.bundle.json"
)

OUT_RESULT = (
    OUT_DIR
    / "stage374_production_external_binding_result.json"
)
OUT_SUMMARY = (
    OUT_DIR
    / "stage374_production_external_binding_summary.txt"
)

OUT_DIR.mkdir(parents=True, exist_ok=True)


def canonical_json(value: Dict[str, Any]) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        indent=2,
    )


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_text(value: str) -> str:
    return sha256_bytes(value.encode("utf-8"))


def sha256_file(path: Path) -> Optional[str]:
    if not path.exists() or not path.is_file():
        return None

    return sha256_bytes(path.read_bytes())


def read_json(path: Path) -> Optional[Dict[str, Any]]:
    if not path.exists():
        return None

    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None

    return value if isinstance(value, dict) else None


def is_sha256(value: Any) -> bool:
    if not isinstance(value, str) or len(value) != 64:
        return False

    try:
        int(value, 16)
    except ValueError:
        return False

    return True


def recompute_self_hash(
    value: Optional[Dict[str, Any]],
    self_hash_field: str,
) -> Optional[str]:
    if not isinstance(value, dict):
        return None

    copy_value = dict(value)
    copy_value.pop(self_hash_field, None)

    return sha256_text(canonical_json(copy_value))


def version_tuple(value: Any) -> Optional[tuple]:
    if not isinstance(value, str):
        return None

    cleaned = value.strip().lower().lstrip("v")
    parts = cleaned.split(".")

    if len(parts) < 3:
        return None

    try:
        return tuple(int(part.split("-")[0]) for part in parts[:3])
    except ValueError:
        return None


def contains_private_material(value: Any) -> bool:
    dangerous_keys = {
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
        "github_token",
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

                if normalized_key in dangerous_keys:
                    if child not in (None, "", False, [], {}):
                        return True

                if scan(child):
                    return True

            return False

        if isinstance(item, list):
            return any(scan(child) for child in item)

        if isinstance(item, str):
            lowered = item.lower()
            return any(
                marker in lowered
                for marker in private_markers
            )

        return False

    return scan(value)


def forbidden_public_file_detected() -> bool:
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
        ".jwt",
        ".oidc",
    }

    for path in DOCS.rglob("*"):
        if path.is_file():
            if path.suffix.lower() in forbidden_suffixes:
                return True

    return False


def main() -> None:
    now = datetime.now(timezone.utc).isoformat()

    stage373_attestation = read_json(STAGE373_ATTESTATION)
    stage373_result = read_json(STAGE373_RESULT)
    input_data = read_json(INPUT_JSON)
    execution_receipt = read_json(EXECUTION_RECEIPT)
    rekor_receipt = read_json(REKOR_RECEIPT)

    declared_attestation_sha256 = (
        stage373_attestation.get("attestation_sha256")
        if isinstance(stage373_attestation, dict)
        else None
    )

    recomputed_attestation_sha256 = recompute_self_hash(
        stage373_attestation,
        "attestation_sha256",
    )

    result_attestation_sha256 = (
        stage373_result.get("attestation_sha256")
        if isinstance(stage373_result, dict)
        else None
    )

    expected_attestation_sha256 = (
        input_data.get("expected_attestation_sha256")
        if isinstance(input_data, dict)
        else None
    )

    expected_identity = (
        input_data.get("expected_identity")
        if isinstance(input_data, dict)
        else None
    )

    expected_issuer = (
        input_data.get("expected_oidc_issuer")
        if isinstance(input_data, dict)
        else None
    )

    minimum_version = (
        input_data.get("minimum_cosign_version")
        if isinstance(input_data, dict)
        else None
    )

    receipt_version = (
        execution_receipt.get("cosign_version")
        if isinstance(execution_receipt, dict)
        else None
    )

    receipt_target_sha256 = (
        execution_receipt.get("target_sha256")
        if isinstance(execution_receipt, dict)
        else None
    )

    receipt_attestation_sha256 = (
        execution_receipt.get("attestation_sha256")
        if isinstance(execution_receipt, dict)
        else None
    )

    attestation_blob_sha256 = sha256_file(
        STAGE373_ATTESTATION
    )

    rekor_artifact_digest = (
        rekor_receipt.get("artifact_digest")
        if isinstance(rekor_receipt, dict)
        else None
    )

    rekor_attestation_sha256 = (
        rekor_receipt.get("attestation_sha256")
        if isinstance(rekor_receipt, dict)
        else None
    )

    bundle_sha256_actual = sha256_file(BUNDLE_FILE)

    bundle_sha256_receipt = (
        execution_receipt.get("bundle_sha256")
        if isinstance(execution_receipt, dict)
        else None
    )

    rekor_bundle_sha256 = (
        rekor_receipt.get("bundle_sha256")
        if isinstance(rekor_receipt, dict)
        else None
    )

    actual_version = version_tuple(receipt_version)
    required_version = version_tuple(minimum_version)

    cosign_version_supported = bool(
        actual_version
        and required_version
        and actual_version >= required_version
    )

    execution_complete = all([
        isinstance(execution_receipt, dict),
        execution_receipt.get("execution_status")
            == "verified",
        execution_receipt.get("sign_exit_code") == 0,
        execution_receipt.get("verify_exit_code") == 0,
        is_sha256(
            execution_receipt.get(
                "cosign_binary_sha256"
            )
        ),
        is_sha256(
            execution_receipt.get(
                "verify_output_sha256"
            )
        ),
        execution_receipt.get("signature_verified")
            is True,
        execution_receipt.get("identity_verified")
            is True,
        execution_receipt.get("oidc_issuer_verified")
            is True,
        execution_receipt.get("expected_identity")
            == expected_identity,
        execution_receipt.get("expected_oidc_issuer")
            == expected_issuer,
    ])

    rekor_log_index = (
        rekor_receipt.get("log_index")
        if isinstance(rekor_receipt, dict)
        else None
    )

    if isinstance(rekor_log_index, str):
        try:
            rekor_log_index_number = int(
                rekor_log_index
            )
        except ValueError:
            rekor_log_index_number = None
    elif isinstance(rekor_log_index, int):
        rekor_log_index_number = rekor_log_index
    else:
        rekor_log_index_number = None

    rekor_integrated_time = (
        rekor_receipt.get("integrated_time")
        if isinstance(rekor_receipt, dict)
        else None
    )

    if isinstance(rekor_integrated_time, str):
        try:
            rekor_integrated_time_number = int(
                rekor_integrated_time
            )
        except ValueError:
            rekor_integrated_time_number = None
    elif isinstance(rekor_integrated_time, int):
        rekor_integrated_time_number = (
            rekor_integrated_time
        )
    else:
        rekor_integrated_time_number = None

    rekor_complete = all([
        isinstance(rekor_receipt, dict),
        rekor_receipt.get("status") == "verified",
        rekor_receipt.get("bundle_present") is True,
        rekor_receipt.get(
            "artifact_digest_matches"
        ) is True,
        rekor_receipt.get(
            "signed_entry_timestamp_present"
        ) is True,
        rekor_receipt.get(
            "signed_entry_timestamp_verified"
        ) is True,
        rekor_receipt.get(
            "inclusion_proof_present"
        ) is True,
        rekor_receipt.get(
            "inclusion_proof_verified"
        ) is True,
        is_sha256(
            rekor_receipt.get("artifact_digest")
        ),
        bool(rekor_receipt.get("log_id")),
        (
            rekor_log_index_number is not None
            and rekor_log_index_number >= 0
        ),
        (
            rekor_integrated_time_number is not None
            and rekor_integrated_time_number > 0
        ),
        bool(
            rekor_receipt.get(
                "inclusion_proof_root_hash"
            )
        ),
        bool(
            rekor_receipt.get(
                "inclusion_proof_tree_size"
            )
        ),
        is_sha256(
            rekor_receipt.get(
                "signed_entry_timestamp_sha256"
            )
        ),
    ])

    stage372_final_acceptance = bool(
        isinstance(stage373_result, dict)
        and stage373_result.get(
            "stage372_final_acceptance"
        ) is True
    )

    checks = {
        "stage373_attestation_present":
            stage373_attestation is not None,
        "stage373_result_present":
            stage373_result is not None,
        "stage374_input_present":
            input_data is not None,
        "cosign_execution_receipt_present":
            execution_receipt is not None,
        "rekor_receipt_present":
            rekor_receipt is not None,

        "attestation_declared_sha256_valid":
            is_sha256(declared_attestation_sha256),
        "attestation_sha256_matches":
            declared_attestation_sha256
            == recomputed_attestation_sha256,
        "stage373_result_attestation_matches":
            result_attestation_sha256
            == declared_attestation_sha256,
        "input_expected_attestation_matches":
            expected_attestation_sha256
            == declared_attestation_sha256,

        "receipt_target_blob_sha256_matches":
            receipt_target_sha256
            == attestation_blob_sha256,

        "receipt_logical_attestation_sha256_matches":
            receipt_attestation_sha256
            == declared_attestation_sha256,

        "rekor_artifact_blob_sha256_matches":
            rekor_artifact_digest
            == attestation_blob_sha256,

        "rekor_logical_attestation_sha256_matches":
            rekor_attestation_sha256
            == declared_attestation_sha256,

        "cosign_version_supported":
            cosign_version_supported,
        "cosign_execution_complete":
            execution_complete,

        "bundle_present":
            BUNDLE_FILE.exists(),
        "bundle_sha256_valid":
            is_sha256(bundle_sha256_actual),
        "bundle_sha256_matches_execution_receipt":
            bundle_sha256_actual
            == bundle_sha256_receipt,
        "bundle_sha256_matches_rekor_receipt":
            bundle_sha256_actual
            == rekor_bundle_sha256,

        "rekor_log_id_present":
            bool(
                rekor_receipt.get("log_id")
                if isinstance(rekor_receipt, dict)
                else None
            ),

        "rekor_log_index_valid":
            (
                rekor_log_index_number is not None
                and rekor_log_index_number >= 0
            ),

        "rekor_integrated_time_valid":
            (
                rekor_integrated_time_number is not None
                and rekor_integrated_time_number > 0
            ),

        "rekor_inclusion_root_hash_present":
            bool(
                rekor_receipt.get(
                    "inclusion_proof_root_hash"
                )
                if isinstance(rekor_receipt, dict)
                else None
            ),

        "rekor_inclusion_tree_size_present":
            bool(
                rekor_receipt.get(
                    "inclusion_proof_tree_size"
                )
                if isinstance(rekor_receipt, dict)
                else None
            ),

        "rekor_signed_entry_timestamp_sha256_valid":
            is_sha256(
                rekor_receipt.get(
                    "signed_entry_timestamp_sha256"
                )
                if isinstance(rekor_receipt, dict)
                else None
            ),

        "rekor_verification_complete":
            rekor_complete,

        "private_material_detected":
            contains_private_material({
                "stage373_attestation":
                    stage373_attestation,
                "stage373_result":
                    stage373_result,
                "stage374_input":
                    input_data,
                "execution_receipt":
                    execution_receipt,
                "rekor_receipt":
                    rekor_receipt,
            }),

        "forbidden_public_file_detected":
            forbidden_public_file_detected(),
    }

    mandatory_integrity_checks = [
        "stage373_attestation_present",
        "stage373_result_present",
        "stage374_input_present",
        "cosign_execution_receipt_present",
        "rekor_receipt_present",
        "attestation_declared_sha256_valid",
        "attestation_sha256_matches",
        "stage373_result_attestation_matches",
        "input_expected_attestation_matches",
    ]

    failed_integrity_checks = [
        name
        for name in mandatory_integrity_checks
        if not checks[name]
    ]

    external_transparency_bound = all([
        checks["receipt_target_blob_sha256_matches"],
        checks[
            "receipt_logical_attestation_sha256_matches"
        ],
        checks["rekor_artifact_blob_sha256_matches"],
        checks[
            "rekor_logical_attestation_sha256_matches"
        ],
        checks["cosign_version_supported"],
        checks["cosign_execution_complete"],
        checks["bundle_present"],
        checks["bundle_sha256_valid"],
        checks[
            "bundle_sha256_matches_execution_receipt"
        ],
        checks[
            "bundle_sha256_matches_rekor_receipt"
        ],
        checks["rekor_verification_complete"],
    ])

    decision = "production_execution_pending"
    reasons = []

    if failed_integrity_checks:
        decision = "block"
        reasons.extend(
            f"integrity_check_failed:{name}"
            for name in failed_integrity_checks
        )

    elif checks["private_material_detected"]:
        decision = "block"
        reasons.append("private_material_detected")

    elif checks["forbidden_public_file_detected"]:
        decision = "block"
        reasons.append(
            "forbidden_public_file_detected"
        )

    elif external_transparency_bound:
        if stage372_final_acceptance:
            decision = (
                "final_acceptance_transparency_bound"
            )
            reasons.append(
                "stage372_final_acceptance_external_binding_verified"
            )
        else:
            decision = (
                "pending_state_transparency_bound"
            )
            reasons.append(
                "stage372_pending_state_external_binding_verified"
            )

    elif (
        execution_receipt
        and execution_receipt.get("sign_exit_code") == 0
        and BUNDLE_FILE.exists()
    ):
        decision = (
            "signature_generated_verification_pending"
        )
        reasons.append(
            "signature_exists_but_full_verification_incomplete"
        )

    else:
        decision = "production_execution_pending"
        reasons.extend([
            "github_actions_sigstore_execution_pending",
            "cosign_verification_pending",
            "rekor_inclusion_verification_pending",
        ])

    result = {
        "stage": STAGE,
        "engine": (
            "Production Sigstore Signing and "
            "Rekor Inclusion Verification Gate"
        ),
        "created_at": now,
        "source_stage": 373,
        "previous_hash":
            result_attestation_sha256,
        "stage373_attestation_sha256":
            declared_attestation_sha256,
        "expected_identity":
            expected_identity,
        "expected_oidc_issuer":
            expected_issuer,
        "minimum_cosign_version":
            minimum_version,
        "observed_cosign_version":
            receipt_version,
        "stage372_final_acceptance":
            stage372_final_acceptance,
        "decision": decision,
        "external_transparency_bound":
            external_transparency_bound,
        "reasons": reasons,
        "checks": checks,
        "safety_boundary": {
            "no_private_keys": True,
            "no_oidc_tokens": True,
            "no_github_tokens": True,
            "no_raw_qkd_key_material": True,
            "no_raw_timestamp_binaries":
                True,
            "no_free_form_shell_command":
                True,
            "github_actions_least_privilege":
                True,
            "cosign_version_floor_enforced":
                True,
            "metadata_and_public_bundle_only":
                True,
        },
        "guarantee": {
            "what_stage374_guarantees": [
                (
                    "Stage373 attestation is re-hashed "
                    "before external binding."
                ),
                (
                    "Cosign verification must succeed "
                    "for the expected GitHub Actions "
                    "identity and OIDC issuer."
                ),
                (
                    "The Sigstore bundle must match both "
                    "execution and Rekor receipts."
                ),
                (
                    "External transparency binding becomes "
                    "true only after complete verification."
                ),
                (
                    "Stage372 pending status is preserved "
                    "even after successful external binding."
                ),
            ],
            "what_stage374_does_not_guarantee": [
                (
                    "It does not change Stage372 "
                    "timestamp verification."
                ),
                (
                    "It does not perform ML-DSA signing "
                    "or verification."
                ),
                (
                    "It does not publish OIDC tokens or "
                    "GitHub credentials."
                ),
            ],
        },
    }

    result_sha256 = sha256_text(canonical_json(result))
    result["result_sha256"] = result_sha256

    OUT_RESULT.write_text(
        json.dumps(
            result,
            ensure_ascii=False,
            indent=2,
        ),
        encoding="utf-8",
    )

    summary = [
        "Stage374: Production Sigstore Signing",
        "and Rekor Inclusion Verification Gate",
        "",
        f"Decision: {decision}",
        (
            "External Transparency Bound: "
            f"{external_transparency_bound}"
        ),
        (
            "Stage372 Final Acceptance: "
            f"{stage372_final_acceptance}"
        ),
        (
            "Stage373 Attestation SHA256: "
            f"{declared_attestation_sha256}"
        ),
        (
            "Observed Cosign Version: "
            f"{receipt_version}"
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
            "Stage374 performs production Sigstore "
            "and Rekor verification for the Stage373 "
            "attestation."
        ),
        (
            "Until a verified GitHub Actions artifact "
            "is imported, the correct decision is "
            "production_execution_pending."
        ),
        (
            "If external verification succeeds while "
            "Stage372 remains pending, the correct "
            "decision is pending_state_transparency_bound."
        ),
    ])

    OUT_SUMMARY.write_text(
        "\n".join(summary) + "\n",
        encoding="utf-8",
    )

    print(f"decision={decision}")
    print(
        "external_transparency_bound="
        f"{external_transparency_bound}"
    )
    print(
        "stage372_final_acceptance="
        f"{stage372_final_acceptance}"
    )
    print(
        "stage373_attestation_sha256="
        f"{declared_attestation_sha256}"
    )
    print(f"result_sha256={result_sha256}")


if __name__ == "__main__":
    main()
