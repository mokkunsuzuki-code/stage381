import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


STAGE = 378
SOURCE_STAGE = 377

STAGE377_RESULT_PATH = Path(
    "docs/timestamp-finalization/"
    "stage377_dual_timestamp_finalization_result.json"
)

INPUT_PATH = Path(
    "docs/qkd/"
    "stage378_qkd_safety_metadata_input.json"
)

CLASSIFICATION_PATH = Path(
    "docs/qkd/"
    "stage378_evidence_classification.json"
)

RESULT_PATH = Path(
    "docs/qkd/"
    "stage378_qkd_safety_metadata_binding_result.json"
)

SUMMARY_PATH = Path(
    "docs/qkd/"
    "stage378_qkd_safety_metadata_binding_summary.txt"
)

ALLOWED_CLASSIFICATIONS = {
    "physical_qkd_system",
    "controlled_testbed",
    "qkd_simulator",
    "metadata_only",
}

EVIDENCE_LEVELS = {
    "metadata_only": "QKD-E1",
    "qkd_simulator": "QKD-E2",
    "controlled_testbed": "QKD-E3",
    "physical_qkd_system": "QKD-E4",
}

FORBIDDEN_SUFFIXES = {
    ".qkdkey",
    ".rawkey",
    ".siftedkey",
    ".reconciledkey",
    ".finalkey",
    ".secretbits",
    ".keybits",
    ".otpkey",
    ".key",
    ".pem",
    ".p12",
    ".pfx",
    ".seed",
    ".pk8",
    ".enc",
    ".ots",
    ".tsq",
    ".tsr",
    ".tst",
}

FORBIDDEN_NAME_PREFIXES = (
    "qkd_raw_key",
    "qkd_secret_key",
    "qkd_sifted_key",
    "qkd_reconciled_key",
    "qkd_final_key",
    "qkd_key_material",
    "raw_key",
    "sifted_key",
    "reconciled_key",
    "final_key",
    "secret_key",
    "private_key",
)

FORBIDDEN_CONTENT_MARKERS = (
    b"-----BEGIN PRIVATE KEY-----",
    b"-----BEGIN ENCRYPTED PRIVATE KEY-----",
    b"-----BEGIN RSA PRIVATE KEY-----",
    b"-----BEGIN EC PRIVATE KEY-----",
    b"-----BEGIN OPENSSH PRIVATE KEY-----",
    b"ACTIONS_ID_TOKEN_REQUEST_TOKEN=",
    b"GITHUB_TOKEN=",
    b"github_pat_",
    b"ghp_",
)


def canonical_json(data: Dict[str, Any]) -> bytes:
    return json.dumps(
        data,
        ensure_ascii=False,
        sort_keys=True,
        indent=2,
    ).encode("utf-8")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> Optional[str]:
    if not path.is_file():
        return None
    return sha256_bytes(path.read_bytes())


def read_json(path: Path) -> Optional[Dict[str, Any]]:
    if not path.is_file():
        return None

    try:
        parsed = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None

    return parsed if isinstance(parsed, dict) else None


def recompute_self_hash(
    data: Optional[Dict[str, Any]],
    hash_field: str,
) -> Optional[str]:
    if not isinstance(data, dict):
        return None

    copied = dict(data)
    copied.pop(hash_field, None)
    return sha256_bytes(canonical_json(copied))


def is_sha256(value: Any) -> bool:
    if not isinstance(value, str) or len(value) != 64:
        return False

    try:
        int(value, 16)
    except ValueError:
        return False

    return True


def nested(
    data: Optional[Dict[str, Any]],
    *keys: str,
) -> Any:
    current: Any = data

    for key in keys:
        if not isinstance(current, dict):
            return None
        current = current.get(key)

    return current


def is_number(value: Any) -> bool:
    return (
        isinstance(value, (int, float))
        and not isinstance(value, bool)
    )


def public_forbidden_file_candidates() -> List[str]:
    candidates: List[str] = []

    docs = Path("docs")
    if not docs.is_dir():
        return ["docs_directory_missing"]

    for path in docs.rglob("*"):
        if not path.is_file():
            continue

        lower_name = path.name.lower()
        lower_suffix = path.suffix.lower()

        if lower_suffix in FORBIDDEN_SUFFIXES:
            candidates.append(path.as_posix())
            continue

        if lower_name.startswith(FORBIDDEN_NAME_PREFIXES):
            candidates.append(path.as_posix())

    return sorted(set(candidates))


def public_private_content_candidates() -> List[str]:
    candidates: List[str] = []

    docs = Path("docs")
    if not docs.is_dir():
        return ["docs_directory_missing"]

    for path in docs.rglob("*"):
        if not path.is_file():
            continue

        try:
            raw = path.read_bytes()
        except OSError:
            candidates.append(path.as_posix())
            continue

        if any(marker in raw for marker in FORBIDDEN_CONTENT_MARKERS):
            candidates.append(path.as_posix())

    return sorted(set(candidates))


def key_safety_checks(
    metadata: Optional[Dict[str, Any]],
) -> Dict[str, bool]:
    key_safety = nested(metadata, "key_safety")

    if not isinstance(key_safety, dict):
        return {
            "key_safety_object_present": False,
            "raw_key_absent": False,
            "sifted_key_absent": False,
            "reconciled_key_absent": False,
            "final_secret_key_absent": False,
            "public_recovery_prevented": False,
        }

    return {
        "key_safety_object_present": True,
        "raw_key_absent":
            key_safety.get("raw_key_included") is False,
        "sifted_key_absent":
            key_safety.get("sifted_key_included") is False,
        "reconciled_key_absent":
            key_safety.get("reconciled_key_included") is False,
        "final_secret_key_absent":
            key_safety.get("final_secret_key_included") is False,
        "public_recovery_prevented":
            key_safety.get(
                "key_material_publicly_recoverable"
            ) is False,
    }


def evaluate_qber(
    metadata: Optional[Dict[str, Any]],
) -> Dict[str, Any]:
    qber = nested(metadata, "qber")

    if not isinstance(qber, dict):
        return {
            "status": "not_provided",
            "observed_qber": None,
            "declared_qber_limit": None,
            "qber_within_declared_limit": None,
            "limit_source": None,
            "values_valid": False,
        }

    observed = qber.get("observed_qber")
    declared_limit = qber.get("declared_qber_limit")
    declared_within = qber.get("qber_within_declared_limit")
    limit_source = qber.get("limit_source")

    all_null = all(
        value is None
        for value in (
            observed,
            declared_limit,
            declared_within,
            limit_source,
        )
    )

    if all_null:
        return {
            "status": "not_provided",
            "observed_qber": None,
            "declared_qber_limit": None,
            "qber_within_declared_limit": None,
            "limit_source": None,
            "values_valid": True,
        }

    values_valid = all([
        is_number(observed),
        is_number(declared_limit),
        isinstance(declared_within, bool),
        isinstance(limit_source, str),
        bool(limit_source.strip()) if isinstance(limit_source, str)
        else False,
        0 <= observed <= 1 if is_number(observed) else False,
        0 <= declared_limit <= 1
        if is_number(declared_limit)
        else False,
    ])

    computed_within = (
        observed <= declared_limit
        if is_number(observed) and is_number(declared_limit)
        else None
    )

    declaration_matches = (
        computed_within == declared_within
        if computed_within is not None
        and isinstance(declared_within, bool)
        else False
    )

    return {
        "status": (
            "within_declared_limit"
            if values_valid
            and declaration_matches
            and declared_within is True
            else "outside_declared_limit"
            if values_valid
            and declaration_matches
            and declared_within is False
            else "invalid"
        ),
        "observed_qber": observed,
        "declared_qber_limit": declared_limit,
        "qber_within_declared_limit": declared_within,
        "computed_qber_within_declared_limit": computed_within,
        "declaration_matches_computation": declaration_matches,
        "limit_source": limit_source,
        "values_valid": values_valid,
    }


def evidence_requirements(
    classification: str,
    metadata: Optional[Dict[str, Any]],
) -> Tuple[bool, List[str]]:
    evidence = nested(metadata, "evidence")

    if not isinstance(evidence, dict):
        return False, ["evidence_object_missing"]

    missing: List[str] = []

    if classification == "metadata_only":
        return True, missing

    if classification == "qkd_simulator":
        if evidence.get("simulator_description_present") is not True:
            missing.append("simulator_description_present")

    elif classification == "controlled_testbed":
        if evidence.get("testbed_description_present") is not True:
            missing.append("testbed_description_present")
        if evidence.get("measurement_summary_present") is not True:
            missing.append("measurement_summary_present")

    elif classification == "physical_qkd_system":
        if evidence.get("measurement_summary_present") is not True:
            missing.append("measurement_summary_present")
        if evidence.get("device_attestation_present") is not True:
            missing.append("device_attestation_present")
        if evidence.get("operator_attestation_present") is not True:
            missing.append("operator_attestation_present")

    else:
        missing.append("unsupported_evidence_classification")

    return len(missing) == 0, missing


def evidence_level(
    requested_classification: str,
    classification_valid: bool,
    requirements_satisfied: bool,
    key_safety_passed: bool,
    public_boundary_passed: bool,
) -> str:
    if not all([
        classification_valid,
        requirements_satisfied,
        key_safety_passed,
        public_boundary_passed,
    ]):
        return "QKD-E0"

    return EVIDENCE_LEVELS.get(
        requested_classification,
        "QKD-E0",
    )


def write_json_with_hash(
    path: Path,
    payload: Dict[str, Any],
    hash_field: str,
) -> Dict[str, Any]:
    output = dict(payload)
    output[hash_field] = sha256_bytes(canonical_json(output))

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(canonical_json(output) + b"\n")

    return output


def main() -> int:
    created_at = datetime.now(timezone.utc).isoformat()

    stage377 = read_json(STAGE377_RESULT_PATH)
    metadata = read_json(INPUT_PATH)

    stage377_declared_hash = (
        stage377.get("result_sha256")
        if stage377
        else None
    )

    stage377_recomputed_hash = recompute_self_hash(
        stage377,
        "result_sha256",
    )

    stage377_result_present = stage377 is not None

    stage377_stage_valid = (
        stage377_result_present
        and stage377.get("stage") == SOURCE_STAGE
    )

    stage377_hash_valid = all([
        is_sha256(stage377_declared_hash),
        stage377_recomputed_hash is not None,
        stage377_declared_hash == stage377_recomputed_hash,
    ])

    stage377_final_acceptance_verified = all([
        stage377_result_present,
        stage377.get("decision")
            == "dual_timestamp_final_acceptance_verified",
        stage377.get("effective_final_acceptance") is True,
        stage377.get("timestamp_verified") is True,
        stage377.get("rfc3161_verified") is True,
        stage377.get("opentimestamps_verified") is True,
        stage377.get("verified_proof_count") == 2,
    ])

    metadata_present = metadata is not None

    metadata_stage_valid = all([
        metadata_present,
        metadata.get("stage") == STAGE,
        metadata.get("source_stage") == SOURCE_STAGE,
        metadata.get("input_type")
            == "qkd_safety_metadata",
    ])

    requested_classification = (
        metadata.get("evidence_classification")
        if metadata
        else None
    )

    classification_valid = (
        requested_classification
        in ALLOWED_CLASSIFICATIONS
    )

    requirements_satisfied, missing_requirements = (
        evidence_requirements(
            requested_classification
            if isinstance(requested_classification, str)
            else "",
            metadata,
        )
    )

    safety_checks = key_safety_checks(metadata)

    key_safety_passed = all(safety_checks.values())

    forbidden_files = public_forbidden_file_candidates()
    forbidden_content = public_private_content_candidates()

    public_boundary_passed = (
        len(forbidden_files) == 0
        and len(forbidden_content) == 0
    )

    publication_boundary = nested(
        metadata,
        "publication_boundary",
    )

    declared_publication_boundary_valid = all([
        isinstance(publication_boundary, dict),
        publication_boundary.get("metadata_only") is True,
        publication_boundary.get(
            "raw_qkd_key_publication_prohibited"
        ) is True,
        publication_boundary.get(
            "derived_secret_publication_prohibited"
        ) is True,
        publication_boundary.get(
            "private_device_credentials_prohibited"
        ) is True,
    ])

    qber = evaluate_qber(metadata)

    assigned_level = evidence_level(
        requested_classification
        if isinstance(requested_classification, str)
        else "",
        classification_valid,
        requirements_satisfied,
        key_safety_passed,
        public_boundary_passed,
    )

    metadata_file_sha256 = sha256_file(INPUT_PATH)

    classification_payload: Dict[str, Any] = {
        "stage": STAGE,
        "source_stage": SOURCE_STAGE,
        "classification_type":
            "qkd_evidence_classification",
        "created_at": created_at,
        "previous_hash": stage377_declared_hash,
        "requested_classification":
            requested_classification,
        "assigned_evidence_level": assigned_level,
        "classification_valid": classification_valid,
        "requirements_satisfied":
            requirements_satisfied,
        "missing_requirements": missing_requirements,
        "qber_assessment": qber,
        "key_safety_passed": key_safety_passed,
        "public_boundary_passed":
            public_boundary_passed,
        "metadata_file_sha256":
            metadata_file_sha256,
        "classification_mapping": {
            "metadata_only": "QKD-E1",
            "qkd_simulator": "QKD-E2",
            "controlled_testbed": "QKD-E3",
            "physical_qkd_system": "QKD-E4",
            "invalid_or_unsafe": "QKD-E0"
        },
    }

    classification = write_json_with_hash(
        CLASSIFICATION_PATH,
        classification_payload,
        "classification_sha256",
    )

    checks = {
        "stage377_result_present":
            stage377_result_present,
        "stage377_stage_valid":
            stage377_stage_valid,
        "stage377_result_hash_valid":
            stage377_hash_valid,
        "stage377_final_acceptance_verified":
            stage377_final_acceptance_verified,
        "metadata_input_present":
            metadata_present,
        "metadata_stage_valid":
            metadata_stage_valid,
        "evidence_classification_valid":
            classification_valid,
        "classification_requirements_satisfied":
            requirements_satisfied,
        "key_safety_metadata_valid":
            key_safety_passed,
        "declared_publication_boundary_valid":
            declared_publication_boundary_valid,
        "public_forbidden_file_absent":
            len(forbidden_files) == 0,
        "public_private_content_absent":
            len(forbidden_content) == 0,
        "qber_values_valid":
            qber.get("values_valid") is True,
        "classification_hash_created":
            is_sha256(
                classification.get(
                    "classification_sha256"
                )
            ),
    }

    reasons: List[str] = []

    if not stage377_result_present:
        reasons.append("stage377_result_missing")
    elif not stage377_stage_valid:
        reasons.append("stage377_result_stage_invalid")
    elif not stage377_hash_valid:
        reasons.append("stage377_result_hash_invalid")
    elif not stage377_final_acceptance_verified:
        reasons.append(
            "stage377_dual_timestamp_final_acceptance_pending"
        )

    if not metadata_present:
        reasons.append("qkd_metadata_input_missing")
    elif not metadata_stage_valid:
        reasons.append("qkd_metadata_stage_invalid")

    if not classification_valid:
        reasons.append("unsupported_evidence_classification")

    reasons.extend(
        f"missing_requirement:{item}"
        for item in missing_requirements
    )

    if not key_safety_passed:
        reasons.append("qkd_key_safety_metadata_failed")

    if not declared_publication_boundary_valid:
        reasons.append(
            "declared_publication_boundary_invalid"
        )

    if forbidden_files:
        reasons.append("forbidden_public_qkd_file_detected")

    if forbidden_content:
        reasons.append(
            "private_material_marker_detected_in_docs"
        )

    if qber.get("values_valid") is not True:
        reasons.append("qber_metadata_invalid")

    critical_safety_passed = all([
        metadata_present,
        metadata_stage_valid,
        classification_valid,
        requirements_satisfied,
        key_safety_passed,
        declared_publication_boundary_valid,
        public_boundary_passed,
        qber.get("values_valid") is True,
    ])

    if not critical_safety_passed:
        decision = "block"
        qkd_metadata_bound = False
    elif not stage377_final_acceptance_verified:
        decision = "qkd_binding_pending_previous_stage"
        qkd_metadata_bound = False
    elif requested_classification == "metadata_only":
        decision = "qkd_operational_evidence_pending"
        qkd_metadata_bound = True
    else:
        decision = "qkd_safety_metadata_bound"
        qkd_metadata_bound = True

    result_payload: Dict[str, Any] = {
        "stage": STAGE,
        "source_stage": SOURCE_STAGE,
        "engine":
            "QKD Safety Metadata Binding "
            "& Evidence Classification Gate",
        "created_at": created_at,
        "previous_hash": stage377_declared_hash,
        "stage377_result_path":
            STAGE377_RESULT_PATH.as_posix(),
        "stage377_decision":
            stage377.get("decision")
            if stage377
            else None,
        "stage377_verified_proof_count":
            stage377.get("verified_proof_count")
            if stage377
            else None,
        "stage377_result_sha256":
            stage377_declared_hash,
        "stage377_hash_valid":
            stage377_hash_valid,
        "stage377_final_acceptance_verified":
            stage377_final_acceptance_verified,
        "metadata_input_path":
            INPUT_PATH.as_posix(),
        "metadata_input_sha256":
            metadata_file_sha256,
        "classification_path":
            CLASSIFICATION_PATH.as_posix(),
        "classification_sha256":
            classification.get(
                "classification_sha256"
            ),
        "evidence_classification":
            requested_classification,
        "evidence_level":
            assigned_level,
        "qber_assessment": qber,
        "qkd_metadata_bound":
            qkd_metadata_bound,
        "raw_qkd_key_publication_detected":
            len(forbidden_files) > 0,
        "private_material_content_detected":
            len(forbidden_content) > 0,
        "forbidden_public_files":
            forbidden_files,
        "private_content_candidates":
            forbidden_content,
        "checks": checks,
        "decision": decision,
        "reasons": reasons,
        "safety_boundary": {
            "raw_qkd_key_publication_prohibited": True,
            "derived_qkd_secret_publication_prohibited": True,
            "private_key_publication_prohibited": True,
            "timestamp_raw_binary_publication_prohibited": True,
            "metadata_only_publication": True,
            "universal_qber_threshold_hardcoded": False,
            "declared_qber_limit_required_for_qber_claim":
                True,
        },
        "guarantee": (
            "Stage378 binds public QKD safety metadata "
            "to the declared Stage377 result hash, "
            "classifies the evidence source, prevents "
            "publication of raw or derived QKD secret "
            "material, and fails closed when required "
            "conditions are not satisfied."
        ),
    }

    result = write_json_with_hash(
        RESULT_PATH,
        result_payload,
        "result_sha256",
    )

    summary_lines = [
        "Stage378 QKD Safety Metadata Binding",
        "====================================",
        f"created_at: {created_at}",
        f"decision: {decision}",
        (
            "previous_hash: "
            f"{stage377_declared_hash}"
        ),
        (
            "stage377_decision: "
            f"{result.get('stage377_decision')}"
        ),
        (
            "stage377_verified_proof_count: "
            f"{result.get('stage377_verified_proof_count')}"
        ),
        (
            "evidence_classification: "
            f"{requested_classification}"
        ),
        f"evidence_level: {assigned_level}",
        f"qkd_metadata_bound: {qkd_metadata_bound}",
        (
            "raw_qkd_key_publication_detected: "
            f"{len(forbidden_files) > 0}"
        ),
        (
            "private_material_content_detected: "
            f"{len(forbidden_content) > 0}"
        ),
        f"result_sha256: {result.get('result_sha256')}",
        "",
        "Reasons:",
    ]

    if reasons:
        summary_lines.extend(
            f"- {reason}"
            for reason in reasons
        )
    else:
        summary_lines.append("- none")

    SUMMARY_PATH.write_text(
        "\n".join(summary_lines) + "\n",
        encoding="utf-8",
    )

    print("Stage378 execution completed.")
    print(f"decision={decision}")
    print(
        "previous_hash="
        f"{stage377_declared_hash}"
    )
    print(
        "stage377_hash_valid="
        f"{stage377_hash_valid}"
    )
    print(
        "stage377_final_acceptance_verified="
        f"{stage377_final_acceptance_verified}"
    )
    print(
        "evidence_classification="
        f"{requested_classification}"
    )
    print(f"evidence_level={assigned_level}")
    print(
        "public_forbidden_file_count="
        f"{len(forbidden_files)}"
    )
    print(
        "private_content_candidate_count="
        f"{len(forbidden_content)}"
    )
    print(
        "result_sha256="
        f"{result.get('result_sha256')}"
    )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
