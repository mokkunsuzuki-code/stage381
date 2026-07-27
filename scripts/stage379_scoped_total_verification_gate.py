import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional


STAGE = 379
SOURCE_STAGES = [377, 378]

POLICY_PATH = Path(
    "development/stage379/"
    "stage379_verification_scope_policy.json"
)

POLICY_HASH_PATH = Path(
    "development/stage379/"
    "stage379_verification_scope_policy.sha256"
)

STAGE377_RESULT_PATH = Path(
    "docs/timestamp-finalization/"
    "stage377_dual_timestamp_finalization_result.json"
)

STAGE378_RESULT_PATH = Path(
    "docs/qkd/"
    "stage378_qkd_safety_metadata_binding_result.json"
)

DEVELOPMENT_GATE_RESULT_PATH = Path(
    "development/"
    "stage379_development_gate_result.json"
)

RESULT_PATH = Path(
    "development/stage379/"
    "stage379_scoped_total_verification_result.json"
)

CERTIFICATE_PATH = Path(
    "development/stage379/"
    "stage379_development_acceptance_certificate.json"
)

SUMMARY_PATH = Path(
    "development/stage379/"
    "stage379_scoped_total_verification_summary.txt"
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


def is_sha256(value: Any) -> bool:
    if not isinstance(value, str) or len(value) != 64:
        return False

    try:
        int(value, 16)
    except ValueError:
        return False

    return True


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


def verify_self_hash(
    data: Optional[Dict[str, Any]],
    hash_field: str,
) -> bool:
    if not isinstance(data, dict):
        return False

    declared = data.get(hash_field)
    recomputed = recompute_self_hash(data, hash_field)

    return all([
        is_sha256(declared),
        recomputed is not None,
        declared == recomputed,
    ])


def read_policy_hash(path: Path) -> Optional[str]:
    if not path.is_file():
        return None

    try:
        content = path.read_text(encoding="utf-8").strip()
    except OSError:
        return None

    if not content:
        return None

    candidate = content.split()[0]

    return candidate if is_sha256(candidate) else None


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

    policy = read_json(POLICY_PATH)
    stage377 = read_json(STAGE377_RESULT_PATH)
    stage378 = read_json(STAGE378_RESULT_PATH)
    development_gate = read_json(
        DEVELOPMENT_GATE_RESULT_PATH
    )

    policy_present = policy is not None
    stage377_present = stage377 is not None
    stage378_present = stage378 is not None
    development_gate_present = development_gate is not None

    declared_policy_hash = read_policy_hash(
        POLICY_HASH_PATH
    )

    computed_policy_hash = (
        sha256_bytes(canonical_json(policy))
        if policy
        else None
    )

    policy_hash_valid = all([
        is_sha256(declared_policy_hash),
        computed_policy_hash is not None,
        declared_policy_hash == computed_policy_hash,
    ])

    policy_structure_valid = all([
        policy_present,
        policy.get("stage") == STAGE if policy else False,
        policy.get("execution_mode") == "development"
            if policy else False,
        policy.get("development_only") is True
            if policy else False,
        policy.get("scope_locked") is True
            if policy else False,
        policy.get("scope_reduction_allowed") is False
            if policy else False,
        policy.get("fail_closed") is True
            if policy else False,
        policy.get("required_source_stages")
            == SOURCE_STAGES if policy else False,
        policy.get(
            "formal_certificate_issuance_allowed"
        ) is False if policy else False,
        policy.get(
            "pipeline_completion_declaration_allowed"
        ) is False if policy else False,
    ])

    stage377_hash_valid = verify_self_hash(
        stage377,
        "result_sha256",
    )

    stage378_hash_valid = verify_self_hash(
        stage378,
        "result_sha256",
    )

    development_gate_hash_valid = verify_self_hash(
        development_gate,
        "result_sha256",
    )

    stage377_result_sha256 = (
        stage377.get("result_sha256")
        if stage377 else None
    )

    stage378_result_sha256 = (
        stage378.get("result_sha256")
        if stage378 else None
    )

    development_gate_result_sha256 = (
        development_gate.get("result_sha256")
        if development_gate else None
    )

    stage378_chain_valid = all([
        stage377_present,
        stage378_present,
        stage378.get("previous_hash")
            == stage377_result_sha256,
        stage378.get("stage377_result_sha256")
            == stage377_result_sha256,
        stage378.get("stage377_hash_valid") is True,
    ])

    development_gate_chain_valid = all([
        development_gate_present,
        development_gate.get("previous_hash")
            == stage378_result_sha256,
        development_gate.get("stage377_result_sha256")
            == stage377_result_sha256,
        development_gate.get("stage378_result_sha256")
            == stage378_result_sha256,
    ])

    stage377_requirements = (
        policy.get("required_stage377_conditions", {})
        if policy else {}
    )

    stage377_requirements_satisfied = all([
        stage377_present,
        stage377.get("stage")
            == stage377_requirements.get("stage"),
        stage377_hash_valid,
        stage377.get("decision")
            == stage377_requirements.get("decision"),
        stage377.get("rfc3161_verified")
            is stage377_requirements.get(
                "rfc3161_verified"
            ),
        stage377.get("opentimestamps_verified")
            is stage377_requirements.get(
                "opentimestamps_verified"
            ),
        stage377.get("timestamp_verified")
            is stage377_requirements.get(
                "timestamp_verified"
            ),
        stage377.get("verified_proof_count")
            == stage377_requirements.get(
                "verified_proof_count"
            ),
        stage377.get("effective_final_acceptance")
            is stage377_requirements.get(
                "effective_final_acceptance"
            ),
    ])

    stage378_checks = (
        stage378.get("checks", {})
        if stage378 else {}
    )

    stage378_requirements = (
        policy.get("required_stage378_conditions", {})
        if policy else {}
    )

    stage378_requirements_satisfied = all([
        stage378_present,
        stage378.get("stage")
            == stage378_requirements.get("stage"),
        stage378_hash_valid,
        stage378_chain_valid,
        stage378.get("stage377_hash_valid")
            is stage378_requirements.get(
                "stage377_hash_valid"
            ),
        stage378.get(
            "stage377_final_acceptance_verified"
        ) is stage378_requirements.get(
            "stage377_final_acceptance_verified"
        ),
        stage378.get("qkd_metadata_bound")
            is stage378_requirements.get(
                "qkd_metadata_bound"
            ),
        stage378_checks.get(
            "public_forbidden_file_absent"
        ) is stage378_requirements.get(
            "public_forbidden_file_absent"
        ),
        stage378_checks.get(
            "public_private_content_absent"
        ) is stage378_requirements.get(
            "public_private_content_absent"
        ),
        stage378.get(
            "raw_qkd_key_publication_detected"
        ) is stage378_requirements.get(
            "raw_qkd_key_publication_detected"
        ),
        stage378.get(
            "private_material_content_detected"
        ) is stage378_requirements.get(
            "private_material_content_detected"
        ),
        stage378_checks.get(
            "evidence_classification_valid"
        ) is stage378_requirements.get(
            "evidence_classification_valid"
        ),
        stage378_checks.get(
            "classification_requirements_satisfied"
        ) is stage378_requirements.get(
            "classification_requirements_satisfied"
        ),
    ])

    accepted_qkd_evidence_levels = (
        policy.get("accepted_qkd_evidence_levels", [])
        if policy else []
    )

    qkd_evidence_level_accepted = all([
        stage378_present,
        isinstance(stage378.get("evidence_level"), str),
        stage378.get("evidence_level")
            in accepted_qkd_evidence_levels,
    ])

    required_safety_boundaries = (
        policy.get("required_safety_boundaries", {})
        if policy else {}
    )

    actual_safety_boundaries = (
        stage378.get("safety_boundary", {})
        if stage378 else {}
    )

    safety_boundaries_satisfied = all(
        actual_safety_boundaries.get(key) is expected
        for key, expected
        in required_safety_boundaries.items()
    )

    development_gate_allows_execution = all([
        development_gate_present,
        development_gate_hash_valid,
        development_gate_chain_valid,
        development_gate.get("decision")
            in {
                "development_only_upstream_pending",
                "formal_promotion_eligible",
            },
        development_gate.get(
            "development_only"
        ) is True,
        development_gate.get(
            "formal_stage379_acceptance"
        ) is False,
        development_gate.get(
            "public_release_allowed"
        ) is False,
        development_gate.get(
            "checks", {}
        ).get(
            "development_execution_allowed"
        ) is True,
    ])

    critical_integrity_valid = all([
        policy_present,
        policy_hash_valid,
        policy_structure_valid,
        stage377_present,
        stage377_hash_valid,
        stage378_present,
        stage378_hash_valid,
        stage378_chain_valid,
        development_gate_allows_execution,
        safety_boundaries_satisfied,
        qkd_evidence_level_accepted,
    ])

    formal_acceptance_requirements_satisfied = all([
        critical_integrity_valid,
        stage377_requirements_satisfied,
        stage378_requirements_satisfied,
        development_gate.get(
            "checks", {}
        ).get(
            "formal_promotion_requirements_satisfied"
        ) is True if development_gate else False,
    ])

    reasons: List[str] = []

    if not policy_present:
        reasons.append("verification_scope_policy_missing")
    elif not policy_hash_valid:
        reasons.append("verification_scope_policy_hash_invalid")
    elif not policy_structure_valid:
        reasons.append("verification_scope_policy_invalid")

    if not stage377_present:
        reasons.append("stage377_result_missing")
    elif not stage377_hash_valid:
        reasons.append("stage377_result_hash_invalid")
    elif not stage377_requirements_satisfied:
        reasons.append("stage377_formal_acceptance_pending")

    if not stage378_present:
        reasons.append("stage378_result_missing")
    elif not stage378_hash_valid:
        reasons.append("stage378_result_hash_invalid")
    elif not stage378_chain_valid:
        reasons.append("stage378_hash_chain_invalid")
    elif not stage378_requirements_satisfied:
        reasons.append("stage378_qkd_binding_pending")

    if not qkd_evidence_level_accepted:
        reasons.append("stage378_qkd_evidence_level_not_accepted")

    if not safety_boundaries_satisfied:
        reasons.append("stage378_safety_boundary_invalid")

    if not development_gate_allows_execution:
        reasons.append("stage379_development_gate_blocked")

    if not critical_integrity_valid:
        decision = "block"
    elif formal_acceptance_requirements_satisfied:
        decision = "formal_acceptance_requirements_met"
    else:
        decision = "development_verification_pending_upstream"

    certificate_issued = False
    pipeline_completed = False
    formal_acceptance = False

    result_payload: Dict[str, Any] = {
        "stage": STAGE,
        "source_stages": SOURCE_STAGES,
        "engine": (
            "Scoped Total Verification Acceptance Certificate "
            "& Pipeline Completion Gate"
        ),
        "created_at": created_at,
        "execution_mode": "development",
        "development_only": True,
        "formal_acceptance": formal_acceptance,
        "certificate_issued": certificate_issued,
        "pipeline_completed": pipeline_completed,
        "public_release_allowed": False,
        "verification_scope_policy_path":
            POLICY_PATH.as_posix(),
        "verification_scope_policy_sha256":
            declared_policy_hash,
        "stage377_result_path":
            STAGE377_RESULT_PATH.as_posix(),
        "stage377_result_sha256":
            stage377_result_sha256,
        "stage378_result_path":
            STAGE378_RESULT_PATH.as_posix(),
        "stage378_result_sha256":
            stage378_result_sha256,
        "development_gate_result_path":
            DEVELOPMENT_GATE_RESULT_PATH.as_posix(),
        "development_gate_result_sha256":
            development_gate_result_sha256,
        "previous_hash":
            stage378_result_sha256,
        "checks": {
            "verification_scope_policy_present":
                policy_present,
            "verification_scope_policy_hash_valid":
                policy_hash_valid,
            "verification_scope_policy_structure_valid":
                policy_structure_valid,
            "stage377_result_present":
                stage377_present,
            "stage377_result_hash_valid":
                stage377_hash_valid,
            "stage377_requirements_satisfied":
                stage377_requirements_satisfied,
            "stage378_result_present":
                stage378_present,
            "stage378_result_hash_valid":
                stage378_hash_valid,
            "stage378_hash_chain_valid":
                stage378_chain_valid,
            "stage378_requirements_satisfied":
                stage378_requirements_satisfied,
            "qkd_evidence_level_accepted":
                qkd_evidence_level_accepted,
            "safety_boundaries_satisfied":
                safety_boundaries_satisfied,
            "development_gate_allows_execution":
                development_gate_allows_execution,
            "critical_integrity_valid":
                critical_integrity_valid,
            "formal_acceptance_requirements_satisfied":
                formal_acceptance_requirements_satisfied,
        },
        "upstream_state": {
            "stage377_decision":
                stage377.get("decision")
                if stage377 else None,
            "stage377_verified_proof_count":
                stage377.get("verified_proof_count")
                if stage377 else None,
            "stage377_effective_final_acceptance":
                stage377.get(
                    "effective_final_acceptance"
                ) if stage377 else None,
            "stage378_decision":
                stage378.get("decision")
                if stage378 else None,
            "stage378_qkd_metadata_bound":
                stage378.get("qkd_metadata_bound")
                if stage378 else None,
            "stage378_evidence_classification":
                stage378.get("evidence_classification")
                if stage378 else None,
            "stage378_evidence_level":
                stage378.get("evidence_level")
                if stage378 else None,
        },
        "decision": decision,
        "reasons": reasons,
        "guarantee": (
            "Stage379 development evaluation verifies the "
            "locked scope, upstream self-hashes, hash chain, "
            "QKD public-safety boundary, and development gate. "
            "It never issues a formal certificate or declares "
            "pipeline completion while upstream evidence is "
            "pending."
        ),
    }

    result = write_json_with_hash(
        RESULT_PATH,
        result_payload,
        "result_sha256",
    )

    certificate_payload: Dict[str, Any] = {
        "stage": STAGE,
        "certificate_type":
            "development_non_acceptance_certificate",
        "created_at": created_at,
        "development_only": True,
        "formal_certificate": False,
        "formal_acceptance": False,
        "pipeline_completed": False,
        "scope_policy_sha256":
            declared_policy_hash,
        "stage377_result_sha256":
            stage377_result_sha256,
        "stage378_result_sha256":
            stage378_result_sha256,
        "stage379_result_sha256":
            result["result_sha256"],
        "decision": decision,
        "reasons": reasons,
        "statement": (
            "This document records a development evaluation "
            "only. It is not a formal Stage379 acceptance "
            "certificate and does not declare pipeline "
            "completion."
        ),
    }

    certificate = write_json_with_hash(
        CERTIFICATE_PATH,
        certificate_payload,
        "certificate_sha256",
    )

    summary_lines = [
        "Stage379 Scoped Total Verification Development Result",
        "====================================================",
        f"created_at: {created_at}",
        f"decision: {decision}",
        "development_only: true",
        "formal_acceptance: false",
        "certificate_issued: false",
        "pipeline_completed: false",
        f"scope_policy_sha256: {declared_policy_hash}",
        f"stage377_result_sha256: {stage377_result_sha256}",
        f"stage378_result_sha256: {stage378_result_sha256}",
        (
            "stage377_requirements_satisfied: "
            f"{stage377_requirements_satisfied}"
        ),
        (
            "stage378_requirements_satisfied: "
            f"{stage378_requirements_satisfied}"
        ),
        (
            "critical_integrity_valid: "
            f"{critical_integrity_valid}"
        ),
        (
            "formal_acceptance_requirements_satisfied: "
            f"{formal_acceptance_requirements_satisfied}"
        ),
        f"reasons: {', '.join(reasons) if reasons else 'none'}",
        f"result_sha256: {result['result_sha256']}",
        (
            "development_certificate_sha256: "
            f"{certificate['certificate_sha256']}"
        ),
        "",
        (
            "No formal acceptance certificate was issued. "
            "No pipeline completion was declared."
        ),
    ]

    SUMMARY_PATH.write_text(
        "\n".join(summary_lines) + "\n",
        encoding="utf-8",
    )

    print("Stage379 scoped total verification completed.")
    print(f"decision={decision}")
    print(
        "critical_integrity_valid="
        f"{critical_integrity_valid}"
    )
    print(
        "stage377_requirements_satisfied="
        f"{stage377_requirements_satisfied}"
    )
    print(
        "stage378_requirements_satisfied="
        f"{stage378_requirements_satisfied}"
    )
    print(
        "formal_acceptance_requirements_satisfied="
        f"{formal_acceptance_requirements_satisfied}"
    )
    print(f"formal_acceptance={formal_acceptance}")
    print(f"certificate_issued={certificate_issued}")
    print(f"pipeline_completed={pipeline_completed}")
    print(f"result_sha256={result['result_sha256']}")
    print(
        "development_certificate_sha256="
        f"{certificate['certificate_sha256']}"
    )

    return 0 if critical_integrity_valid else 1


if __name__ == "__main__":
    raise SystemExit(main())
