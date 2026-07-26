# Stage377: Production Dual-Timestamp Finalization and Superseding Final Acceptance Gate

Stage377 extends Stage376 by connecting two independently verified production timestamp receipts to a new effective final-acceptance decision.

Stage377 does not rewrite the Stage372 or Stage376 historical records. It preserves both records and creates a new Stage377 result only after the required external evidence has been evaluated.

## Purpose

Stage376 established the fail-closed acceptance model for external timestamps.

Stage377 adds the operational finalization layer:

1. Produce and verify an RFC3161 timestamp receipt.
2. Produce and verify an OpenTimestamps receipt.
3. Confirm that both proofs refer to the same established Stage360 target.
4. Bind the new decision to the established Stage376 result hash.
5. Issue a new effective final acceptance only when both independent proofs verify.
6. Preserve the Stage372 and Stage376 historical records without modification.

## Established Bindings

Stage376 result SHA256:

`32ff58a1f4d5837518226eee70b32833a8147617df3142ff2f641eca3f116138`

Canonical Stage360 timestamp target SHA256:

`052c8f0283110e405443d56f2396c52a8486e7a70a489f831af107dad73ab1b5`

Historic Stage372 result SHA256:

`ef1847f09c7862d271d71e548f403f75c91b93b2ffc21dec6016f53e0db7c3aa`

## Initial State

Before both production timestamp receipts are verified:

- `decision: timestamp_finalization_pending`
- `rfc3161_verified: false`
- `opentimestamps_verified: false`
- `effective_final_acceptance: false`
- `maximum_timestamp_assurance: false`

This is the expected fail-closed state.

An unexecuted or unconfirmed timestamp system must not be treated as verified.

## Successful State

Final acceptance is issued only when both independent timestamp rails verify:

- `decision: dual_timestamp_final_acceptance_verified`
- `rfc3161_verified: true`
- `opentimestamps_verified: true`
- `verified_proof_count: 2`
- `timestamp_verified: true`
- `effective_final_acceptance: true`
- `maximum_timestamp_assurance: true`

## Decision Model

Stage377 can return the following decisions:

### `timestamp_finalization_pending`

Neither timestamp system has completed a verified production result.

### `rfc3161_verified_opentimestamps_pending`

The RFC3161 receipt is verified, but the OpenTimestamps proof is still unconfirmed or unverified.

### `opentimestamps_verified_rfc3161_pending`

The OpenTimestamps receipt is verified, but the RFC3161 receipt is still unverified.

### `dual_timestamp_final_acceptance_verified`

Both independent timestamp systems verified the same Stage360 target and all final-acceptance conditions passed.

### `block`

A required binding, receipt, hash, verification result, or publication-boundary condition failed.

## RFC3161 Verification Rail

The RFC3161 workflow:

- verifies the exact Stage360 target SHA256 before execution
- generates an RFC3161 request using SHA256
- sends the request to the configured timestamp authority
- receives a timestamp response
- extracts the signed timestamp token
- verifies the target message imprint
- verifies the timestamp authority signature
- verifies the certificate chain using OpenSSL
- generates a metadata-only public receipt
- deletes raw RFC3161 material from the GitHub-hosted runner

The public repository does not require publication of the raw timestamp request, raw timestamp response, timestamp token, or certificate bundle.

## OpenTimestamps Verification Rail

The OpenTimestamps workflow:

- verifies the exact Stage360 target SHA256 before execution
- copies the target into a private runner directory
- creates an OpenTimestamps proof
- runs OpenTimestamps verification
- records whether a confirmed public blockchain anchor exists
- records `pending_confirmation` when confirmation is not yet available
- claims `verified` only when the public anchor and verified time are confirmed
- generates a metadata-only public receipt
- deletes the raw `.ots` proof from the GitHub-hosted runner

A newly created OpenTimestamps proof commonly requires time before reaching a confirmed public blockchain anchor.

Stage377 does not treat an unconfirmed proof as final verification.

## GitHub Actions Workflows

Stage377 adds:

- `.github/workflows/stage377-production-rfc3161.yml`
- `.github/workflows/stage377-production-opentimestamps.yml`
- `.github/workflows/stage377-dual-final-acceptance.yml`

### RFC3161 Workflow

Produces the artifact:

`stage377-rfc3161-metadata-receipt`

### OpenTimestamps Workflow

Produces the artifact:

`stage377-opentimestamps-metadata-receipt`

### Dual Final-Acceptance Workflow

Accepts:

- RFC3161 GitHub Actions run ID
- OpenTimestamps GitHub Actions run ID

It downloads the two metadata receipts, imports them into the checked-out repository, runs the Stage377 finalization engine, and generates a metadata-only finalization package.

The finalization workflow does not automatically commit or push files to the repository.

## Stage377 Engine

The Stage377 finalization engine is:

`scripts/stage377_dual_timestamp_finalization.py`

It validates:

- Stage376 result integrity
- Stage372 result integrity
- Stage360 target hash binding
- RFC3161 receipt structure
- RFC3161 verification status
- OpenTimestamps receipt structure
- OpenTimestamps verification status
- common target binding
- required proof count
- metadata-only publication boundary
- absence of forbidden timestamp binaries under `docs/`
- absence of private key material under `docs/`

## Public Evidence

Stage377 publishes the following metadata and decision files:

- `docs/timestamp-policy/stage377_dual_timestamp_finalization_policy.json`
- `docs/timestamp-evidence/stage377_rfc3161_verification_receipt.json`
- `docs/timestamp-evidence/stage377_opentimestamps_verification_receipt.json`
- `docs/timestamp-finalization/stage377_dual_timestamp_finalization_result.json`
- `docs/timestamp-finalization/stage377_superseding_final_acceptance_manifest.json`
- `docs/timestamp-finalization/stage377_dual_timestamp_finalization_summary.txt`

## Private and Excluded Material

Stage377 does not publish:

- private keys
- secret seeds
- OIDC tokens
- GitHub tokens
- raw QKD key material
- RFC3161 `.tsq` files
- RFC3161 `.tsr` files
- RFC3161 timestamp tokens
- RFC3161 certificate bundles
- raw OpenTimestamps `.ots` proof files
- free-form externally supplied shell commands

Raw timestamp material is handled under Git-ignored private directories.

## Historical Preservation

Stage377 does not change the historic Stage372 or Stage376 result files.

The Stage377 result records their established hashes and creates a new result representing a later verification state.

Superseding does not mean deleting or rewriting previous history.

It means that a newer, independently verified record establishes the latest effective final-acceptance state.

## Fail-Closed Principle

Stage377 does not grant final acceptance merely because:

- one timestamp rail succeeded
- a proof file exists
- a workflow completed without a validated receipt
- an OpenTimestamps proof was created but not confirmed
- a timestamp response was received but not cryptographically verified
- two receipts refer to different target hashes
- a required historical hash does not match
- raw timestamp material entered the public directory

Any such state remains pending or becomes blocked.

## Local Verification

Run:

```bash
python3 -m py_compile \
  scripts/stage377_dual_timestamp_finalization.py

python3 \
  scripts/stage377_dual_timestamp_finalization.py

cat \
  docs/timestamp-finalization/stage377_dual_timestamp_finalization_summary.txt

Before production timestamp receipts exist, the expected output includes:

Decision: timestamp_finalization_pending
RFC3161 Verified: False
OpenTimestamps Verified: False
Effective Final Acceptance: False
Maximum Timestamp Assurance: False
GitHub Pages

Stage377 preserves the existing GitHub Pages structure under:

docs/

Public page:

https://mokkunsuzuki-code.github.io/stage377/

Safety Statement

Stage377 is a verification and audit-evidence system.

It does not include:

malware
exploit automation
attack payloads
credential theft
private-key publication
raw QKD key publication
License

MIT License.

<!-- STAGE378_README_START -->

# Stage378: QKD Safety Metadata Binding & Evidence Classification Gate

Stage378 extends Stage377 with a Fail-Closed QKD safety metadata binding and evidence classification layer.

Stage378 does not publish, reconstruct, transfer, or expose raw QKD key material.

## Stage377 to Stage378

Stage377 dual-timestamp finalization result -> Stage377 result SHA256 validation -> previous_hash binding -> QKD safety metadata validation -> QKD evidence classification -> raw-key non-publication verification -> QKD evidence-level assignment -> Stage378 decision.

## What Stage378 Adds

- Stage377 result SHA256 verification
- Stage377 previous-hash binding
- QKD safety metadata validation
- QKD evidence-source classification
- QKD evidence-level assignment
- QBER declaration consistency checking
- QKD raw-key publication prevention
- private-material scanning inside docs
- Fail-Closed handling when Stage377 is incomplete

## Evidence Classifications

- metadata_only: public safety metadata only
- qkd_simulator: evidence generated by a QKD simulator
- controlled_testbed: evidence generated in a controlled QKD test environment
- physical_qkd_system: evidence generated by an identified physical QKD system

Simulator evidence is not treated as physical-device evidence.

## QKD Evidence Levels

- QKD-E0: invalid, insufficient, inconsistent, or unsafe evidence
- QKD-E1: safe metadata-only evidence
- QKD-E2: QKD simulator evidence
- QKD-E3: controlled QKD testbed evidence
- QKD-E4: physical QKD-system evidence satisfying required metadata checks

The evidence level identifies the type and completeness of submitted evidence. It does not independently prove universal QKD security.

## QBER Handling

Stage378 does not impose one universal QBER threshold.

It validates observed_qber, declared_qber_limit, qber_within_declared_limit, and limit_source.

The threshold source must be identified because the valid limit may depend on the protocol, implementation, security proof, operating conditions, or system policy.

## Current Initial State

Stage377 currently reports timestamp_finalization_pending and verified_proof_count 0.

Therefore Stage378 correctly reports qkd_binding_pending_previous_stage, metadata_only, QKD-E1, and qkd_metadata_bound false.

This is the expected Fail-Closed result.

## Public Stage378 Files

- docs/qkd/stage378_qkd_safety_metadata_input.json
- docs/qkd/stage378_evidence_classification.json
- docs/qkd/stage378_qkd_safety_metadata_binding_result.json
- docs/qkd/stage378_qkd_safety_metadata_binding_summary.txt

## Stage378 Engine

- scripts/stage378_qkd_safety_metadata_binding_gate.py

## Publication Boundary

Stage378 prohibits publication of raw QKD keys, sifted keys, reconciled keys, final QKD secrets, derived secret material, private keys, device credentials, GitHub tokens, OIDC tokens, RFC3161 raw binaries, and OpenTimestamps raw binaries.

Only public metadata, classifications, hashes, decisions, and summaries belong in docs.

## Private Directories

- core/
- private_core/
- private/
- secrets/
- keys/
- runner-output/
- imported/

## License

MIT License. See LICENSE.

<!-- STAGE378_README_END -->
