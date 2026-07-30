# Stage381: Deterministic Reverification & Reproducibility Gate

Stage381 extends Stage380 with a cross-platform deterministic
reverification and reproducibility gate.

It verifies whether the same fixed verification input produces the same
material result on:

- Ubuntu
- Windows
- macOS

Stage381 does not replace, rewrite, or upgrade the Stage380 verification
scope. It preserves the Stage380 independent offline verification package
and adds a fail-closed cross-platform comparison layer.

## What Stage381 Adds

Stage381 adds the following public verification components:

1. A fixed canonicalization profile
2. Deterministic environment-result generation
3. Ubuntu, Windows, and macOS verification through GitHub Actions
4. Cross-platform comparison of required result fields
5. A Stage381 verification-package contract
6. SHA-256 binding of the contract and verification records
7. A final fail-closed package verifier
8. Downloadable GitHub Actions verification artifacts

## Verification Flow

```text
Stage380 independent offline verification package
                    |
                    v
      Fixed Stage381 canonicalization rules
                    |
                    v
       Ubuntu / Windows / macOS execution
                    |
                    v
       Deterministic environment results
                    |
                    v
        Cross-platform field comparison
                    |
                    v
       Stage381 final package verification
```

## Required Cross-Platform Conditions

Stage381 requires all three configured platforms to be present.

The comparison must confirm:

- the same fixed verification input was used
- the same decision was produced
- the same verification status was produced
- the same package-integrity result was produced
- the same critical-failure count was produced
- the same process exit code was produced
- the same Stage380 result SHA-256 was bound
- the same canonical result SHA-256 was produced

If a required platform result is missing, malformed, inconsistent, or not
bound to the required Stage380 input, Stage381 remains fail-closed.

## One-Command Local Verification

A local machine can validate the Stage381 package structure with:

```bash
python3 development/stage381/verify_stage381_cross_platform_package.py
```

A single local machine verifies only the result available on that machine.

Formal cross-platform verification requires Ubuntu, Windows, and macOS
results. The included GitHub Actions workflow provides those environments
without requiring the operator to own three separate computers.

## GitHub Actions Verification

The workflow is:

```text
.github/workflows/stage381-cross-platform-reverification.yml
```

It performs:

1. Deterministic verification on Ubuntu
2. Deterministic verification on Windows
3. Deterministic verification on macOS
4. Artifact collection
5. Cross-platform comparison
6. Stage381 contract validation
7. Final package verification
8. Verification-package artifact upload

## License

This project is released under the MIT License.

See the `LICENSE` file included in this repository for the complete license
text.

## Security and Publication Boundary

Stage381 publishes only the files required for deterministic verification
and audit.

The following material must remain outside the public repository:

- `core/`
- `private_core/`
- `private/`
- `secrets/`
- `keys/`
- `imported/`
- private keys
- credentials
- unpublished raw evidence
- confidential execution material

Stage381 does not publish attack code, harmful payloads, secret keys, or
private-core implementation material.

## Fail-Closed Meaning

A fail-closed result does not automatically mean that the verifier
malfunctioned.

Before all three operating-system results exist, Stage381 must report that
cross-platform reverification is not verified.

Stage381 may report successful cross-platform reproducibility only after all
required platform records exist and all required comparison fields match.

## Current Verification Status

The Stage381 implementation and GitHub Actions workflow are present.

Formal Stage381 cross-platform completion requires a successful GitHub
Actions execution with matching Ubuntu, Windows, and macOS results.

Until that execution succeeds, cross-platform reverification must remain
unverified.

## Inherited Stage380 Foundation

The following Stage380 documentation is retained because Stage381 extends
rather than replaces the Stage380 independent offline verification package.
Stage380 extends Stage379 by packaging the established verification scope into a deterministic offline verification contract.

Stage380 does not replace or rewrite Stage379. It preserves the Stage379 development snapshot and verifies the package from an independent, offline, fail-closed perspective.

## Purpose

Stage380 adds two core capabilities:

1. Independent Verification Package Contract
2. Deterministic Offline Core Verifier

The purpose is to make the Stage379 verification package independently reproducible without network access and without changing the established verification scope.

## Current State

Stage380 is currently development-only.

The current decision is:

`development_package_verified_upstream_pending`

Current verified state:

- package integrity verified: `true`
- formal independent verification: `false`
- formal acceptance: `false`
- pipeline completed: `false`
- public release allowed: `false`
- critical failure count: `0`

Formal independent verification remains pending because the upstream formal acceptance conditions are not yet complete.

## Upstream Conditions

Stage380 depends on the established Stage377, Stage378, and Stage379 results.

Required formal conditions include:

### Stage377

- `verified_proof_count == 2`
- `effective_final_acceptance == true`

### Stage378

- `qkd_metadata_bound == true`
- Stage377 result hash valid
- Stage378 hash chain valid
- QKD publication boundary valid
- QKD evidence classification complete

### Stage379

- `formal_acceptance == true`
- `pipeline_completed == true`
- `critical_integrity_valid == true`

Until these conditions are satisfied, Stage380 must remain development-only and fail closed against any formal acceptance claim.

## Independent Verification Package Contract

The Stage380 contract is:

`development/stage380/stage380_independent_verification_package_contract.json`

The contract defines:

- source stage
- source snapshot manifest
- required input files
- deterministic offline execution
- package locking
- scope-reduction prohibition
- fail-closed behavior
- development-only state
- formal acceptance prohibition

The contract is fixed by:

`development/stage380/stage380_independent_verification_package_contract.sha256`

Verification command:

```bash
shasum -a 256 -c development/stage380/stage380_independent_verification_package_contract.sha256
```

## Deterministic Offline Core Verifier

The Stage380 verifier is:

development/stage380/verify_stage380_independent_package.py

The verifier performs the following checks:

Stage380 contract presence
Stage380 contract SHA-256 verification
SHA-256 record path verification
contract policy validation
required input presence checks
required input SHA-256 calculation
Stage379 snapshot manifest verification
Stage379 snapshot artifact hash verification
Stage379 snapshot artifact size verification
duplicate artifact-path detection
Stage377 state observation
Stage378 state observation
Stage379 state observation
Stage379 critical-integrity validation
Stage379 development certificate validation
formal-acceptance readiness evaluation
fail-closed decision generation
deterministic result generation

Run the verifier with:

python3 development/stage380/verify_stage380_independent_package.py

Expected current decision:

decision=development_package_verified_upstream_pending
package_integrity_verified=true
formal_independent_verification=false
critical_failure_count=0
## Deterministic Output

Stage380 is designed so that the same input produces the same output.

The result intentionally excludes:

runtime timestamps
random values
hostnames
usernames
absolute local paths
network-derived values

Deterministic verification can be checked with:

FIRST_HASH=$(shasum -a 256 development/stage380/stage380_independent_verification_result.json | awk '{print $1}')
python3 development/stage380/verify_stage380_independent_package.py >/dev/null
SECOND_HASH=$(shasum -a 256 development/stage380/stage380_independent_verification_result.json | awk '{print $1}')
printf "FIRST_HASH=%s\nSECOND_HASH=%s\n" "$FIRST_HASH" "$SECOND_HASH"
[ "$FIRST_HASH" = "$SECOND_HASH" ] && echo "DETERMINISTIC_OUTPUT_VALID"
## Fail-Closed Principle

Stage380 must return fail_closed when a critical verification requirement fails.

Examples include:

missing Stage380 contract
invalid contract JSON
contract SHA-256 mismatch
invalid SHA-256 record path
missing required input
missing Stage379 snapshot manifest
Stage379 snapshot artifact missing
Stage379 snapshot artifact hash mismatch
Stage379 snapshot artifact size mismatch
duplicate snapshot artifact path
invalid Stage379 critical integrity
invalid development certificate type
contract policy mismatch
scope reduction enabled
offline mode disabled
package lock disabled

Stage380 does not convert missing, unknown, pending, or invalid evidence into verified evidence.

## Verification Result

The deterministic verification result is:

development/stage380/stage380_independent_verification_result.json

It contains:

decision
verification status
package-integrity status
formal-verification status
upstream state
contract SHA-256
snapshot SHA-256
required-input SHA-256 values
verification checks
critical failures
deterministic result SHA-256

The external result hash record is:

development/stage380/stage380_independent_verification_result.sha256

Verification command:

shasum -a 256 -c development/stage380/stage380_independent_verification_result.sha256
## Verification Manifest

The Stage380 manifest is:

development/stage380/stage380_independent_verification_manifest.json

The manifest records:

development policy
verification contract
deterministic verifier
verification result
verification certificate
actual SHA-256 values
actual file sizes
artifact count

The manifest is fixed by:

development/stage380/stage380_independent_verification_manifest.sha256

Verification command:

shasum -a 256 -c development/stage380/stage380_independent_verification_manifest.sha256
## Verification Certificate

The Stage380 development certificate is:

development/stage380/stage380_independent_verification_certificate.json

Certificate type:

development_independent_verification_certificate

The certificate does not claim formal independent verification.

It records that:

deterministic offline package verification completed
package integrity was verified
formal independent verification remains pending
upstream formal acceptance remains incomplete
pipeline completion is not claimed

The certificate is fixed by:

development/stage380/stage380_independent_verification_certificate.sha256

Verification command:

shasum -a 256 -c development/stage380/stage380_independent_verification_certificate.sha256
## Stage379 Preservation

Stage380 preserves and consumes the Stage379 development package.

Primary Stage379 inputs include:

development/stage379/stage379_development_snapshot_manifest.json
development/stage379/stage379_development_acceptance_certificate.json
development/stage379/stage379_scoped_total_verification_result.json
development/stage379/stage379_verification_scope_policy.json

Stage380 does not modify these Stage379 records.

The previous root README is preserved at:

development/stage380/README.stage377-preserved.md

## Public and Private Boundaries

Stage380 preserves the existing Git exclusion rules.

The following directories must remain private and must not be pushed to GitHub:

core/
private_core/
private/
secrets/
keys/
imported/

Stage380 must not publish:

private keys
secret seeds
access tokens
OIDC tokens
GitHub tokens
raw QKD key material
private runner output
unrestricted external command input
raw confidential evidence

Only reviewed metadata and approved public evidence may be placed under docs/.

## Offline Verification Boundary

The Stage380 verifier requires no network access.

It does not:

contact timestamp authorities
contact blockchain nodes
contact Sigstore or Rekor
download GitHub Actions artifacts
fetch external evidence
execute user-supplied shell commands
generate or expose secret material

Stage380 verifies the locally available package as provided.

## Directory Structure
development/stage380/
├── README.stage377-preserved.md
├── stage380_independent_verification_package_contract.json
├── stage380_independent_verification_package_contract.sha256
├── verify_stage380_independent_package.py
├── stage380_independent_verification_result.json
├── stage380_independent_verification_result.sha256
├── stage380_independent_verification_manifest.json
├── stage380_independent_verification_manifest.sha256
├── stage380_independent_verification_certificate.json
└── stage380_independent_verification_certificate.sha256

Root development policy:

.stage380-development-policy.json
## Verification Sequence

Recommended verification sequence:

python3 -m json.tool .stage380-development-policy.json >/dev/null

python3 -m json.tool \
development/stage380/stage380_independent_verification_package_contract.json \
>/dev/null

shasum -a 256 -c \
development/stage380/stage380_independent_verification_package_contract.sha256

python3 -m py_compile \
development/stage380/verify_stage380_independent_package.py

python3 \
development/stage380/verify_stage380_independent_package.py

shasum -a 256 -c \
development/stage380/stage380_independent_verification_result.sha256

python3 -m json.tool \
development/stage380/stage380_independent_verification_manifest.json \
>/dev/null

shasum -a 256 -c \
development/stage380/stage380_independent_verification_manifest.sha256

python3 -m json.tool \
development/stage380/stage380_independent_verification_certificate.json \
>/dev/null

shasum -a 256 -c \
development/stage380/stage380_independent_verification_certificate.sha256
## Decision Model
development_package_verified_upstream_pending

The Stage380 package is internally valid, but upstream formal acceptance conditions remain incomplete.

independent_verification_package_ready

The Stage380 package is internally valid and all required upstream formal acceptance conditions are satisfied.

This decision must not be emitted unless the actual Stage377, Stage378, and Stage379 records satisfy the contract.

fail_closed

One or more critical integrity, policy, hash, file, snapshot, or certificate checks failed.

## Security Properties

Stage380 provides the following development-stage properties:

deterministic local verification
offline operation
package integrity validation
artifact hash validation
artifact size validation
duplicate-path detection
upstream-state observation
fail-closed decisions
scope-lock enforcement
scope-reduction prohibition
private-boundary preservation
no formal claim while upstream is pending

Stage380 does not prove that an external organization or independent third party has executed the verifier.

That requires an actual independent execution environment and independently retained evidence.

## Current Limitations

Current limitations include:

Stage377 has not yet reached dual verified timestamp acceptance
Stage378 QKD metadata binding remains pending
Stage379 formal acceptance remains pending
Stage380 remains development-only
no third-party execution claim is made
no production-readiness claim is made
no pipeline-completion claim is made

These limitations are intentionally represented rather than hidden.

## License

This project is licensed under the MIT License.

See:

LICENSE

The MIT License applies to the published source code and documentation in this repository. It does not override restrictions, confidentiality requirements, third-party licenses, or security controls applicable to private material or external evidence.
