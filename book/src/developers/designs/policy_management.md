# Policy Distribution and Management

## Summary

This document describes a policy distribution architecture where kanidm is the authoritative policy distribution server, and policy validation is performed on every client before policy activation.  
A dedicated client-side policy daemon retrieves policy bundles, verifies signatures, enforces scope/authorization rules, and exposes policy data only to intended policy consumers. Policy consumers are called **implementors** and are separate software components (for example, KDE) that enforce their own policy semantics. The content of the policy should not be standardized and left to be defined by the specific implementor and created by the administrator. Similar to how Active Directory has policy templating, but more open.

This makes implementation simpler, as the "policy" could just be the same format as the current config file for a given piece of software, but with priority enforcement, or it could be a new format.

## Motivation

We need a uniform policy distribution plane that:

- centralizes policy publication and rollout in Linux to facilitate better adoption for Linux Desktop in the enterprise space
- Most existing systems are more server oriented, requiring the client to be online at time of configuration
- have a policy management system that does not implicitly trust the server
- avoids broad local policy exposure,
- supports independent policy implementors without embedding implementation logic in the policy distribution daemon (kanidm)

## Goals

- Use kanidm as the distribution source for policies. 
- Require cryptographic signature verification of policies on clients.
- Ensure only authorized implementors can access their relevant policies (As defined by the policy manifest ).
- Decouple distribution/verification from policy enforcement.
- Provide safe rollout, rollback, and key rotation behavior.

## Non-Goals

- Defining the internal policy format of every implementor.
- Running policy enforcement logic inside the policy daemon.
- Providing unrestricted process-level access to all policy data.
- Replacing existing implementor-specific configuration loaders.

## Terminology
- **Policy manifest**: A manifest containing policy version, validity, payload digests, access control for the digests...
- **Policy Artifact**: Implementor-specific policy payload referenced by digest from the manifest.
- **Policy Daemon**: Local system service that syncs, verifies, stores, and serves policy data.
- **Implementor**: Separate software component that consumes policy and enforces behavior (example: KDE).
- **Active Snapshot**: The currently verified and activated local policy state.

## High-Level Architecture

1. Administrators publish policy manifests and artifacts to kanidm.
2. Manifests are signed by trusted policy signing keys.
3. Clients run a policy daemon that fetches updates from kanidm.
4. The daemon verifies signatures, validity windows, digests, and scope.
5. Verified policy is atomically installed as a new active snapshot.
6. Implementors read only their authorized policy view from daemon-managed interfaces.

## Trust and Security Model

- Transport security to kanidm is required but not sufficient.
- Policy authenticity is established by manifest signatures, verified client-side.
- Clients trust a configured policy trust root (or key set), not raw server responses.
- Manifest acceptance requires:
  - valid signature chain to a trusted key,
  - non-revoked signing key,
  - valid time window (`not_before`, `not_after`),
  - digest match for all referenced artifacts,
  - applicable target scope for the client.
- On validation failure, clients keep the previous active snapshot. (Please comment on this)

## Data Model

### Signed Policy Manifest
(Please comment)

Required fields:

- `policy_set_id` (stable identifier)
- `version` (monotonic integer)
- `issued_at`
- `not_before`
- `not_after`
- `scope` (domain, groups, host classes, attributes)
- `implementor_bindings`:
  - `implementor_id` (for example `org.kde.desktop`)
  - `implementor_path` (eg. /usr/bin/thunderbird)
  - `schema_id` / `schema_version` (Given to implementor)
  - artifact references + digests
- optional `supersedes` / `revokes` metadata

### Policy Artifacts

- Implementor-specific payload files (for example JSON/TOML/YAML/binary as declared by schema).
- Content-addressed and integrity-checked via digests from the signed manifest.
- Not trusted unless referenced by a validated manifest.

## Client Policy Daemon

### Responsibilities

- Authenticate to kanidm and sync policy metadata/artifacts. (Based on machine and user auth)
- Validate all cryptographic and semantic constraints.
- Build per-implementor projections from the active snapshot.
- Expose projection data through restricted local interfaces.
- Log verification, activation, and access events.
- Support rollback to last known-good snapshot.

### Local Access Control

The daemon MUST prevent broad policy disclosure:

- No world-readable policy store. (unless specified by manifest)
- Implementors can access only their own `implementor_id` projection using the `implementor_path` binary. 
- Access can be enforced by filesystem ACLs, local RPC identity checks, or both.
- Non-authorized processes receive no policy data.

### Activation Semantics

- Install new snapshots in staging storage.
- Verify complete snapshot before activation.
- Switch active snapshot atomically.
- Keep prior snapshot for rollback and resilience.
- (Comment) notify implementor of new policy ? (Optional?)

## Implementor Interface Model

Implementors are independent software and may have different policy semantics.

Required properties:

- Stable implementor identity (`implementor_id`).
- Versioned schema handling for their policy payloads.
- Explicit reload/apply behavior on policy update.
- No direct dependency on kanidm for policy fetch or trust decisions.

Example: KDE is an implementor that reads only KDE-scoped policy from the policy daemon and applies those settings in its own enforcement path.

## Distribution Flow

1. Publisher creates artifacts and manifest.
2. Publisher signs manifest and uploads manifest + artifacts to kanidm.
3. Policy daemon polls or receives change notification.
4. Daemon downloads manifest and referenced artifacts.
5. Daemon verifies signature, key status, freshness, scope, and digests.
6. Daemon stages and atomically activates the snapshot.
7. Daemon updates implementor projections and signals implementors (optional).
8. Implementors reload and enforce policy.

## Key Management and Rotation

- Support multiple trusted signing keys.
- Allow staged key rotation with overlap.
- Distribute revocation metadata via kanidm (As a policy whos implementor is the kanidm daemon?)
- Reject new and existing manifests signed by revoked keys.
- Preserve service continuity with last known-good valid snapshot.

## Failure Handling

- Verification failure: do not activate candidate snapshot.
- Offline mode: continue with active snapshot until local expiration policy is reached.
- Expired active snapshot: behavior is manifest defined. (Stop enforcement, continue enforcement but don't fallback to it, etc. )

## Open Questions

Lots. 

- Prefered manifest and signature formats
- Polling vs notification for change propagation.
- Standard local transport for implementors (files, Unix sockets, DBus ?).
- Many others

## Future Work
- Attestation of applied policy ? (That might be hard)