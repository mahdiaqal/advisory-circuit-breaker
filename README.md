# AdvisoryCircuitBreaker

An operational GenLayer gate for **one Maven release against one named GHSA advisory**. It is not a versioned graph, a certificate issuer, an escrow, or a general vulnerability scanner. The result controls whether the owner can record use of the release through this contract.

## Why GenLayer

The Maven release identity and GitHub Advisory Database affected-version data are fetched from fixed, contract-derived URLs. The advisory's exploit description is not a structured policy category; GenLayer leader and validators independently classify its primary impact. That semantic class determines whether an affected release is `BLOCKED` or `WATCH` under the owner's precommitted policy. The complete source hashes, parsed coordinates, affected-version result, impact class, decision and report root must match exactly. A bad source or unclear impact is `REVIEW`, never permission to use.

```text
register_release(group, artifact, version, GHSA, policy)
       │
       ▼
scan_advisory ── fetch Maven Central POM + GitHub advisory JSON independently
       │           verify coordinates and affected range
       │           classify exploit impact with validator consensus
       ├── BLOCKED / REVIEW ── deny activation and use
       └── OPEN / WATCH ── owner may activate ── record_use
```

`scan_advisory` is permissionless so a third party can trigger a fresh risk check. A blocking or indeterminate scan deactivates the gate immediately. `record_use` is owner-only, requires an active permissive gate and a scan no older than its configured 1–24 hour window, and binds an immutable use ID to the scan root. A stale scan stops use even if the stored status remains permissive. The owner can always disable. A new release requires a new gate; registration never mutates a release's identity or advisory.

## Trust boundary

- The caller does **not** supply a vulnerability summary, impact label, source body, confidence score, or arbitrary URL. The contract derives `repo.maven.apache.org` and `api.github.com` URLs from bounded identifiers.
- The Maven POM establishes the registered artifact's published identity, **not** that any external service deployed it.
- GitHub Advisory Database establishes what this particular advisory records about the package. Absence from one advisory is **not** proof of general safety.
- The semantic classifier determines policy category, not factual package identity or affected-version membership.
- A `WATCH` result permits activation only because the owner did not configure that impact to block; RCE is always a blocking class. `REVIEW` denies use.
- Consumers must actually call `record_use` or `can_use`; this contract cannot stop a service that ignores the gate.
- This is a testnet research primitive, not professional vulnerability-management advice.

## API

`register_release`, `scan_advisory`, `activate`, `disable`, `record_use`, `can_use`, `get_gate`, `get_scan`, `get_use`.

Example gate: `org.apache.logging.log4j:log4j-core:2.14.1` against `GHSA-jfh8-c2jp-5v3q`, blocking `RCE,DOS`. A second gate for `2.17.1` demonstrates the advisory-specific unaffected path. The [GitHub advisory record](https://api.github.com/advisories/GHSA-jfh8-c2jp-5v3q) and [Maven Central release](https://repo.maven.apache.org/maven2/org/apache/logging/log4j/log4j-core/2.14.1/log4j-core-2.14.1.pom) are the externally acquired evidence.

## Checks and deployment

```powershell
genvm-lint check contracts/AdvisoryCircuitBreaker.py --json
python -m pytest tests/direct -q
genlayer network set studionet
genlayer deploy --contract contracts/AdvisoryCircuitBreaker.py
genlayer receipt <deployment-tx-hash>
genlayer code <contract-address>
```

Inspect a finalized receipt's **leader execution result**, not only its lifecycle status, before citing it as proof. See [LIVE_PROOFS.md](LIVE_PROOFS.md) for verified transactions. The source uses a pinned GenVM runner.
