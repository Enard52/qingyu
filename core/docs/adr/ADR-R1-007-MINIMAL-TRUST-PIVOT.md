# ADR R1-007: Minimal trust model pivot

Status: Proposed / independent design review pending.

## Decision

R1 removes the self-built IBCS and all automatic clone/rollback detection and
recovery from required scope. It retains Authority-signed terminal truth,
durable Core decision/finalization fencing, exact receipt/Audit/state binding,
deterministic reconciliation, and explicit operator re-admission after every
process restart, restore, clone, snapshot recovery, copy or storage replacement.

`R1-MARATHON-C01` is disposed as **DEFERRED / REMOVED FROM R1 REQUIRED SCOPE**,
not PASS and not failed implementation. Revision 1–6 evidence remains immutable
design history. No Revision 7 or further self-built witness protocol is allowed.

## Deferred beyond R1

- self-built IBCS or transparency log;
- automatic clone/Core rollback/Authority rollback discovery;
- snapshot restore auto-activation or automatic rollback recovery;
- multi-witness/quorum/cross-region/Byzantine rollback detection.

If later required, first evaluate a mature external transparency log,
consensus-backed witness, managed monotonic service or append-only external
ledger and freeze its actual guarantees in a new Architecture Phase.

## Consequences

R1 makes no automatic anti-rollback claim. A locally self-consistent restored
database is not ACTIVE evidence. On every service start the default is
`RECOVERY_REQUIRES_OPERATOR_ADMISSION`; write, lease, owner and governance
mutation paths remain denied until a fresh explicit recovery authorization
validates Authority and local history and creates a new storage generation and
runtime incarnation. Availability is intentionally sacrificed for safety.

Authority publication acknowledgements and old IBCS documents have no runtime
correctness role. Gateway/legacy remain outside scope and zero-touch.

