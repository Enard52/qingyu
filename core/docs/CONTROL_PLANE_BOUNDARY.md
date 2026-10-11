# Production Control Plane Boundary

This document defines the deployment boundary for the production Control Plane
used by Qingyu Core. It is a contract for an external, durable, non-cloned
authority. Core's relational database is a replica of the decisions needed by
the application; it is not the authority for fencing, ownership, or recovery.

## Authority and linearization

The Control Plane is the single linearization point for operations that can
change authority state:

- GENESIS reservation, claim, commit, anchor publication, and completion;
- continuity epoch issuance and owner lease acquisition/revocation;
- mutation prepare/commit/abort;
- owner transfer and restore claim/activation; and
- witness checkpoint advancement.

Each operation is serialized by a durable compare-and-swap on the authority's
current state. The accepted operation records its `mutation_id`, continuity,
epoch, expected state version, resulting state version, and audit checkpoint in
one authority transaction. A response is successful only after that commit is
durable and the required witness quorum has acknowledged it.

Core may commit its local transaction only after a prepare decision. Core then
publishes its resulting audit checkpoint to the authority and requests the
authority commit decision. If either side cannot reconcile, the continuity is
quarantined and writes fail closed until an operator completes reconciliation.

An authority implementation must provide a durable monotonic state, a 2-of-3
witness quorum, duplicate `mutation_id` detection, and recovery after process
or node loss. The initial PostgreSQL deployment persists a three-slot witness
set and two durable acknowledgements per operation in the independent Control
Plane database; moving those slots to independent witness nodes is an
operational fault-domain improvement, not a Core interface change. In-memory
authority is test/development-only. Production must fail closed when no
configured external authority is available.

## Separation from Core

The production Control Plane must not use the Core database as its only
durability mechanism and must not be restored from the same backup artifact as
Core. It owns authority state, witness acknowledgements, leases, storage
generation, and recovery claims. Core stores local projections and receipts for
verification and read paths.

The Core process has no Gateway database credentials, Gateway ORM imports, or
write capability to Gateway. Evidence remains available through Gateway's
stable read-only Evidence Query API.

## Credential classes

Use separate credentials and rotation domains for:

| Credential | Holder | Scope |
| --- | --- | --- |
| Control Plane service identity | Core runtime | Prepare/commit governed operations for assigned continuity |
| Control Plane operator identity | Break-glass operator tooling | Owner transfer, restore authorization, and quarantine release |
| Witness identities | Independent witness nodes | Quorum acknowledgement only |
| Core database identity | Core runtime/migration job | Core schema and local projection only |
| Gateway Evidence token | Core read client | GET-only Evidence Query API |

Credentials must be injected at runtime, never committed to source, and never
shared between Core, Gateway, migration jobs, operators, or witnesses. An
operator credential cannot be used as the Core service identity, and a Core
service identity cannot authorize owner transfer or restore activation.

## Failure behavior

The following conditions are fail-closed: unavailable quorum, stale or future
epoch, invalid lease, duplicate storage generation, duplicate genesis, audit
checkpoint mismatch, restore identity mismatch, and authority/Core state
divergence. The system must preserve the evidence needed to investigate the
condition and must not silently retry with a new identity, alias, epoch, or
mutation payload.
