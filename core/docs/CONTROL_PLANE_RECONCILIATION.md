# Control Plane and Core Reconciliation Contract

Core and the external Control Plane intentionally hold different views of the
same continuity. Reconciliation proves that the Core projection is permitted
to participate in the current authority epoch; it does not promote Core into a
source of truth.

## Required comparison

For a continuity under review, compare these values exactly:

| Field | Control Plane | Core |
| --- | --- | --- |
| `qingyu_identity_id` | immutable identity | identity registry |
| `continuity_id` | immutable continuity key | continuity registry |
| `initial_owner_fingerprint` | immutable anchor | GENESIS record |
| `storage_generation` | current generation | metadata / GENESIS projection |
| `epoch` | fencing epoch | continuity and metadata projection |
| `state_version` | authority version | Core metadata |
| `audit_high_water` | committed audit sequence | Core metadata / audit ledger |
| `audit_head_hash` | committed audit head | Core metadata / audit ledger |
| `lease_id` and expiry | current lease | local lease projection, if present |

The comparison must also verify that the Core audit chain is contiguous and
that every committed local receipt has a matching authority decision. Alias
resolution is a lookup concern; an alias is never compared as an identity key.

## Reconciliation outcomes

- `RECONCILED`: all required values match and the authority permits the local
  runtime to continue.
- `READ_ONLY`: identity and GENESIS match, but the authority has not issued a
  current lease or recovery epoch.
- `QUARANTINED`: any identity, owner anchor, generation, epoch, audit, witness,
  or receipt mismatch exists.
- `REJECTED`: the manifest is malformed, refers to a different continuity, or
  attempts to use an old epoch or old lease.

Only the external authority may move `READ_ONLY` or `QUARANTINED` back to a
writable state. Local repair must be append-only and must retain the original
failure evidence. Reconciliation must never create a new continuity to bypass
a conflict.

## Commit protocol checkpoint

For each governed mutation, the durable sequence is:

1. authority accepts a prepare using the expected epoch, lease, mutation id,
   and state version;
2. Core records a local prepared/committed receipt and audit record;
3. Core publishes the resulting audit checkpoint;
4. authority commits the mutation and witness quorum acknowledges it; and
5. Core marks the receipt final only after the authority commit is confirmed.

If the sequence stops between steps, restart with the same mutation id and the
same canonical payload. A different payload, identity, epoch, or alias is a
new operation and must be rejected until the old operation is resolved.

