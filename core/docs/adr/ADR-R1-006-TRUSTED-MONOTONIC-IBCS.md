# ADR R1-006: IBCS as trusted monotonic witness

Status: Proposed / Simplification Design Gate pending.

## Decision

R1 treats IBCS as the sole trusted monotonic witness for canonical receipt
high-water. The correctness chain is one-way:

`Operation candidate -> Authority Terminal Certificate -> Core canonical
receipt/audit -> IBCS Publication Certificate -> nonce-bound IBCS Freshness
Attestation -> Admission`.

Authority may retain publication acknowledgements for observability, metrics
and audit, but they cannot establish, override or repair canonical history and
are not an admission prerequisite. No Authority/IBCS mutual anti-rollback loop
is part of R1.

## Consequences

- Core and Authority rollback/clone are detectable relative to trusted IBCS.
- IBCS outage or any mismatch is fail-closed.
- IBCS self-rollback and globally consistent rollback of all domains are not
  automatically detectable and are expressly outside the R1 threat model.
- IBCS must be independently deployed and protected; recovery requires an
  explicit operator ceremony. This ADR does not specify a production DR product.
- Multi-witness/quorum/transparency log belongs to a later Architecture Phase.
- Strict serial publication is accepted: N+1 cannot start before N is witnessed
  and a fresh exact-head admission check succeeds.

## Rejected alternatives

- Authority confirmation as a second anti-rollback authority: rejected because
  it creates circular trust and a confirmation-ledger rollback ambiguity.
- Core local state as high-water: rejected because Core backups are cloneable.
- Automatic `max(sequence)` repair: rejected because equal numbers do not prove
  equal signed history and can conceal a fork.

