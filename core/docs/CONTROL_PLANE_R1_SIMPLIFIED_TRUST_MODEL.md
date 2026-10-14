# Control Plane R1 Simplified Trust Model

Status: DESIGN CANDIDATE. This document defines the Revision 6 security claim;
it does not assert implementation or acceptance. Revision 5 is retained only
as rejected design history and is not patched or inherited by implication.

## Trust anchor and threat boundary

R1 chooses IBCS as a **trusted monotonic independent witness**. Correctness
assumes that IBCS retains its append-only history and signing identity. Core
and Authority do not prove IBCS non-rollback; Authority confirmation metadata
is not a correctness root. The supported claims are:

1. A Core rollback or stale clone is detected relative to fresh IBCS head.
2. An Authority rollback or stale state is detected relative to fresh IBCS head.
3. Any Core/Authority/IBCS mismatch or missing proof closes admission.
4. IBCS unavailability, identity/generation mismatch, corruption suspicion or
   ambiguous storage state closes admission and requires operator recovery.

R1 does **not** claim automatic cryptographic detection of IBCS's own rollback,
or detection after Core, Authority and IBCS are all consistently rolled back.
Multi-witness quorum, transparency logs and cross-region consensus are outside
R1. They require a later architecture phase. This is a narrower honest claim,
not permission to silently repair or continue after witness uncertainty.

IBCS remains a separate authenticated process, credential, service identity,
storage, generation and protected deployment. Same-host acceptance proves
process/credential/storage isolation and fail-closed behavior, not whole-host
disaster tolerance. Production requires a separately approved deployment and
recovery ceremony. IBCS recovery is never an ordinary runtime path.

## Trust domains and allowed failures

| Domain | In-scope observations/failures | Safety response |
| --- | --- | --- |
| Core Local | crash, response loss, stale snapshot/clone, rollback, restart | compare exact canonical head and storage generation with Authority terminal and fresh IBCS; mismatch CLOSED/QUARANTINE |
| Authority | crash, response loss, stale canonical state, rollback, restart | compare signed terminal chain/head with IBCS; behind/conflict CLOSED/QUARANTINE |
| IBCS | outage, response loss, stale nonce, identity/generation mismatch, suspected corruption/rollback/storage ambiguity | no automatic diagnosis/repair; CLOSED/QUARANTINE and operator recovery |
| Operator/Root | fixed public authorization and explicit recovery | secrets remain outside Core/IBCS DB; compromise or consistent global rollback is outside R1 automated guarantee |

An old nonce, self-consistent local database, Authority operational metadata,
or maximum numeric sequence is never sufficient. Only exact hashes, signed
lineage, a fresh IBCS attestation and proof-of-possession for IBCS's one current
Core activation ticket may open admission. The ticket's ephemeral private key
is process-memory-only; disk clones cannot obtain it. Legitimate restart uses
explicit ticket expiry/revocation and Authority-authorized fresh activation,
never silent replacement of a live claimant.

## Required fault classifications

- `Core=N-1, Authority=N, IBCS=N`: stale Core/clone; admission closed. Normal
  restart may replay exact signed receipt/audit into the same admitted storage
  generation. A different clone/storage identity needs explicit restore.
- `Authority=N-1, IBCS=N`: Authority stale/rollback/divergence; admission closed.
  Core cannot reconstruct Authority history or choose the larger number.
- `Core=Authority=N, IBCS=N-1/unavailable/conflicting`: divergence. If Core's
  durable publication state is `PUBLICATION_PENDING`, § retry rules may append
  the exact N only against expected IBCS predecessor. If local state is
  `PUBLICATION_CONFIRMED`, missing/lower IBCS is QUARANTINE and never republished.
- `IBCS>N` relative to either Core or Authority: stale external domain;
  admission closed and explicit reconciliation required.
- equal sequence with different receipt/certificate/audit/terminal hash:
  QUARANTINE. No numeric maximum reconciliation.

IBCS may itself have rolled back in any divergence, but R1 does not claim to
prove that cause. It guarantees fail-closed behavior for the observed mismatch.
