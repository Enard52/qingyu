# ADR: Control Plane Reliability Profiles

- Status: R1 reliability decision and baseline provenance amendment accepted for design; implementation not authorized by this ADR
- Scope: Qingyu Core Phase 2, Foundation Commit 1 remediation
- Supersedes: Phase 2 interpretation that a single PostgreSQL database can
  provide three independent rollback witnesses

## Context

The frozen Core design described a three-witness, two-of-three protocol across
independent failure domains. Commit 1B represented those witnesses as rows in
the same PostgreSQL Authority database and let the Authority process create two
acknowledgements itself. Restoring the database restores both the Authority and
its alleged witness evidence. The design therefore cannot prevent two restored
Authority copies from independently appearing active.

Correct multi-failure-domain consensus requires external infrastructure and is
not safely approximated with additional rows, locks, or counters in one
database. Qingyu will not implement Raft or Paxos inside the Python Core.

Subsequent read-only investigation found the same-database witness tables and
rows in an old acceptance database, but found no canonical committed Control
Plane `0001_control_plane` revision or signed provisioning/identity origin.
Those existing rows are **legacy forensic evidence**, not a production witness
deployment or a canonical Authority history. The separate baseline decision
is specified in `CONTROL_PLANE_R1_BASELINE_PROVENANCE.md`.

## Decision

Control Plane reliability is split into two explicit profiles.

### R1 — Personal Production

R1 uses one independent, durable PostgreSQL Authority deployment. All supported
Core clones for an Authority domain connect to this same deployment. PostgreSQL
transactions and conditional CAS provide the linearization point for writer,
owner, epoch, generation, and recovery decisions.

The deployment includes an independent Authority Service. Core calls its
versioned authenticated TLS API and never receives the Authority database DSN
or receipt-signing private key. The service database role may execute hardened
`SECURITY DEFINER` procedures and read restricted views, but has no direct
authoritative-table, sequence, DDL, or ownership privileges.

R1 supports Core cloning, Core backup/restore, duplicate runtimes, stale-writer
fencing, Authority process restart, temporary Authority outage with fail-closed
writes, and manual Authority replacement only from an externally verifiable
complete Authority head. Core backups never contain Authority data, runtime
credentials, or receipt-signing keys. R1 does not require independently durable
zero-RPO recovery storage. Therefore unexpected permanent Authority loss is
unrecoverable when completeness of the last acknowledged terminal head cannot
be proved; the domain remains fail closed.

R1 Authority identity is `(authority_domain_id, authority_instance_id,
authority_generation)`. Core pins that identity and the Authority receipt
verification key. Manual DR decommissions the old deployment, admits only a
recovery source whose complete signed terminal head is independently provable,
restores it in isolation, verifies the external operator-root-signed generation
record and surviving Core receipts as additional fencing evidence, then creates
a new instance/key and advances generation in one stable-ID idempotent
activation. The generation record and Core receipts do not by themselves prove
completeness of normal terminal commits. If a commit may be missing, or the
maximum accepted generation/head cannot be proven, activation fails closed.
Core accepts the new pin only with the operator-root-signed transition artifact.

R1 assumes operators never expose two Authority deployments for one domain at
the same time. It does not provide automatic election if an Authority database
is cloned and both copies are brought online. An updated Core rejects receipts
from the old instance/generation after manual DR, but R1 does not claim to
control an operator who continues routing other stale Core clients to an old
Authority.

### R2 — High Availability / Multi-host

R2 covers independent Authority failure domains, rollback witnesses, quorum
membership, automatic election/failover, and automatic prevention of split
brain between concurrently exposed Authority clones. It is deferred. A future
R2 implementation must integrate a mature linearizable consensus service such
as etcd or Consul rather than implement custom consensus in Core.

## Consequences

- Same-database `cp_witnesses`, `cp_quorum_acks`, `_quorum()` and all claims
  that they are a production security mechanism are excluded from the new R1
  implementation. Their real rows in the CASE D legacy acceptance database
  remain untouched and forensic-only; this ADR authorizes no cleanup.
- R1 still requires durable operation receipts, an Authority-owned monotonic
  sequence, exact idempotency scope, `PREPARED -> COMMITTED|ABORTED`, uncertain-
  result reconciliation, real dual-Core-clone acceptance, role separation,
  independent migrations, and a tested manual DR procedure.
- Manual DR is not a general permanent-loss guarantee: a commit-response-loss
  followed by loss of the Authority and every complete recovery chain must make
  activation of an older backup fail closed.
- Authority database clone/election is removed from the R1 acceptance matrix
  and becomes an R2 acceptance concern. Dual **Core** clone competition against
  one Authority remains mandatory R1 evidence.
- Core Foundation Commit 1 remains open until the R1 implementation and three
  independent implementation reviews pass.
- The old hand-written `0001_control_plane` marker is not the parent of the
  new canonical lineage. A newly committed parentless
  `0001_control_plane_r1_initial` begins R1 in a separately provisioned
  `qingyu_control_r1_acceptance` environment, with signed origin and no trust
  transfer from the old acceptance database. The baseline ADR governs details.

`PREPARED` produces a durable authenticated prepare acknowledgement but does
not consume the terminal Authority sequence or advance its hash head. Exactly
one terminal `COMMITTED` or authoritative `ABORTED` receipt is signed and
ordered at PostgreSQL transaction commit. Core persists local intent before
contacting Authority and treats any transport-uncertain result as
reconciliation-required, never as an inferred abort.

Terminal order is lexicographic `(authority_generation, authority_sequence)`;
the numeric sequence is monotonic within one generation, and the generation-
1 opening receipt uses a domain-separated genesis seed bound to the signed
canonical provisioning origin and has no previous generation. Each later
generation-opening receipt binds the verified previous generation terminal
head and its operator-signed DR authorization. R1 uses an
immutable offline operator-root key pinned at GENESIS to authorize manual DR and
new instance/key transitions. If the previous accepted generation/head or root
cannot be proven, recovery remains fail-closed.

The detailed normative contract, dirty-diff disposition, implementation DAG,
and acceptance matrix are in `../CONTROL_PLANE_R1_REMEDIATION_PLAN.md`.
