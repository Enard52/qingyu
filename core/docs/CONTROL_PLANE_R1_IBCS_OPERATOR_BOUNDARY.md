# R1 IBCS Operator Boundary

Status: DESIGN CANDIDATE / test-only acceptance profile; no service exists yet.

IBCS must use a process, service identity, signing credential, authenticated
TLS endpoint, append-only storage and storage/IBCS generation distinct from
Core, Authority, Gateway and every legacy database/volume. Runtime cannot
generate or replace its signing key, trust-on-first-use a new identity, rewrite
certificates, lower its head, or automatically recover ambiguous storage.

Startup verifies pinned identity/generation, certificate hash chain, current
head, storage ownership/ACL and configured backup provenance before serving a
fresh attestation. Any missing predecessor, duplicate sequence with different
hash, unexpected lower head, identity/generation mismatch, corrupt row/file,
ambiguous restore or multiple active deployment claim produces:

`QUARANTINE + ADMISSION CLOSED + operator recovery required`.

IBCS also persists the singleton public half/metadata of the current
`CoreActivationTicketV1`. A ticket binds the witnessed head and a process-only
ephemeral public key. Runtime restart or machine restore cannot silently evict
a live ticket; expiry/revocation and a new Authority-authorized activation are
required. Operator inspection must show ticket claimant, expiry, head and any
competing claim without exposing a private key.

Runtime must not drop/recreate/reinitialize IBCS storage, mint replacement
history, copy Core/Authority state into IBCS, or interpret Authority operational
confirmation as permission to repair. Operator recovery is a separate signed
procedure that verifies backup/history, records reason/provenance, and—if
authorized by a future contract—bumps IBCS generation. C01 does not implement
that disaster-recovery product. Acceptance teardown/destruction requires later
explicit authorization. Production needs its own deployment and ceremony; the
test-only IBCS/Root cannot be promoted.

Operator and acceptance reports may contain public identities, generations,
certificate hashes and test results, never private keys, passphrases, bearer
credentials or DSNs. Gateway/legacy resources remain zero-touch.
