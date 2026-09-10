# Phase 3 Final Acceptance Report

Status: PASS — Commit 5 closure record. Phase 3 is frozen at the Gateway boundary defined by the accompanying contracts.

## Scope and isolation

- Acceptance source: approved ChatGPT Export Sample #001, SHA-256 `04c54e6f87bd2113c5183ba7a2f24b2694c333e5eab6f42308f654063ee4b040`.
- Fresh source database: `qingyu_phase3_commit5_source`, migrated empty → 0015 → 0016.
- Fresh restore database: `qingyu_phase3_commit5_restore`, created from `template0`.
- Fresh archive roots: `D:\q5src` and `D:\q5dst`; both removed after acceptance.
- Long-term `qingyu` was not used as an acceptance source and was not mutated.
- Final long-term read-only transaction returned `qingyu | 0011_integrity_checked_at`; no migration or write was executed there.
- No staging tree was restored. No Worker Runtime, Hermes, Mem0, Graphiti, model provider, or network inference was loaded for restore validation.

## Actual backup and restore result

The operator helper `scripts/phase3_backup_restore_acceptance.ps1` completed successfully using PostgreSQL/`pg_dump` 16.15. It created a custom-format dump, verified `pg_restore --list`, copied only committed objects and manifests, restored the dump in one transaction, validated Alembic head and foreign-key validation state, and then removed both disposable databases and roots.

- Dump SHA-256: `c2ed33e866dbd1c065e7e16b41b4e71b2b0af96bde4f447a4ca345b2119193cc`
- Canonical source reconstruction digest: `ca4f7528dac6fa504be7f38256408863c02885e06aa31b1a57320f08e182cad4`
- Canonical restored reconstruction digest: `ca4f7528dac6fa504be7f38256408863c02885e06aa31b1a57320f08e182cad4`
- Unvalidated foreign keys: 0
- Restored staging: false
- Source/restore orphan committed objects: 0/0

Both source and restore independently produced: 15 conversations, 944 nodes, 929 messages, 15 structural null nodes, 15 roots, 3 branch parents, 18 leaves, 15 resolved current nodes, 941 current-path nodes, 9 resolved attachment objects with verified bytes, and 3 raw-only blobs not promoted to logical attachments.

The retained local backup package and secret-free inventory are in `D:\q5backup`. They are operator evidence, not repository content. The inventory records all dump/object/manifest digests, migration/parser versions, PostgreSQL tool versions, and hashes of the tested source files.

## Regression and independent review

- Repository-wide regression: `335 passed`, with 2 dependency deprecation warnings and 0 failures.
- Reviewer A — Evidence / Data Integrity: PASS; P0/P1/P2 open = 0.
- Reviewer B — Reliability / Disaster Recovery: PASS; P0/P1/P2 open = 0.
- Reviewer C — Architecture / Boundary: PASS; P0/P1/P2 open = 0.
- `git diff --check`: PASS; only Git's informational LF→CRLF worktree warnings were emitted.

## Cleanup confirmation

After the run, neither disposable database existed; `D:\q5src` and `D:\q5dst` did not exist. The backup package was intentionally retained for inspection. Cleanup never targeted the long-term database or archive root.

## Residual operational hardening

- P3: enforce the logical deletion boundary with distinct OS/database principals and audited ACL/RBAC policy.
- P3: define production RPO/RTO, backup encryption, retention, capacity, off-site replication, and periodic restore-drill ownership.
- P3: replace broad durable-report serialization with an explicit public allow-list if new report producers are introduced.

These items do not change the frozen evidence model and do not authorize a next implementation phase, Hermes integration, or any new runtime feature.
