# Control Plane Backup and Disaster Recovery Runbook

This runbook applies to the production Control Plane and its three witness
stores. It does not authorize direct writes to Gateway or to the Core database.
Keep Control Plane backups and Core backups in separate repositories, with
separate access policies and retention controls.

## Backup requirements

Back up the following authority data using the Control Plane's supported,
consistent snapshot mechanism:

- current epoch, state version, storage generation, and lease state;
- immutable GENESIS manifest, initial owner fingerprint, and anchor;
- owner-transfer and recovery records;
- mutation decision records keyed by `mutation_id`;
- witness quorum checkpoints and audit high-water/head hash; and
- backup metadata: authority version, snapshot id, creation time, and source
  witness set.

The snapshot must be acknowledged by at least two of three witnesses. A single
database dump, filesystem copy, or Core backup is not a valid Control Plane
backup. Encrypt backups at rest and in transit, and test restore using a
quarantined authority namespace before declaring the backup usable.

## Restore procedure

1. Freeze governed writes and record the affected continuity and last known
   authority checkpoint.
2. Select a Control Plane snapshot and verify its signature, source witness
   set, snapshot id, and monotonic version.
3. Restore into a new, isolated authority namespace. Never overwrite the live
   authority in place.
4. Obtain two-of-three witness agreement that the restored snapshot is valid.
5. Compare the restored GENESIS identity, `continuity_id`, initial owner
   fingerprint, storage generation, epoch, and audit checkpoint with the
   incident record and Core backup manifest.
6. Keep the restored continuity read-only. The operator must explicitly claim
   recovery and issue a higher epoch before writes can resume.
7. Reconcile Core's local audit high-water/head hash and state version against
   the authority checkpoint. Any mismatch remains quarantined.
8. After validation, route traffic to the new authority namespace, monitor the
   first governed mutation, and retain the old namespace for investigation.

Do not restore a cloned Core database and the old authority namespace together
as if they were one transaction. The authority's recovery claim is the fencing
event that prevents the old runtime or clone from writing.

## Core backup exclusion

Core backups may contain local projections, receipts, and the append-only audit
ledger needed for verification. They must not be treated as backups of:

- Control Plane lease or witness state;
- owner-transfer authorization;
- the authoritative epoch issuer;
- the authoritative GENESIS duplicate-prevention record; or
- Gateway Evidence.

Core restore starts read-only and requires identity, continuity, GENESIS owner
anchor, authority checkpoint, and audit-chain verification. A restored Core
database cannot self-authorize writes or issue an epoch.

## Recovery evidence

Record snapshot ids, witness acknowledgements, operator identity, approval
reason, old/new epochs, storage generations, audit checkpoint, and the final
reconciliation result. Retain failed and rejected restore attempts. Do not
delete or rewrite them to make a restore appear successful.

