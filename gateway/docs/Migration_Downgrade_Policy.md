# Migration downgrade policy

Forward migrations are the supported production path. Downgrades are intended
for disposable development and migration-verification databases and can be
destructive when a revision drops tables or columns.

Migration `0003_archive_observations` moves source provenance out of
`archive_objects`. Its historical downgrade drops the observation table and does
not reconstruct provenance or restore the original non-null source columns. It
must therefore be treated as a destructive, unsupported production downgrade.
The published historical migration is intentionally unchanged.

Migration `0013_import_job_defaults` has a deterministic downgrade to
the nullable/default contract established by `0005` and `0006`. It does not
attempt to repair older destructive downgrade semantics.
