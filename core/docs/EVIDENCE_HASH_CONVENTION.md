# Evidence Hash Convention

For Git checkpoint and closure evidence, do not treat a raw worktree byte SHA-256 as the only committed-content binding.

Preferred bindings:

- Git object identity for commits, tags, and blobs.
- SHA-256 over explicitly identified Git committed blob content.

If evidence also records a worktree byte hash, label it clearly as `worktree-byte-hash`. If evidence records a hash over committed Git blob content, label it as `git-blob-content-hash`. This avoids apparent mismatches caused by checkout newline conversion or other worktree filters.

Historical evidence is not rewritten for this convention. New checkpoint evidence should name which byte domain each hash covers.
