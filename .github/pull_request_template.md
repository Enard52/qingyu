## What does this change?

## Why?

Closes #

## Checklist

- [ ] Tests added or updated, and they pass locally (`pytest -q` in the affected component)
- [ ] `ruff check --select E9,F63,F7,F82 .` passes
- [ ] No secrets, tokens, real conversation data or machine-specific paths
- [ ] Keeps the design boundaries (Gateway evidence stays append-only; Core does not import Gateway code or use Gateway DB credentials; failures stay fail-closed)
- [ ] Docs updated if behaviour changed
