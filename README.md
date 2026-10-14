# Qingyu

Qingyu is a personal **memory gateway** plus a **governance core**, written in Python (FastAPI + PostgreSQL 16).

| Directory | What it is |
|---|---|
| `gateway/` | Qingyu Memory Gateway: imports and archives conversation data (e.g. ChatGPT exports), stores memories, and exposes a read-only evidence API. |
| `core/` | Qingyu Core: identity, governance, signer trust, audit and the R1 control plane. It uses its own PostgreSQL database and reads Gateway data only through the read-only API. |
| `contracts/` | Shared JSON schemas and contracts between Gateway and Core. |

## Quick start (Gateway)

```bash
cd gateway
python3.12 -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
cp .env.example .env   # fill in DATABASE_URL and API_TOKEN yourself
docker compose up -d db
alembic upgrade head
uvicorn app.main:app --host 127.0.0.1 --port 8000
```

See `gateway/README.md` and `core/README.md` for component details.

## History

This repository was assembled from the original per-component repositories. Their full commit history (from September 2026 on) has been preserved with original dates, under `gateway/`, `core/` and `contracts/`. Local acceptance-evidence artifacts, database snapshots, backups and machine-specific paths were removed from history before publication.

## AI-assisted development

Much of this code was written with AI coding agents (e.g. OpenAI Codex) under the maintainer's direction and review. Original commit identities from those agents were normalized to the maintainer account.

## License

Apache License 2.0. See [LICENSE](LICENSE).
