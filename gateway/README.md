# Qingyu Memory Gateway

Phase 1 foundation. PostgreSQL 16 runs only in Docker Compose.

### Linux / macOS (bash)

```bash
python3.12 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
cp .env.example .env
# In .env set POSTGRES_PASSWORD and matching DATABASE_URL.
# Generate three distinct secrets for API_TOKEN, EVIDENCE_READ_API_TOKEN,
# and EVIDENCE_CURSOR_SIGNING_KEY:
python -c "import secrets; print(secrets.token_urlsafe(32))"
docker compose up -d db
alembic upgrade head
uvicorn app.main:app --host 127.0.0.1 --port 8000
```

### Windows (PowerShell)

```powershell
py -3.12 -m venv .venv
& .\.venv\Scripts\python.exe -m pip install -e ".[dev]"
Copy-Item .env.example .env
# In .env set POSTGRES_PASSWORD and matching DATABASE_URL.
# Generate three distinct secrets for API_TOKEN, EVIDENCE_READ_API_TOKEN,
# and EVIDENCE_CURSOR_SIGNING_KEY:
python -c "import secrets; print(secrets.token_urlsafe(32))"
docker compose up -d db
& .\.venv\Scripts\python.exe -m alembic upgrade head
& .\.venv\Scripts\python.exe -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

> **Note**: For any `APP_ENV` other than `test`, Gateway requires three distinct, non-example secrets (`API_TOKEN`, `EVIDENCE_READ_API_TOKEN`, and `EVIDENCE_CURSOR_SIGNING_KEY`); see `gateway/app/config.py`.

