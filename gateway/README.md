# Qingyu Memory Gateway

Phase 1 foundation. PostgreSQL 16 runs only in Docker Compose.

```powershell
py -3.12 -m venv .venv
& .\.venv\Scripts\python.exe -m pip install -e ".[dev]"
Copy-Item .env.example .env
# Generate a local token, then set API_TOKEN in .env:
python -c "import secrets; print(secrets.token_urlsafe(32))"
docker compose up -d db
& .\.venv\Scripts\python.exe -m alembic upgrade head
& .\.venv\Scripts\python.exe -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

## Running tests

Gateway tests require a dedicated test database named `qingyu_test` with migrations applied to the latest revision. If the database isn't migrated, the tests stop early and tell you to run `alembic upgrade head` against it.

Windows (PowerShell):

```powershell
$env:APP_ENV="test"
$env:TEST_DATABASE_URL="postgresql+psycopg://qingyu:<your-password>@127.0.0.1:5432/qingyu_test"
$env:DATABASE_URL=$env:TEST_DATABASE_URL
& .\.venv\Scripts\python.exe -m alembic upgrade head
& .\.venv\Scripts\python.exe -m pytest -q
```

Linux / macOS (bash), from `gateway/` with its venv activated:

```bash
. .venv/bin/activate
export APP_ENV=test
export TEST_DATABASE_URL="postgresql+psycopg://qingyu:<your-password>@127.0.0.1:5432/qingyu_test"
export DATABASE_URL="$TEST_DATABASE_URL"
alembic upgrade head
python -m pytest -q
```
