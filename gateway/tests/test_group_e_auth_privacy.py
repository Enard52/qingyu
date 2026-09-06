import logging

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError

from app.config import Settings
from app.db import engine
from app.main import app
from app.errors import safe_database_error


@pytest.mark.parametrize('token',['','changeme','example','change-this-local-token'])
def test_non_test_runtime_rejects_public_or_empty_tokens(token):
    with pytest.raises(ValueError,match='API_TOKEN'):
        Settings(app_env='production',api_token=token,_env_file=None)


def test_sqlalchemy_hides_secret_parameters():
    marker='SUPER_SECRET_CHAT_CONTENT_123'
    assert engine.hide_parameters is True
    with engine.connect() as connection:
        with pytest.raises(Exception) as caught: connection.execute(text('select cast(:value as integer)'),{'value':marker})
    assert marker not in safe_database_error(caught.value)


def test_api_database_error_and_auth_logs_do_not_leak_secrets(caplog):
    marker='SUPER_SECRET_CHAT_CONTENT_123'; token='SUPER_SECRET_TOKEN'
    if not any(getattr(route,'path',None)=='/_test_database_error' for route in app.routes):
        @app.get('/_test_database_error')
        def fail(): raise SQLAlchemyError(marker)
    caplog.set_level(logging.INFO)
    response=TestClient(app).get('/_test_database_error')
    assert response.status_code==500 and response.json()=={'detail':{'code':'database_error'}}
    TestClient(app).get('/api/v1/protected-ping',headers={'Authorization':f'Bearer {token}'})
    output=caplog.text
    assert marker not in output and token not in output
