"""Owned independent request process for scoped Authority author race checks."""
import json
import os
from pathlib import Path
import sys
import time

import psycopg
from cryptography.hazmat.primitives import serialization
from app.control_plane.r1_scoped_authority import ScopedAuthority, configuration_digest
from app.control_plane.r1_scoped_postgres import ScopedPostgresStore
from app.control_plane.r1_scoped_messages import AuthorityCaller
from app.control_plane.r1_validation_codec import sha
from tests.r1_roundtrip_provider import material, trust, boundary


def run(config_path, request_path, ready_path, gate_path):
    path = Path(config_path)
    config = json.loads(path.read_text())
    assert config["container"] == "r1-s03-ca100502580e-pg" and config["host"] == "127.0.0.1" and config["port"] == 49995
    assert config["dbname"].startswith("r1_slice03_test_ca100502580e_author_")
    value = json.loads(Path(request_path).read_text())
    key = serialization.load_pem_private_key((path.parent / "receipt.key").read_bytes(), None)
    signs = []
    class Signer:
        key_id = config["pin"]["receipt_key_id"]
        def sign(self, message):
            signs.append(sha(message))
            return key.sign(message)
    def connect():
        return psycopg.connect(host=config["host"], port=config["port"], dbname=config["dbname"],
                               user="control_plane_app", password=config["app_password"])
    store = ScopedPostgresStore(connect, scope_id=config["scope_id"],
        configuration_digest=configuration_digest(trust(config), (material(config),), boundary(config)))
    service = ScopedAuthority(store=store, trust=trust(config), deployments=(material(config),),
                               boundary=boundary(config), receipt_signer=Signer())
    Path(ready_path).write_text(str(os.getpid()))
    deadline = time.monotonic() + 20
    while not Path(gate_path).exists():
        if time.monotonic() >= deadline:
            raise RuntimeError("owned race gate timeout")
        time.sleep(.01)
    try:
        reply = service.prepare(bytes.fromhex(value["request"]), bytes.fromhex(value["source"]), AuthorityCaller(**value["caller"]))
        result = {"pid": os.getpid(), "status": reply.state, "ack_sha256": sha(reply.ack_wire), "sign_calls": len(signs)}
    except Exception as exc:
        result = {"pid": os.getpid(), "status": "REJECT", "error_type": type(exc).__name__,
                  "reason": str(exc), "sign_calls": len(signs)}
    print(json.dumps(result))


if __name__ == "__main__":
    run(*sys.argv[1:])
