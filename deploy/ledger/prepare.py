"""Prepare local private configuration from a pinned canonical ledger checkout."""

import argparse
import json
import os
from pathlib import Path
import secrets
import shutil
import subprocess

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


PIN = "2679c9e0a5430cde9e435339e441a94989d2bcd6"
TASK = Path(__file__).resolve().parents[4]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, default=TASK / "work/ledger-track")
    parser.add_argument("--runtime", type=Path, default=TASK / "work/ledger-runtime")
    parser.add_argument("--port-offset", type=int, default=0)
    parser.add_argument("--instance", default="earned-authority")
    args = parser.parse_args()
    source, runtime = args.source.resolve(), args.runtime.resolve()
    head = subprocess.check_output(["git", "-C", str(source), "rev-parse", "HEAD"], text=True).strip()
    if head != PIN:
        raise SystemExit(f"expected canonical source revision {PIN}; found {head}")
    if subprocess.check_output(["git", "-C", str(source), "diff", "--name-only", "HEAD"], text=True).strip():
        raise SystemExit("canonical tracked source must be unmodified")
    runtime.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(runtime, 0o700)
    env_file = runtime / "local.env"
    if env_file.exists():
        print(json.dumps({"status": "existing_configuration_preserved", "env_file": str(env_file)}))
        return
    init = runtime / "init"
    init.mkdir(mode=0o700)
    for migration in sorted((source / "migrations").glob("*.sql")):
        shutil.copy2(migration, init / migration.name)
    admin_password = secrets.token_hex(24)
    app_password = secrets.token_hex(24)
    permissions = (source / "demo/postgres-init/03-permissions.sql").read_text()
    permissions = permissions.replace("PASSWORD 'ledger_app'", f"PASSWORD '{app_password}'")
    (init / "999_permissions.sql").write_text(permissions)
    # SQL only initializes an empty named volume; restart never resets its data.
    private_key = Ed25519PrivateKey.generate()
    key_file = runtime / "writer-private.pem"
    key_file.write_bytes(private_key.private_bytes(serialization.Encoding.PEM,
                        serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    os.chmod(key_file, 0o600)
    public_file = runtime / "writer-public.pem"
    public_file.write_bytes(private_key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
    values = {
        "LEDGER_INSTANCE": args.instance,
        "LEDGER_SOURCE_DIR": str(source), "LEDGER_RUNTIME_DIR": str(runtime),
        "LEDGER_DOCKERFILE": str(Path(__file__).with_name("Dockerfile").resolve()),
        "LEDGER_DB_ADMIN_PASSWORD": admin_password, "LEDGER_DB_APP_PASSWORD": app_password,
        "ARE_LEDGER_API_TOKEN": secrets.token_hex(32), "LEDGER_DB_PORT": str(29432 + args.port_offset),
        "LEDGER_GRPC_PORT": str(29492 + args.port_offset), "LEDGER_HEALTH_PORT": str(29480 + args.port_offset), "LEDGER_METRICS_PORT": str(29483 + args.port_offset),
        "LEDGER_SIGNER_KEY_ID": "earned-authority-local-writer-v1",
        "LEDGER_PRIVATE_KEY_PATH": str(key_file), "LEDGER_PUBLIC_KEY_PATH": str(public_file),
    }
    env_file.write_text("".join(f"{key}={value}\n" for key, value in values.items()))
    os.chmod(env_file, 0o600)
    print(json.dumps({"status": "prepared", "source_revision": PIN, "env_file": str(env_file),
                      "named_volume": args.instance + "-ledger-data"}))


if __name__ == "__main__":
    main()
