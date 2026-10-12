#!/usr/bin/env python3
"""Install a new Passport issuer and reread one receipt signed by the previous key."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from evidence import bind_sources, source_hashes

HERE = Path(__file__).resolve().parent
KIT = HERE.parents[1]
sys.path.insert(0, str(KIT))
TASK = Path(os.environ.get("EA_WORKSPACE", str(KIT.parents[1]))).resolve()
from earned_authority.passport_client import PassportClient


def config(path):
    return dict(line.split("=", 1) for line in path.read_text().splitlines() if line and not line.startswith("#"))


def write_env(path, values):
    path.write_text("".join(f"{key}={value}\n" for key, value in values.items()))
    os.chmod(path, 0o600)


def pem_private(key):
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())


def pem_public(key):
    return key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)


def fingerprint(text):
    return hashlib.sha256(text.encode()).hexdigest()


def client(values, public, historical=()):
    return PassportClient("127.0.0.1:" + values["ARE_PASSPORT_GRPC_PORT"], values["ARE_PASSPORT_MUTATION_TOKEN"], public,
                          sdk_path=values["PASSPORT_SDK_DIR"], historical_public_keys=historical)


def main():
    before_hashes = source_hashes()
    parser = argparse.ArgumentParser()
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    runtime = TASK / "work/reference-runtime"
    env_path = runtime / "reference.env"
    values = config(env_path)
    state = json.loads(Path(values["ARE_PASSPORT_STATE_PATH"]).read_text())
    operations = state.get("operations") or {}
    if not operations:
        raise SystemExit("Passport state has no operation receipt to reread")
    operation_id = sorted(operations)[0]
    payload = json.loads(base64_payload(operations[operation_id]["canonical_payload"]))
    agent = payload["agent_id"]
    public_path = Path(values["ARE_PASSPORT_PUBLIC_KEY_PATH"])
    key_path = Path(values["ARE_PASSPORT_KEY_PATH"])
    historical_path = Path(values.get("ARE_PASSPORT_HISTORICAL_KEYS_PATH") or runtime / "passport/historical-public.pem")
    saved = runtime / "issuer-cutover-previous"
    report = {"environment": "REAL_LOCAL_SERVICES", "started_at": datetime.now(timezone.utc).isoformat(),
              "agent_id": agent, "operation_id": operation_id, "checks": [],
              "scope": "Explicit issuer cutover on one host. New operations use the new key. One previously stored receipt still verifies under the public key that signed it. The previous public key is installed in an explicit historical file; receipts do not grant trust by themselves.",
              "limits": ["Not silent rotation", "Not hardware key protection", "Not a second host"]}

    def check(name, passed, **evidence):
        report["checks"].append({"check": name, "passed": bool(passed), "evidence": evidence})
        if not passed:
            raise AssertionError(name)

    def reference(command):
        subprocess.run([sys.executable, str(HERE / "reference.py"), command], check=True, env={**os.environ, "EA_WORKSPACE": str(TASK)})

    replaced = False
    try:
        current_public = public_path.read_text()
        previous = client(values, current_public)
        try:
            stored = previous.operation(agent, operation_id)
        finally:
            previous.close()
        check("historical_receipt_verifies_before_cutover", stored is not None and stored["public_key_pem"] == current_public,
              receipt_digest=hashlib.sha256(base64_bytes(stored["canonical_payload_base64"])).hexdigest(), issuer=fingerprint(current_public))
        reference("stop")
        if saved.exists():
            shutil.rmtree(saved)
        saved.mkdir(mode=0o700)
        shutil.copy2(key_path, saved / "ed25519.pem")
        shutil.copy2(public_path, saved / "ed25519-public.pem")
        if historical_path.is_file():
            shutil.copy2(historical_path, saved / "historical-public.pem")
        new_key = Ed25519PrivateKey.generate()
        historical_path.parent.mkdir(mode=0o700, exist_ok=True)
        historical_text = (historical_path.read_text() if historical_path.is_file() else "") + current_public
        if not historical_text.endswith("\n"):
            historical_text += "\n"
        historical_path.write_text(historical_text)
        os.chmod(historical_path, 0o600)
        key_path.write_bytes(pem_private(new_key))
        os.chmod(key_path, 0o600)
        new_public = pem_public(new_key).decode()
        public_path.write_text(new_public)
        values["ARE_PASSPORT_HISTORICAL_KEYS_PATH"] = str(historical_path)
        write_env(env_path, values)
        replaced = True
        reference("restore")
        fresh = client(config(env_path), new_public, (current_public,))
        try:
            reread = fresh.operation(agent, operation_id)
            check("historical_receipt_verifies_after_new_key", reread["public_key_pem"] == current_public and reread["canonical_payload_base64"] == stored["canonical_payload_base64"],
                  previous_issuer=fingerprint(current_public), current_issuer=fingerprint(new_public))
            authority = fresh.current(agent)
            scopes = []
            for scope in authority["subject"]["scope_set"]:
                ttl = (scope["expires_ts"] - scope["granted_ts"]) // 1000
                scopes.append({"action_class": scope["action_class"], "resource_pattern": scope["resource_pattern"],
                               "context_constraints": scope["context_constraints"], "scope_ttl_seconds": ttl})
            passport_ttl = (authority["subject"]["expires_ts"] - authority["subject"]["issued_ts"]) // 1000
            issued = fresh.issue(agent, scopes, passport_ttl, authority, "issuer-cutover", operation_id="issuer-cutover-" + operation_id[:24])
            new_receipt = issued["operation_receipt"]
            check("new_operation_uses_new_key", new_receipt["public_key_pem"] == new_public and new_receipt["public_key_pem"] != current_public,
                  operation_id=new_receipt["operation_id"], issuer=fingerprint(new_public))
            again = fresh.operation(agent, operation_id)
            check("original_receipt_still_verifies", again["canonical_payload_base64"] == stored["canonical_payload_base64"] and again["public_key_pem"] == current_public)
        finally:
            fresh.close()
        report.update(execution_state="COMPLETED", acceptance_color="GREEN")
    except Exception as exc:
        report.update(execution_state="ABORTED", acceptance_color="RED", error=type(exc).__name__ + ": " + str(exc))
        if replaced and (saved / "ed25519.pem").is_file():
            shutil.copy2(saved / "ed25519.pem", key_path)
            shutil.copy2(saved / "ed25519-public.pem", public_path)
            previous_historical = saved / "historical-public.pem"
            if previous_historical.is_file():
                shutil.copy2(previous_historical, historical_path)
            elif historical_path.is_file():
                historical_path.unlink()
            restored = config(env_path)
            restored.pop("ARE_PASSPORT_HISTORICAL_KEYS_PATH", None)
            write_env(env_path, restored)
            subprocess.run([sys.executable, str(HERE / "reference.py"), "restore"], check=False, env={**os.environ, "EA_WORKSPACE": str(TASK)})
    bind_sources(report, before_hashes)
    report["finished_at"] = datetime.now(timezone.utc).isoformat()
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"report": str(args.report), "status": report["acceptance_color"], "checks": len(report["checks"])}))
    return 0 if report.get("execution_state") == "COMPLETED" else 1


def base64_payload(value):
    import base64
    if isinstance(value, str):
        return base64.b64decode(value)
    return bytes(value)


def base64_bytes(value):
    import base64
    return base64.b64decode(value)


if __name__ == "__main__":
    raise SystemExit(main())
