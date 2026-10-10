"""Exercise the real, owned canonical ledger and PostgreSQL deployment.

This is connected-service correctness evidence, not a product-value evaluation.
It restarts only the two named reference containers and restores its one admin
tamper probe in a finally block. The named database volume is retained.
"""

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import subprocess
import sys
import time
from urllib.request import urlopen
from uuid import uuid4

from cryptography.hazmat.primitives import serialization

KIT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(KIT))
from earned_authority.ledger_client import LedgerClient, LedgerError, canonical_json


def read_config(path):
    return dict(line.split("=", 1) for line in path.read_text().splitlines()
                if line and not line.startswith("#"))


def client_from_config(config, *, token=None, trust=True):
    private = serialization.load_pem_private_key(
        Path(config["LEDGER_PRIVATE_KEY_PATH"]).read_bytes(), password=None)
    public = serialization.load_pem_public_key(Path(config["LEDGER_PUBLIC_KEY_PATH"]).read_bytes())
    return LedgerClient(
        "127.0.0.1:" + config["LEDGER_GRPC_PORT"],
        config["ARE_LEDGER_API_TOKEN"] if token is None else token,
        sdk_path=Path(config["LEDGER_SOURCE_DIR"]) / "sdks/python",
        signer_private_key=private, signer_key_id=config["LEDGER_SIGNER_KEY_ID"],
        trusted_writers={config["LEDGER_SIGNER_KEY_ID"]: public} if trust else {},
    )


def await_ready(config, timeout=90):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with urlopen("http://127.0.0.1:" + config["LEDGER_HEALTH_PORT"] + "/readyz", timeout=2) as response:
                if response.status == 200:
                    return
        except Exception:
            pass
        time.sleep(0.5)
    raise RuntimeError("owned ledger did not become ready before timeout")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--env-file", required=True, type=Path)
    parser.add_argument("--report", required=True, type=Path)
    parser.add_argument("--skip-restart", action="store_true")
    args = parser.parse_args()
    config = read_config(args.env_file)
    instance = config.get("LEDGER_INSTANCE", "earned-authority")
    db_name, service_name = instance + "-ledger-db", instance + "-ledger-service"
    run_id = "ledger-connected-" + str(uuid4())
    report = {"run_id": run_id, "started_at": datetime.now(timezone.utc).isoformat(),
              "environment": "REAL_LOCAL_SERVICES", "execution_state": "RUNNING",
              "scope": "canonical standalone ledger with PostgreSQL; not EDD product-value measurement",
              "checks": [], "commands": [], "results": {}}

    def record(name, ok, **evidence):
        report["checks"].append({"check": name, "passed": bool(ok), "evidence": evidence})
        if not ok:
            raise AssertionError(name)

    def command(argv, *, input_text=None):
        # All recorded argv are deliberately secret-free.
        result = subprocess.run(argv, input=input_text, text=True, capture_output=True)
        report["commands"].append({"argv": argv, "exit_code": result.returncode})
        return result

    def sql(statement):
        return command(["podman", "exec", "-i", db_name, "psql",
                        "-X", "-v", "ON_ERROR_STOP=1", "-U", "ledger", "-d", "ledger"],
                       input_text=statement)

    client = None
    try:
        for container in (db_name, service_name):
            result = command(["podman", "inspect", "--format", "{{.Id}} {{.Image}}", container])
            record(container + "_exists", result.returncode == 0, identity=result.stdout.strip())
        revision = command(["git", "-C", config["LEDGER_SOURCE_DIR"], "rev-parse", "HEAD"])
        report["source_revision"] = revision.stdout.strip()
        record("canonical_source_pinned", report["source_revision"] == "2679c9e0a5430cde9e435339e441a94989d2bcd6")
        await_ready(config)
        client = client_from_config(config)
        event = {"agent_id": "ledger-reference-agent", "attempt_id": run_id + "-attempt",
                 "correlation_id": run_id, "event_type": "connected_validation",
                 "outcome": "PASS", "authority_revision": 1, "purpose": "real-ledger-adapter-test"}
        key = run_id + "-idempotency"
        receipt = client.append(event, key)
        record("authenticated_signed_append_and_verify", client.verify(receipt, event),
               entry_id=receipt["entry_id"], entry_hash=receipt["entry_hash"], hash_version=receipt["hash_version"])
        record("duplicate_returns_same_receipt", client.append(event, key) == receipt)
        entries = client.sdk.query(entry_type=receipt["entry_type"], correlation_id=run_id)
        record("duplicate_does_not_append", len(entries) == 1, matching_entries=len(entries))
        rejected = False
        try:
            client.append({**event, "outcome": "FAIL"}, key)
        except LedgerError:
            rejected = True
        record("conflicting_idempotency_rejected", rejected)
        for field, value in (("attempt_id", "wrong-attempt"), ("authority_revision", 2), ("outcome", "FAIL")):
            record("changed_event_" + field + "_rejected", not client.verify(receipt, {**event, field: value}))
        record("changed_receipt_rejected", not client.verify({**receipt, "entry_hash": "0" * 64}, event))
        untrusted = client_from_config(config, trust=False)
        record("untrusted_writer_rejected", not untrusted.verify(receipt, event))
        untrusted.close()
        unauth = client_from_config(config, token="intentionally-incorrect-reference-token")
        rejected = False
        try:
            unauth.append(event, run_id + "-unauthorized")
        except LedgerError:
            rejected = True
        record("incorrect_api_token_cannot_write", rejected)
        unauth.sdk.metadata = None
        rejected = False
        try:
            unauth.append(event, run_id + "-missing-auth")
        except LedgerError:
            rejected = True
        record("missing_api_token_cannot_write", rejected)
        unauth.close()
        # This SQL uses a validated server-issued UUID inside our owned database.
        from uuid import UUID
        entry_id = str(UUID(receipt["entry_id"]))
        for operation in ("UPDATE are_ledger.ledger_entries SET content=content", "DELETE FROM are_ledger.ledger_entries"):
            result = sql("BEGIN; SET LOCAL ROLE ledger_app; " + operation +
                         " WHERE entry_id='" + entry_id + "'; ROLLBACK;")
            record("application_role_" + operation.split()[0].lower() + "_denied",
                   result.returncode != 0 and "permission denied" in result.stderr)
        record("app_denial_preserves_receipt", client.verify(receipt, event))
        if not args.skip_restart:
            client.close()
            client = None
            for name in (db_name, service_name):
                result = command(["podman", "restart", name])
                record(name + "_restart", result.returncode == 0)
            await_ready(config)
            client = client_from_config(config)
            record("receipt_survives_database_and_service_restart", client.verify(receipt, event))
            record("idempotency_survives_restart", client.append(event, key) == receipt)
        else:
            report["restart_validation"] = "NOT_RUN"
        # A privileged DBA can modify bytes; verify detection, then restore only
        # this owned test row. This is not a claim of externally anchored history.
        tamper_event = {**event, "event_type": "tamper_probe", "attempt_id": run_id + "-tamper"}
        tamper_receipt = client.append(tamper_event, run_id + "-tamper-key")
        tamper_id = str(UUID(tamper_receipt["entry_id"]))
        original = canonical_json(tamper_event).hex()
        altered = canonical_json({**tamper_event, "outcome": "FORGED"}).hex()
        try:
            result = sql("UPDATE are_ledger.ledger_entries SET content=decode('" + altered +
                         "','hex') WHERE entry_id='" + tamper_id + "';")
            record("owned_admin_tamper_injected", result.returncode == 0)
            record("stored_tamper_rejected_locally", not client.verify(tamper_receipt, tamper_event))
            proof = client.sdk.verify_proof(tamper_receipt["entry_hash"], tamper_receipt["entry_type"])
            record("stored_tamper_detected_by_canonical_server", not proof.valid, failure_reason=proof.failure_reason)
        finally:
            result = sql("UPDATE are_ledger.ledger_entries SET content=decode('" + original +
                         "','hex') WHERE entry_id='" + tamper_id + "';")
            record("owned_probe_restored", result.returncode == 0)
        record("restored_assertion_verifies", client.verify(tamper_receipt, tamper_event))
        chain = client.sdk.verify_chain(tamper_receipt["entry_type"])
        record("canonical_chain_verifies", chain.chain_valid, entries_checked=chain.entries_checked)
        report["results"] = {"event": event, "receipt": receipt, "tamper_receipt": tamper_receipt,
                             "durable_volume": instance + "-ledger-data"}
        report["execution_state"] = "COMPLETED"
        report["acceptance_color"] = "GREEN" if not args.skip_restart else "AMBER"
    except Exception as exc:
        report["execution_state"] = "ABORTED"
        report["acceptance_color"] = "RED"
        report["error"] = type(exc).__name__ + ": " + str(exc)
    finally:
        if client:
            client.close()
        report["finished_at"] = datetime.now(timezone.utc).isoformat()
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"report": str(args.report), "execution_state": report["execution_state"],
                      "acceptance_color": report["acceptance_color"], "checks": len(report["checks"])}))
    return 0 if report["execution_state"] == "COMPLETED" else 1


if __name__ == "__main__":
    raise SystemExit(main())
