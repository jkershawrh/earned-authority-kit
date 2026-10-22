#!/usr/bin/env python3
"""Restore copied Passport state, registry SQLite, and the Ledger volume on one host."""
import argparse
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
from types import SimpleNamespace
from evidence import bind_sources, source_hashes

HERE = Path(__file__).resolve().parent
KIT = HERE.parents[1]
TASK = Path(os.environ.get("EA_WORKSPACE", str(KIT.parents[1]))).resolve()


def config(path):
    return dict(line.split("=", 1) for line in path.read_text().splitlines() if line and not line.startswith("#"))


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def copy_sqlite(source, destination):
    destination.parent.mkdir(parents=True, exist_ok=True)
    for suffix in ("", "-wal", "-shm"):
        item = Path(str(source) + suffix)
        target = Path(str(destination) + suffix)
        if item.is_file():
            shutil.copy2(item, target)
        elif target.exists():
            target.unlink()


def main():
    before_hashes = source_hashes()
    parser = argparse.ArgumentParser()
    parser.add_argument("--registry", type=Path, required=True)
    parser.add_argument("--backup-dir", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    runtime = TASK / "work/reference-runtime"
    ledger_env = TASK / "work/ledger-runtime/local.env"
    values = config(runtime / "reference.env")
    ledger = config(ledger_env)
    state_path = Path(values["ARE_PASSPORT_STATE_PATH"])
    volume = ledger.get("LEDGER_INSTANCE", "earned-authority") + "-ledger-data"
    instance = ledger.get("LEDGER_INSTANCE", "earned-authority")
    venv = TASK / "work/ledger-venv/bin/podman-compose"
    compose = [str(venv), "-p", instance + "-ledger", "--env-file", str(ledger_env), "-f", str(KIT / "deploy/ledger/compose.yaml")]
    spec = importlib.util.spec_from_file_location("connected_validation", KIT / "tools/validate_connected.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    settings = SimpleNamespace(config=runtime / "reference.env", ledger_config=ledger_env)
    report = {"environment": "REAL_LOCAL_SERVICES", "started_at": datetime.now(timezone.utc).isoformat(),
              "registry": str(args.registry), "passport_state": str(state_path), "ledger_volume": volume, "checks": [],
              "scope": "Same-host copy restore of Passport state, the registry SQLite file, and the Ledger volume. Installer keys stay in place. This is not corrupted-disk repair, a second host, or hostile rollback protection.",
              "limits": ["Not filesystem or disk repair", "Not a different host", "Foundation identity volume is left as retained container state"]}

    def check(name, passed, **evidence):
        report["checks"].append({"check": name, "passed": bool(passed), "evidence": evidence})
        if not passed:
            raise AssertionError(name)

    def snapshot():
        rt = module.build_runtime(settings, args.registry)
        try:
            events = rt.events()
            verified = [rt.ledger.verify(row["receipt"], row["event"]) for row in events if row["receipt"]]
            operations = rt.authority_operations()
            return {"events": len(events), "verified": len(verified), "all_verified": bool(verified) and all(verified),
                    "applied": sum(item["state"] == "APPLIED" for item in operations), "mutations": rt.mutation_count}
        finally:
            rt.passport.close(); rt.ledger.close(); rt.close()

    def reference(command):
        subprocess.run([sys.executable, str(HERE / "reference.py"), command], check=True, env={**os.environ, "EA_WORKSPACE": str(TASK)})

    backup = args.backup_dir
    archive = backup / "ledger-volume.tar"
    clobbered = False
    volume_removed = False
    try:
        before = snapshot()
        check("pre_restore_historical_receipts_verify", before["events"] > 0 and before["all_verified"] and before["applied"] > 0, **before)
        reference("stop")
        if backup.exists():
            shutil.rmtree(backup)
        backup.mkdir(parents=True, mode=0o700)
        shutil.copy2(state_path, backup / "passport-state.json")
        copy_sqlite(args.registry, backup / "registry.sqlite")
        subprocess.run(["podman", "volume", "export", volume, "--output", str(archive)], check=True)
        original_state = digest(backup / "passport-state.json")
        state_path.write_text('{"clobber":true}\n')
        args.registry.write_bytes(b"")
        for suffix in ("-wal", "-shm"):
            extra = Path(str(args.registry) + suffix)
            if extra.exists():
                extra.unlink()
        clobbered = True
        check("live_copy_differs_from_backup", digest(state_path) != original_state and args.registry.stat().st_size == 0)
        subprocess.run([*compose, "down"], check=True)
        subprocess.run(["podman", "volume", "rm", volume], check=True)
        subprocess.run(["podman", "volume", "create", volume], check=True)
        volume_removed = True
        shutil.copy2(backup / "passport-state.json", state_path)
        copy_sqlite(backup / "registry.sqlite", args.registry)
        clobbered = False
        subprocess.run(["podman", "volume", "import", volume, str(archive)], check=True)
        volume_removed = False
        check("restored_files_match_backup", digest(state_path) == original_state and digest(args.registry) == digest(backup / "registry.sqlite"))
        reference("restore")
        after = snapshot()
        check("historical_receipts_reread_and_verify", after == before, before=before, after=after)
        report.update(execution_state="COMPLETED", acceptance_color="GREEN")
    except Exception as exc:
        report.update(execution_state="ABORTED", acceptance_color="RED", error=type(exc).__name__ + ": " + str(exc))
        if volume_removed and archive.is_file():
            subprocess.run(["podman", "volume", "create", volume], check=False)
            subprocess.run(["podman", "volume", "import", volume, str(archive)], check=False)
        if clobbered and (backup / "passport-state.json").is_file():
            shutil.copy2(backup / "passport-state.json", state_path)
            copy_sqlite(backup / "registry.sqlite", args.registry)
        subprocess.run([sys.executable, str(HERE / "reference.py"), "restore"], check=False, env={**os.environ, "EA_WORKSPACE": str(TASK)})
    bind_sources(report, before_hashes)
    report["finished_at"] = datetime.now(timezone.utc).isoformat()
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"report": str(args.report), "status": report["acceptance_color"], "checks": len(report["checks"])}))
    return 0 if report.get("execution_state") == "COMPLETED" else 1


if __name__ == "__main__":
    raise SystemExit(main())
