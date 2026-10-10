"""Restart the owned real stack and verify its earlier authority and evidence."""
import argparse
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace

HERE = Path(__file__).resolve().parent
KIT = HERE.parents[1]
TASK = Path(os.environ.get("EA_WORKSPACE", str(KIT.parents[1]))).resolve()


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--prior-report", type=Path, required=True)
    p.add_argument("--report", type=Path, required=True)
    args = p.parse_args()
    prior = json.loads(args.prior_report.read_text())
    if prior.get("acceptance_color") != "GREEN" or prior.get("environment") != "REAL_LOCAL_SERVICES":
        raise SystemExit("Requires an actual successful connected run")
    runtime_dir = TASK / "work/reference-runtime"
    spec = importlib.util.spec_from_file_location("connected_validation", KIT / "tools/validate_connected.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    settings = SimpleNamespace(config=runtime_dir / "reference.env", ledger_config=TASK / "work/ledger-runtime/local.env")
    state = Path(prior["state_path"])
    agent = prior["agent_id"]
    report = {"environment": "REAL_LOCAL_SERVICES", "started_at": datetime.now(timezone.utc).isoformat(),
              "prior_report": str(args.prior_report), "agent_id": agent, "checks": [],
              "scope": "Same-host full process/container restart with durable volumes and installer-managed keys retained; not backup disaster recovery or second-person acceptance"}
    def check(name, passed, **evidence):
        report["checks"].append({"check": name, "passed": bool(passed), "evidence": evidence})
        if not passed:
            raise AssertionError(name)
    def snapshot():
        rt = module.build_runtime(settings, state)
        try:
            identity = rt.policy.request("/v1/identity/agents/" + agent)
            authority = rt.authority(agent)
            events = rt.events()
            verified = [rt.ledger.verify(row["receipt"], row["event"]) for row in events]
            return {"identity": identity, "authority": authority, "mutations": rt.mutation_count,
                    "events": events, "all_verified": all(verified), "count": len(events)}
        finally:
            rt.passport.close(); rt.ledger.close(); rt.close()
    try:
        before = snapshot()
        check("pre_restart_all_receipts_verify", before["count"] > 0 and before["all_verified"], count=before["count"])
        values = module.read_config(settings.config)
        key_paths = [Path(values["ARE_PASSPORT_KEY_PATH"]), Path(values["ARE_PASSPORT_PUBLIC_KEY_PATH"])]
        key_hashes = [hashlib.sha256(path.read_bytes()).hexdigest() for path in key_paths]
        for action in ("stop", "restore"):
            subprocess.run([sys.executable, HERE / "reference.py", action], check=True)
        after = snapshot()
        check("passport_signer_preserved", key_hashes == [hashlib.sha256(path.read_bytes()).hexdigest() for path in key_paths])
        check("foundation_identity_preserved", before["identity"] == after["identity"])
        check("passport_authority_revision_scopes_preserved", before["authority"] == after["authority"])
        check("registry_mutations_preserved", before["mutations"] == after["mutations"], mutation_count=after["mutations"])
        check("ledger_receipts_preserved_and_verify", before["events"] == after["events"] and after["all_verified"], event_count=after["count"])
        report.update(execution_state="COMPLETED", acceptance_color="GREEN")
    except Exception as exc:
        report.update(execution_state="ABORTED", acceptance_color="RED", error=type(exc).__name__ + ": " + str(exc))
    report["finished_at"] = datetime.now(timezone.utc).isoformat()
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"report": str(args.report), "status": report["acceptance_color"], "checks": len(report["checks"])}))
    return 0 if report["execution_state"] == "COMPLETED" else 1


if __name__ == "__main__":
    raise SystemExit(main())
