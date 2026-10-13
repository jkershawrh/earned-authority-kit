#!/usr/bin/env python3
"""Real subprocess failures around durable canonical authority operations.

Faults are injected at named coordinator checkpoints or at an actual gRPC proxy.
The proxy forwards canonical bytes and metadata; it never fabricates authority.
"""
import argparse
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import time

from validate_connected import build_runtime, ROOT
from earned_authority.runtime import Denied, ident
from earned_authority.contracts import canonical_digest
from earned_authority.grants import iter_grants, grants_for_skill, unique_grant
from deploy.ledger.validate import read_config


def write_json(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    with temporary.open("w") as handle:
        json.dump(value, handle, indent=2)
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())
    temporary.replace(path)


def close_runtime(rt):
    if rt:
        rt.passport.close()
        rt.ledger.close()
        rt.close()


def source_hashes():
    tracked = [Path(__file__), ROOT / "tools/validate_connected.py"] + list((ROOT / "earned_authority").glob("*.py"))
    return {str(p.relative_to(ROOT)): "sha256:" + hashlib.sha256(p.read_bytes()).hexdigest() for p in tracked}


def child(args):
    job = json.loads(args.child_job.read_text())
    rt = build_runtime(args, Path(job["state"]))
    def checkpoint(stage, operation):
        write_json(job["checkpoint"], {"stage": stage, "operation_id": operation["operation_id"],
                                      "pid": os.getpid(), "time_ns": time.time_ns()})
        if stage == job.get("crash_stage"):
            os._exit(23)
        if stage == "remote_committed" and job.get("readonly_after_remote"):
            # SQLite itself rejects the next attempted journal/event write.
            rt._db = lambda: sqlite3.connect("file:" + str(Path(job["state"]).resolve()) + "?mode=ro", uri=True, timeout=5)
    rt.authority_checkpoint = checkpoint
    if job.get("local_durability_unavailable"):
        rt.local_durability_available = False
    try:
        action = job["action"]
        if action == "grant":
            rt.grant(job["qualification_id"], agent=job["agent"], action=job.get("scope_action", "release"), resource=job.get("resource", "model/champion"), operation_id=job["operation_id"])
        elif action == "revoke":
            rt.revoke(job["agent"], job.get("skill", "release-model"), reason="RECOVERY_VALIDATION", operation_id=job["operation_id"])
        elif action == "recover":
            rt.recover_authority_intents(job["agent"])
        elif action == "reevaluate":
            rt.reevaluate(job["agent"], "release-model", state="UNKNOWN")
        elif action == "drain":
            rt.drain_withdrawals()
        elif action == "flush":
            rt.flush_outbox()
        else:
            raise ValueError("Unknown child action")
        if job.get("flush"):
            rt.flush_outbox()
        write_json(job["result"], {"outcome": "RETURNED", "pid": os.getpid()})
        return 0
    except Exception as exc:
        write_json(job["result"], {"outcome": "RAISED", "pid": os.getpid(), "exception": type(exc).__name__,
                                   "reason": getattr(exc, "reason", str(exc))})
        if job.get("readonly_after_remote") and isinstance(exc, sqlite3.OperationalError) and "readonly" in str(exc).lower():
            return 24
        if job.get("local_durability_unavailable") and isinstance(exc, Denied) and exc.reason == "LOCAL_DURABILITY_UNAVAILABLE":
            return 25
        if job.get("allow_lost_response_hold") and isinstance(exc, (Denied, TimeoutError)):
            return 26
        raise
    finally:
        close_runtime(rt)


def proxy(args):
    """Discard the real Apply response after the upstream has committed it."""
    import grpc
    settings = json.loads(args.proxy_config.read_text())
    channel = grpc.insecure_channel(settings["upstream"])
    class Forward(grpc.GenericRpcHandler):
        def service(self, details):
            method = details.method
            def invoke(request, context):
                upstream = channel.unary_unary(method, request_serializer=lambda value: value, response_deserializer=lambda value: value)
                try:
                    response, call = upstream.with_call(request, metadata=context.invocation_metadata(), timeout=10)
                    if method.endswith("/ApplyPassportOperation"):
                        write_json(settings["dropped_reply"], {"method": method, "pid": os.getpid(), "upstream_committed_response_bytes": len(response), "time_ns": time.time_ns()})
                        context.abort(grpc.StatusCode.UNAVAILABLE, "injected response loss after real canonical commit")
                    context.send_initial_metadata(call.initial_metadata() or ())
                    context.set_trailing_metadata(call.trailing_metadata() or ())
                    return response
                except grpc.RpcError as exc:
                    context.set_trailing_metadata(exc.trailing_metadata() or ())
                    context.abort(exc.code(), exc.details())
            return grpc.unary_unary_rpc_method_handler(invoke, request_deserializer=lambda value: value, response_serializer=lambda value: value)
    server = grpc.server(ThreadPoolExecutor(max_workers=8))
    server.add_generic_rpc_handlers((Forward(),))
    port = server.add_insecure_port("127.0.0.1:0")
    server.start()
    write_json(settings["ready"], {"port": port, "pid": os.getpid()})
    try:
        server.wait_for_termination()
    finally:
        channel.close()


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--config", type=Path, required=True)
    p.add_argument("--ledger-config", type=Path, required=True)
    p.add_argument("--state-dir", type=Path, required=True)
    p.add_argument("--report", type=Path, default=ROOT / "reports/authority-recovery.json")
    p.add_argument("--child-job", type=Path)
    p.add_argument("--proxy-config", type=Path)
    p.add_argument("--verify-existing-report", type=Path)
    args = p.parse_args()
    if args.child_job:
        return child(args)
    if args.proxy_config:
        proxy(args)
        return 0
    if args.verify_existing_report:
        return verify_existing(args)
    return run(args)


def verify_existing(args):
    prior = json.loads(args.verify_existing_report.read_text())
    before_hashes = source_hashes()
    report = {"environment": "REAL_LOCAL_SERVICES", "started_at": datetime.now(timezone.utc).isoformat(),
              "prior_report": str(args.verify_existing_report), "checks": [],
              "scope": "Read back prior historical operation receipts, signed local journal/events and ledger receipts after service restart; does not issue replacement operations"}
    rt = None
    def check(name, ok, **evidence):
        report["checks"].append({"check": name, "passed": bool(ok), "evidence": evidence})
        if not ok: raise AssertionError(name)
    try:
        if prior.get("acceptance_color") != "GREEN" or prior.get("environment") != "REAL_LOCAL_SERVICES":
            raise ValueError("requires successful real recovery report")
        rt = build_runtime(args, Path(prior["state_path"]))
        operations = {o["operation_id"]: o for o in rt.authority_operations()}
        rows = {row["event"]["event_id"]: row for row in rt.events()}
        for expected in prior["authority_operation_snapshot"]:
            operation = operations.get(expected["operation_id"])
            receipt = rt.passport.operation(expected["agent_id"], expected["operation_id"], expected_request=operation["request"] if operation else None)
            check("historical_operation_survives_restart_" + expected["operation_id"],
                  operation is not None and operation["state"] == "APPLIED" and operation["event_id"] == expected["event_id"]
                  and canonical_digest(receipt) == expected["canonical_receipt_digest"])
        check("exact_prior_events_and_ledger_receipts_preserved", set(rows) == set(prior["event_snapshot"])
              and all(canonical_digest(rows[eid]["event"]) == saved["event_digest"]
                      and canonical_digest(rows[eid]["receipt"]) == saved["receipt_digest"]
                      and rt.ledger.verify(rows[eid]["receipt"], rows[eid]["event"])
                      for eid, saved in prior["event_snapshot"].items()), event_count=len(rows))
        report.update(execution_state="COMPLETED", acceptance_color="GREEN")
    except Exception as exc:
        report.update(execution_state="ABORTED", acceptance_color="RED", error=type(exc).__name__ + ": " + str(exc))
    finally:
        close_runtime(rt)
    report["source_hashes_before"] = before_hashes
    report["source_hashes"] = source_hashes()
    if before_hashes != report["source_hashes"]:
        report.update(execution_state="ABORTED", acceptance_color="AMBER", error="SOURCE_CHANGED_DURING_RUN")
    report["finished_at"] = datetime.now(timezone.utc).isoformat()
    write_json(args.report, report)
    print(json.dumps({"report": str(args.report), "status": report["acceptance_color"], "checks": len(report["checks"])}))
    return 0 if report["execution_state"] == "COMPLETED" else 1


def run(args):
    args.state_dir.mkdir(parents=True, exist_ok=True)
    run_id = ident("authority-recovery")
    state = args.state_dir / (run_id + ".sqlite")
    before_hashes = source_hashes()
    report = {"run_id": run_id, "environment": "REAL_LOCAL_SERVICES", "started_at": datetime.now(timezone.utc).isoformat(),
              "scope": "Real canonical authority and ledger; separate coordinator processes, explicit os._exit checkpoints, actual forwarding-proxy response loss and SQLite read-only write rejection. Bounded recovery tests, not universal distributed safety.",
              "checks": [], "child_processes": [], "state_path": str(state.resolve())}
    rt = None
    proxy_process = None
    proxy_log = None
    sequence = 0
    def check(name, passed, **evidence):
        report["checks"].append({"check": name, "passed": bool(passed), "evidence": evidence})
        if not passed:
            raise AssertionError(name)
    def events(agent, operation_id=None):
        return [row for row in rt.events() if row["event"]["agent_id"] == agent and
                (operation_id is None or row["event"].get("authority_operation_id") == operation_id)]
    def journal(agent, operation_id):
        matches = [row for row in rt.authority_operations(agent) if row["operation_id"] == operation_id]
        if len(matches) != 1:
            raise AssertionError("expected exactly one durable authority intent")
        return matches[0]
    def execute(job, *, expected_exit=0, config=None):
        nonlocal sequence
        sequence += 1
        stem = args.state_dir / (run_id + "-child-" + str(sequence))
        full = {"state": str(state.resolve()), "checkpoint": str(stem.with_suffix(".checkpoint.json").resolve()),
                "result": str(stem.with_suffix(".result.json").resolve()), **job}
        job_path = stem.with_suffix(".job.json")
        write_json(job_path, full)
        argv = [sys.executable, str(Path(__file__).resolve()), "--config", str((config or args.config).resolve()),
                "--ledger-config", str(args.ledger_config.resolve()), "--state-dir", str(args.state_dir.resolve()),
                "--child-job", str(job_path.resolve())]
        with stem.with_suffix(".log").open("w") as log:
            result = subprocess.run(argv, stdout=log, stderr=subprocess.STDOUT, timeout=60)
        checkpoint_path = Path(full["checkpoint"])
        checkpoint = json.loads(checkpoint_path.read_text()) if checkpoint_path.exists() else None
        result_path = Path(full["result"])
        outcome = json.loads(result_path.read_text()) if result_path.exists() else None
        report["child_processes"].append({"sequence": sequence, "action": full["action"], "expected_exit_code": expected_exit,
                "exit_code": result.returncode, "checkpoint": checkpoint, "outcome": outcome, "log": str(stem.with_suffix(".log"))})
        accepted = expected_exit if isinstance(expected_exit, (tuple, list)) else (expected_exit,)
        if result.returncode not in accepted:
            raise AssertionError("child " + str(sequence) + " exit " + str(result.returncode) + "; inspect retained child log")
        if full.get("crash_stage") and (not checkpoint or checkpoint["stage"] != full["crash_stage"]):
            raise AssertionError("child failed to reach its named durable boundary")
        return full
    def prepare(label, *, release=False, read=False):
        agent = rt.policy.request("/v1/identity/agents", {"agent_type": "earned-authority.recovery-" + label,
                                                         "owner_id": "reference-operator"})["agent"]["agent_id"]
        context = {"environment": label + "-" + run_id, "model_version": "model-" + label, "desired_replicas": 1, "max_replicas": 2}
        def qualification(skill):
            for _ in range(3):
                rt.shadow(skill=skill, context=context)
            q = rt.qualify(skill=skill, context=context)
            if q["disposition"] != "ELIGIBLE":
                raise AssertionError("canonical qualification rejected recovery test setup")
            return q
        q = qualification("release-model")
        if release:
            rt.grant(q["qualification_id"], agent=agent)
        if read:
            read_q = qualification("read-health")
            rt.grant(read_q["qualification_id"], agent=agent, action="read", resource="urn:dataset/health")
        return agent, q, context, rt.authority(agent)
    def settled_once(agent, operation_id, expected_revision, event_type):
        op = journal(agent, operation_id)
        matching = events(agent, operation_id)
        check(event_type.lower() + "_recovered_exactly_once_" + operation_id,
              op["state"] == "APPLIED" and len(matching) == 1 and matching[0]["event"]["event_id"] == op["event_id"]
              and matching[0]["event"]["event_type"] == event_type and matching[0]["event"]["authority_revision"] == expected_revision,
              operation_id=operation_id, authority_revision=expected_revision)
        before = (rt.authority(agent)["revision"], [row["event"]["event_id"] for row in events(agent)])
        execute({"action": "recover", "agent": agent, "flush": True})
        after = (rt.authority(agent)["revision"], [row["event"]["event_id"] for row in events(agent)])
        check("repeat_reconciliation_changes_no_revision_or_event_" + operation_id, before == after)
        return op
    try:
        rt = build_runtime(args, state)
        for method in ("recover_authority_intents", "authority_operations"):
            if not callable(getattr(rt, method, None)):
                raise RuntimeError("Required durable authority API not implemented: " + method)

        agent, q, _, before = prepare("intent-before-rpc")
        opid = ident("operation")
        job = {"action": "grant", "agent": agent, "qualification_id": q["qualification_id"], "operation_id": opid}
        execute({**job, "crash_stage": "intent_committed"}, expected_exit=23)
        check("intent_is_durable_before_any_remote_mutation", journal(agent, opid)["state"] == "PREPARED"
              and rt.authority(agent)["revision"] == before["revision"] and not events(agent, opid))
        execute({"action": "recover", "agent": agent})
        settled_once(agent, opid, before["revision"] + 1, "GRANTED")
        revision = rt.authority(agent)["revision"]
        execute(job)
        check("caller_retry_reuses_exact_operation", rt.authority(agent)["revision"] == revision and len(events(agent, opid)) == 1)

        agent, q, _, before = prepare("dispatch-before-rpc")
        opid = ident("operation")
        execute({"action": "grant", "agent": agent, "qualification_id": q["qualification_id"], "operation_id": opid,
                 "crash_stage": "dispatch_committed"}, expected_exit=23)
        check("dispatch_marker_survives_exit_before_rpc", journal(agent, opid)["state"] == "DISPATCHED"
              and rt.authority(agent)["revision"] == before["revision"] and not events(agent, opid))
        execute({"action": "recover", "agent": agent})
        settled_once(agent, opid, before["revision"] + 1, "GRANTED")

        agent, q, _, before = prepare("issue-before-local-event", read=True)
        opid = ident("operation")
        execute({"action": "grant", "agent": agent, "qualification_id": q["qualification_id"], "operation_id": opid,
                 "crash_stage": "remote_committed"}, expected_exit=23)
        committed = rt.authority(agent)
        check("remote_issue_survives_coordinator_exit_without_local_event", committed["revision"] == before["revision"] + 1
              and bool(grants_for_skill(committed, "release-model")) and not events(agent, opid)
              and rt.passport.operation(agent, opid) is not None)
        execute({"action": "recover", "agent": agent})
        settled_once(agent, opid, committed["revision"], "GRANTED")
        check("issue_recovery_preserves_unaffected_grant", unique_grant(rt.authority(agent), "read-health")["grant_id"] == unique_grant(before, "read-health")["grant_id"])

        agent, q, _, before = prepare("event-commit")
        opid = ident("operation")
        execute({"action": "grant", "agent": agent, "qualification_id": q["qualification_id"], "operation_id": opid,
                 "crash_stage": "event_committed"}, expected_exit=23)
        check("event_and_applied_marker_are_atomic", journal(agent, opid)["state"] == "APPLIED" and len(events(agent, opid)) == 1)
        settled_once(agent, opid, before["revision"] + 1, "GRANTED")

        for selective in (False, True):
            agent, q, _, before = prepare("selective-revoke" if selective else "empty-revoke", release=True, read=selective)
            opid = ident("operation")
            execute({"action": "revoke", "agent": agent, "operation_id": opid, "crash_stage": "remote_committed"}, expected_exit=23)
            committed = rt.authority(agent)
            check("canonical_revoke_committed_before_local_event_" + str(selective), committed["revision"] == before["revision"] + 1
                  and not grants_for_skill(committed, "release-model") and not events(agent, opid)
                  and rt.passport.operation(agent, opid) is not None)
            execute({"action": "recover", "agent": agent})
            settled_once(agent, opid, committed["revision"], "REVOKED")
            check("selective_or_empty_aggregate_survives_recovery_" + str(selective),
                  (unique_grant(committed, "read-health")["grant_id"] == unique_grant(before, "read-health")["grant_id"]
                   if selective else not grants_for_skill(committed, "read-health") and not rt.authority(agent)["grants"]))

        agent, q, _, before = prepare("withdrawal-queue-ack", release=True, read=True)
        crashed = execute({"action": "reevaluate", "agent": agent, "crash_stage": "withdrawal_completed"}, expected_exit=23)
        checkpoint = json.loads(Path(crashed["checkpoint"]).read_text())
        opid = checkpoint["operation_id"]
        committed = rt.authority(agent)
        with rt._db() as db:
            pending = db.execute("SELECT COUNT(*) FROM withdrawal_causes WHERE agent=?", (agent,)).fetchone()[0]
        check("withdrawal_ack_survives_exit_before_queue_delete", pending == 1 and journal(agent, opid)["state"] == "APPLIED"
              and committed["revision"] == before["revision"] + 1 and not grants_for_skill(committed, "release-model"))
        event_ids = [row["event"]["event_id"] for row in events(agent)]
        execute({"action": "drain", "agent": agent})
        with rt._db() as db:
            pending = db.execute("SELECT COUNT(*) FROM withdrawal_causes WHERE agent=?", (agent,)).fetchone()[0]
        check("restart_clears_acknowledged_withdrawal_without_second_revision_or_event", pending == 0
              and rt.authority(agent)["revision"] == committed["revision"]
              and [row["event"]["event_id"] for row in events(agent)] == event_ids
              and unique_grant(rt.authority(agent), "read-health")["grant_id"] == unique_grant(before, "read-health")["grant_id"])
        settled_once(agent, opid, committed["revision"], "REVOKED")

        agent, q, _, before = prepare("historical-issue", read=True)
        opid = ident("operation")
        execute({"action": "grant", "agent": agent, "qualification_id": q["qualification_id"], "operation_id": opid,
                 "crash_stage": "remote_committed"}, expected_exit=23)
        prior_revision = rt.authority(agent)["revision"]
        current = rt.passport.current(agent, require_valid=False)
        rt.passport.issue(agent, rt._requests(list(iter_grants(before))), 300, current, "later independent canonical replacement", operation_id=ident("replacement"))
        replacement_revision = rt.authority(agent)["revision"]
        execute({"action": "recover", "agent": agent})
        settled_once(agent, opid, prior_revision, "GRANTED")
        check("historical_issue_proof_never_restores_superseded_authority", replacement_revision == prior_revision + 1
              and rt.authority(agent)["revision"] == replacement_revision and not grants_for_skill(rt.authority(agent), "release-model"))

        agent, q, _, before = prepare("historical-revoke", release=True, read=True)
        opid = ident("operation")
        execute({"action": "revoke", "agent": agent, "operation_id": opid, "crash_stage": "remote_committed"}, expected_exit=23)
        prior_revision = rt.authority(agent)["revision"]
        replacement_grants = json.loads(json.dumps(list(iter_grants(before))))
        replacement_release = unique_grant({"grants": replacement_grants}, "release-model")
        replacement_release["grant_id"] = ident("replacement-grant")
        current = rt.passport.current(agent, require_valid=False)
        rt.passport.issue(agent, rt._requests(replacement_grants), 300, current, "later replacement after old withdrawal", operation_id=ident("replacement"))
        replacement_revision = rt.authority(agent)["revision"]
        execute({"action": "recover", "agent": agent})
        settled_once(agent, opid, prior_revision, "REVOKED")
        check("historical_revoke_never_withdraws_later_replacement", rt.authority(agent)["revision"] == replacement_revision
              and unique_grant(rt.authority(agent), "release-model")["grant_id"] == replacement_release["grant_id"]
              and unique_grant(rt.authority(agent), "read-health")["grant_id"] == unique_grant(before, "read-health")["grant_id"])

        agent, q, _, before = prepare("local-durability")
        opid = ident("operation")
        execute({"action": "grant", "agent": agent, "qualification_id": q["qualification_id"], "operation_id": opid,
                 "local_durability_unavailable": True}, expected_exit=25)
        check("unavailable_local_durability_prevents_remote_mutation", rt.authority(agent)["revision"] == before["revision"]
              and not [o for o in rt.authority_operations(agent) if o["operation_id"] == opid] and not events(agent, opid))
        opid = ident("operation")
        execute({"action": "grant", "agent": agent, "qualification_id": q["qualification_id"], "operation_id": opid,
                 "readonly_after_remote": True}, expected_exit=24)
        check("actual_sqlite_write_failure_leaves_remote_commit_recoverable", rt.authority(agent)["revision"] == before["revision"] + 1
              and journal(agent, opid)["state"] != "APPLIED" and not events(agent, opid))
        execute({"action": "recover", "agent": agent})
        settled_once(agent, opid, before["revision"] + 1, "GRANTED")

        # A distinct forwarding process drops only committed Apply replies.
        values = read_config(args.config)
        proxy_settings = {"upstream": "127.0.0.1:" + values["ARE_PASSPORT_GRPC_PORT"],
                          "ready": str((args.state_dir / (run_id + "-proxy-ready.json")).resolve()),
                          "dropped_reply": str((args.state_dir / (run_id + "-dropped-reply.json")).resolve())}
        proxy_config = args.state_dir / (run_id + "-proxy.json")
        write_json(proxy_config, proxy_settings)
        argv = [sys.executable, str(Path(__file__).resolve()), "--config", str(args.config.resolve()),
                "--ledger-config", str(args.ledger_config.resolve()), "--state-dir", str(args.state_dir.resolve()), "--proxy-config", str(proxy_config.resolve())]
        proxy_log = (args.state_dir / (run_id + "-proxy.log")).open("w")
        proxy_process = subprocess.Popen(argv, stdout=proxy_log, stderr=subprocess.STDOUT)
        deadline = time.monotonic() + 10
        while not Path(proxy_settings["ready"]).exists() and time.monotonic() < deadline and proxy_process.poll() is None:
            time.sleep(0.05)
        if not Path(proxy_settings["ready"]).exists():
            raise AssertionError("real forwarding proxy failed to start")
        ready = json.loads(Path(proxy_settings["ready"]).read_text())
        values["ARE_PASSPORT_GRPC_PORT"] = str(ready["port"])
        proxy_env = args.state_dir / (run_id + "-private-proxy.env")
        proxy_env.write_text("".join(f"{k}={v}\n" for k, v in values.items()))
        proxy_env.chmod(0o600)
        agent, q, _, before = prepare("lost-response")
        opid = ident("operation")
        execute({"action": "grant", "agent": agent, "qualification_id": q["qualification_id"], "operation_id": opid,
                 "allow_lost_response_hold": True}, config=proxy_env, expected_exit=(0, 26))
        check("actual_network_reply_loss_is_observed_after_canonical_commit", Path(proxy_settings["dropped_reply"]).exists()
              and rt.authority(agent)["revision"] == before["revision"] + 1)
        execute({"action": "recover", "agent": agent})
        settled_once(agent, opid, before["revision"] + 1, "GRANTED")

        execute({"action": "flush", "agent": agent})
        rows = rt.events()
        check("restart_outbox_records_each_authority_event_once", all(row["delivery"] == "RECORDED" and rt.ledger.verify(row["receipt"], row["event"]) for row in rows), event_count=len(rows))
        check("authority_recovery_never_mutates_model_registry", rt.mutation_count == 0)
        report["authority_operation_snapshot"] = []
        for operation in rt.authority_operations():
            if operation["state"] != "APPLIED":
                raise AssertionError("unsettled journal remains after successful scenarios")
            receipt = rt.passport.operation(operation["agent_id"], operation["operation_id"], expected_request=operation["request"])
            if receipt is None:
                raise AssertionError("applied journal lacks independently verified canonical receipt")
            report["authority_operation_snapshot"].append({"operation_id": operation["operation_id"], "agent_id": operation["agent_id"],
                "event_id": operation["event_id"], "canonical_receipt_digest": canonical_digest(receipt)})
        report["event_snapshot"] = {row["event"]["event_id"]: {"event_digest": canonical_digest(row["event"]),
                                                               "receipt_digest": canonical_digest(row["receipt"])} for row in rows}
        report.update(execution_state="COMPLETED", acceptance_color="GREEN", mutation_count=rt.mutation_count)
    except Exception as exc:
        import traceback
        report.update(execution_state="ABORTED", acceptance_color="RED", error=type(exc).__name__ + ": " + str(exc), traceback=traceback.format_exc())
    finally:
        if proxy_process:
            proxy_process.terminate()
            try:
                proxy_process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proxy_process.kill()
                proxy_process.wait(timeout=5)
        if proxy_log:
            proxy_log.close()
        close_runtime(rt)
    report["finished_at"] = datetime.now(timezone.utc).isoformat()
    report["source_hashes_before"] = before_hashes
    report["source_hashes"] = source_hashes()
    if before_hashes != report["source_hashes"]:
        report.update(execution_state="ABORTED", acceptance_color="AMBER", error="SOURCE_CHANGED_DURING_RUN")
    write_json(args.report, report)
    print(json.dumps({"report": str(args.report), "status": report["acceptance_color"], "checks": len(report["checks"]), "error": report.get("error")}))
    return 0 if report["execution_state"] == "COMPLETED" else 1


if __name__ == "__main__":
    raise SystemExit(main())
