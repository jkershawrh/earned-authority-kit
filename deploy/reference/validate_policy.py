"""Live checks for immutable local OPA and same-snapshot decision binding."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen
from uuid import uuid4

HERE = Path(__file__).resolve().parent
KIT = HERE.parents[1]
TASK = Path(os.environ.get("EA_WORKSPACE", str(KIT.parents[1]))).resolve()


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--report", type=Path, default=KIT / "reports/opa-network-administration-denied.json")
    args = p.parse_args()
    values = dict(line.split("=", 1) for line in (TASK / "work/reference-runtime/reference.env").read_text().splitlines() if "=" in line)
    base = values["ARE_OPA_BASE_URL"]
    report = {"environment": "REAL_LOCAL_SERVICES", "started_at": datetime.now(timezone.utc).isoformat(), "checks": [],
              "limit": "Immutable loaded local policy with trusted host/container administrators; not a general distributed atomic policy guarantee"}
    def check(name, passed, **evidence):
        report["checks"].append({"check": name, "passed": bool(passed), "evidence": evidence})
        if not passed: raise AssertionError(name)
    try:
        with urlopen(base + "/v1/policies", timeout=3) as response:
            policies = {p["id"]: "sha256:" + hashlib.sha256(p["raw"].encode()).hexdigest() for p in json.load(response)["result"]}
        expected = {values["ARE_OPA_POLICY_ID"]: values["ARE_OPA_POLICY_DIGEST"], values["ARE_OPA_AUTHZ_POLICY_ID"]: values["ARE_OPA_AUTHZ_POLICY_DIGEST"]}
        check("exact_loaded_module_set_and_digests", policies == expected, modules=policies)
        for method, path, payload in (("PUT", "/v1/policies/forbidden-probe", "package forbidden\nallow = true"),
             ("DELETE", "/v1/policies/forbidden-probe", None), ("PUT", "/v1/data/forbidden-probe", '{"allow":true}'),
             ("PATCH", "/v1/data/forbidden-probe", "[]"), ("POST", "/v1/query", '{"query":"true"}'),
             ("POST", "/v1/compile", '{"query":"true"}')):
            request = Request(base + path, method=method, data=None if payload is None else payload.encode(), headers={"Content-Type": "application/json"})
            try:
                with urlopen(request, timeout=3) as response: status = response.status
            except HTTPError as exc: status = exc.code
            check("deny_" + method + "_" + path, status in (401, 403), http_status=status)
        fields = {"decision_id": "probe-" + str(uuid4()), "agent_id": "reference-probe", "action_class": "model.promote_to_production", "resource": "model/champion"}
        request = Request(base + "/v1/data/are/evaluatepolicy/decision", data=json.dumps({"input": {**fields, "policy_digest": "untrusted-caller"}}).encode(), headers={"Content-Type": "application/json"})
        with urlopen(request, timeout=3) as response: decision = json.load(response)["result"]
        binding = {**fields, "policy_id": values["ARE_OPA_POLICY_ID"], "policy_digest": values["ARE_OPA_POLICY_DIGEST"]}
        check("decision_echoes_inputs_and_same_snapshot_binding", all(decision.get(k) == v for k, v in binding.items()) and decision.get("effect") == "ALLOW")
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
