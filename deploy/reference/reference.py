"""Owned local reference lifecycle; secrets stay in private runtime files."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time
from urllib.request import Request, urlopen
from uuid import uuid4

HERE = Path(__file__).resolve().parent
KIT = HERE.parents[1]
TASK = Path(os.environ.get("EA_WORKSPACE", str(KIT.parents[1]))).resolve()
RUNTIME = TASK / "work/reference-runtime"
ENV_FILE = RUNTIME / "reference.env"
LEDGER_ENV = TASK / "work/ledger-runtime/local.env"
VENV = TASK / "work/ledger-venv"
PID_FILE = RUNTIME / "passport-process.json"


def passport_binary():
    return Path(config()["PASSPORT_SOURCE_DIR"]) / "bin/agent-passport"


def config(path=ENV_FILE):
    return dict(line.split("=", 1) for line in path.read_text().splitlines() if line and not line.startswith("#"))


def run(argv, log_name):
    RUNTIME.mkdir(parents=True, exist_ok=True)
    with (RUNTIME / log_name).open("a") as log:
        subprocess.run([str(x) for x in argv], check=True, stdout=log, stderr=subprocess.STDOUT)


def compose(component, *args):
    env_file = LEDGER_ENV if component == "ledger" else ENV_FILE
    compose_file = KIT / "deploy" / component / "compose.yaml"
    instance_key = "LEDGER_INSTANCE" if component == "ledger" else "REFERENCE_INSTANCE"
    instance = config(env_file).get(instance_key, "earned-authority")
    run([VENV / "bin/podman-compose", "-p", instance + "-" + component, "--env-file", env_file, "-f", compose_file, *args], component + "-compose.log")


def wait_http(url, timeout=90):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with urlopen(url, timeout=2) as response:
                if response.status == 200:
                    return
        except Exception:
            pass
        time.sleep(0.5)
    raise RuntimeError("service did not become ready: " + url)


def passport_running():
    if not PID_FILE.exists():
        return False
    saved = json.loads(PID_FILE.read_text())
    result = subprocess.run(["ps", "-p", str(saved["pid"]), "-o", "command="], capture_output=True, text=True)
    return result.returncode == 0 and result.stdout.strip() == str(passport_binary())


def start_passport():
    if passport_running():
        export_passport_public_key()
        return
    env = {**os.environ, **config()}
    with (RUNTIME / "passport.log").open("ab") as log:
        proc = subprocess.Popen([str(passport_binary())], env=env, stdout=log, stderr=subprocess.STDOUT,
                                start_new_session=True)
    PID_FILE.write_text(json.dumps({"pid": proc.pid, "binary": str(passport_binary()),
                                   "started_at": datetime.now(timezone.utc).isoformat()}) + "\n")
    wait_http("http://127.0.0.1:" + config()["ARE_PASSPORT_HEALTH_PORT"] + "/readyz")
    export_passport_public_key()


def export_passport_public_key():
    from cryptography.hazmat.primitives import serialization
    values = config()
    private = serialization.load_pem_private_key(Path(values["ARE_PASSPORT_KEY_PATH"]).read_bytes(), password=None)
    Path(values["ARE_PASSPORT_PUBLIC_KEY_PATH"]).write_bytes(private.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))


def stop_passport():
    if passport_running():
        saved = json.loads(PID_FILE.read_text())
        os.kill(saved["pid"], signal.SIGTERM)
        deadline = time.monotonic() + 15
        while passport_running() and time.monotonic() < deadline:
            time.sleep(0.2)
        if passport_running():
            raise RuntimeError("owned Passport process did not stop gracefully; no force kill attempted")


def foundation_request(method, path, payload=None, *, idem=None):
    values = config()
    request = Request(values["ARE_FOUNDATION_BASE_URL"] + path,
                      data=None if payload is None else json.dumps(payload).encode(), method=method)
    for name, value in {"Authorization": "Bearer " + values["ARE_FOUNDATION_TOKEN"],
                        "X-Request-ID": "reference-" + str(uuid4()),
                        "X-ARE-Agent-ID": "earned-authority-operator"}.items():
        request.add_header(name, value)
    if payload is not None:
        request.add_header("Content-Type", "application/json")
        request.add_header("Idempotency-Key", idem or str(uuid4()))
    with urlopen(request, timeout=15) as response:
        return json.loads(response.read())


def validate_services(report_path):
    run_id = "reference-service-" + str(uuid4())
    checks = []
    def check(name, passed, **evidence):
        checks.append({"check": name, "passed": bool(passed), "evidence": evidence})
        if not passed:
            raise AssertionError(name)
    report = {"run_id": run_id, "environment": "REAL_LOCAL_SERVICES", "checks": checks,
              "started_at": datetime.now(timezone.utc).isoformat(),
              "scope": "Foundation real JWT, PostgreSQL identity, OPA, and canonical Passport health; connected lifecycle validated separately"}
    try:
        wait_http("http://127.0.0.1:" + config().get("FOUNDATION_BFF_HEALTH_PORT", "29599") + "/health")
        wait_http("http://127.0.0.1:" + config()["ARE_PASSPORT_HEALTH_PORT"] + "/readyz")
        check("canonical_passport_healthy", passport_running())
        agent = foundation_request("POST", "/v1/identity/agents",
                {"agent_type": "earned-authority.registry-procedure", "owner_id": "reference-operator"}, idem=run_id)
        agent_id = agent["agent"]["agent_id"]
        check("foundation_registers_active_agent", agent["agent"]["status"] == "ACTIVE", agent_id=agent_id)
        found = foundation_request("GET", "/v1/identity/agents/" + agent_id)
        check("foundation_registry_readback", found["agent"]["agent_id"] == agent_id)
        for action, resource, expected in (("model.promote_to_production", "model/champion", "ALLOW"),
                                            ("model.promote_to_production", "model/experimental", "DENY"),
                                            ("demo.read", "urn:dataset/health", "ALLOW")):
            decision = foundation_request("POST", "/v1/policy/evaluations", {"decision_id": str(uuid4()),
                "agent_id": agent_id, "action_class": action, "resource": resource})
            check("policy_" + action + "_" + expected + "_" + resource.replace("/", "_"),
                  decision["decision"]["effect"] == expected, effect=decision["decision"]["effect"])
        try:
            request = Request(config()["ARE_FOUNDATION_BASE_URL"] + "/v1/meta/deployment")
            with urlopen(request, timeout=5):
                denied = False
        except Exception as exc:
            denied = getattr(exc, "code", 0) in (400, 401)
        check("gateway_rejects_unauthenticated_request", denied)
        report["execution_state"] = "COMPLETED"
        report["acceptance_color"] = "GREEN"
        report["agent_id"] = agent_id
    except Exception as exc:
        report["execution_state"] = "ABORTED"
        report["acceptance_color"] = "RED"
        report["error"] = type(exc).__name__ + ": " + str(exc)
    report["finished_at"] = datetime.now(timezone.utc).isoformat()
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(report, indent=2) + "\n")
    return report


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=["start", "start-passport", "stop", "restore", "validate-services", "validate-connected", "validate-adversarial", "status"])
    parser.add_argument("--report", type=Path, default=KIT / "reports/reference-services.json")
    parser.add_argument("--state-dir", type=Path, default=RUNTIME / "connected-validation")
    args = parser.parse_args()
    if args.command in ("start", "restore"):
        compose("ledger", "up", "-d", "--no-build")
        compose("reference", "up", "-d")
        wait_http("http://127.0.0.1:" + config(LEDGER_ENV)["LEDGER_HEALTH_PORT"] + "/readyz")
        wait_http("http://127.0.0.1:" + config().get("FOUNDATION_BFF_HEALTH_PORT", "29599") + "/health")
        start_passport()
    elif args.command == "start-passport":
        start_passport()
    elif args.command == "stop":
        stop_passport()
        compose("reference", "stop")
        compose("ledger", "stop")
    elif args.command == "validate-services":
        report = validate_services(args.report)
        print(json.dumps({"report": str(args.report), "acceptance_color": report["acceptance_color"]}))
        return 0 if report["execution_state"] == "COMPLETED" else 1
    elif args.command in ("validate-connected", "validate-adversarial"):
        runner = "validate_connected.py" if args.command == "validate-connected" else "validate_adversarial.py"
        run([sys.executable, KIT / "tools" / runner, "--config", ENV_FILE,
             "--ledger-config", LEDGER_ENV, "--state-dir", args.state_dir,
             "--report", args.report], "connected-validation.log")
    print(json.dumps({"command": args.command, "passport_running": passport_running(),
                      "private_config": str(ENV_FILE), "volumes_retained": True}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
