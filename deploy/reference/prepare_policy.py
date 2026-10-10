"""Freeze source policy and its content binding before starting local OPA."""
import argparse
import hashlib
import json
import os
from pathlib import Path

HERE = Path(__file__).resolve().parent
KIT = HERE.parents[1]
TASK = Path(os.environ.get("EA_WORKSPACE", str(KIT.parents[1]))).resolve()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--refresh", action="store_true", help="Explicitly replace the frozen snapshot; restart OPA afterward")
    args = parser.parse_args()
    env_path = TASK / "work/reference-runtime/reference.env"
    values = dict(line.split("=", 1) for line in env_path.read_text().splitlines() if "=" in line)
    runtime = Path(values["REFERENCE_RUNTIME_DIR"])
    source = Path(values["FOUNDATION_SOURCE_DIR"]) / "sx/s0s1-rest-bff/policy/are_evaluatepolicy.rego"
    policy = source.read_bytes()
    authz = (HERE / "authz/authorization.rego").read_bytes()
    digest = "sha256:" + hashlib.sha256(policy).hexdigest()
    policy_id = "policy/are_evaluatepolicy.rego"
    binding = json.dumps({"are_policy_binding": {"policy_id": policy_id, "policy_digest": digest}}, sort_keys=True, indent=2).encode() + b"\n"
    files = {"policy/are_evaluatepolicy.rego": policy, "policy/binding.json": binding,
             "authz/authorization.rego": authz}
    snapshot = runtime / "policy-snapshot"
    for relative, content in files.items():
        path = snapshot / relative
        if path.exists() and path.read_bytes() != content and not args.refresh:
            raise SystemExit("Frozen policy differs from current source. Explicit --refresh and service restart required.")
    for relative, content in files.items():
        path = snapshot / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        if not path.exists() or path.read_bytes() != content:
            temporary = path.with_name(path.name + ".new")
            temporary.write_bytes(content)
            temporary.chmod(0o444)
            temporary.replace(path)
    values.update({"OPA_POLICY_SNAPSHOT_DIR": str(snapshot),
        "ARE_OPA_BASE_URL": "http://127.0.0.1:" + values.get("OPA_PORT", "29582"),
        "ARE_OPA_POLICY_ID": policy_id, "ARE_OPA_POLICY_DIGEST": digest,
        "ARE_OPA_AUTHZ_POLICY_ID": "authz/authorization.rego",
        "ARE_OPA_AUTHZ_POLICY_DIGEST": "sha256:" + hashlib.sha256(authz).hexdigest()})
    env_path.write_text("".join(f"{key}={value}\n" for key, value in values.items()))
    env_path.chmod(0o600)
    manifest = {"policy_id": policy_id, "policy_digest": digest,
        "authz_policy_id": values["ARE_OPA_AUTHZ_POLICY_ID"], "authz_policy_digest": values["ARE_OPA_AUTHZ_POLICY_DIGEST"],
        "files_sha256": {key: hashlib.sha256(value).hexdigest() for key, value in files.items()},
        "contract": "OPA reads policy and binding in one startup load; no watch or network writes; trusted host administrator"}
    (runtime / "policy-snapshot.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(json.dumps(manifest))


if __name__ == "__main__":
    main()
