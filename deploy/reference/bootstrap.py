"""Reconstruct pinned canonical sources and build an isolated local reference."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
from build import source_fingerprint

HERE = Path(__file__).resolve().parent
KIT = HERE.parents[1]


def run(argv, *, cwd=None, env=None, log=None):
    if log:
        with log.open("a") as out:
            subprocess.run([str(x) for x in argv], cwd=cwd, env=env, stdout=out, stderr=subprocess.STDOUT, check=True)
    else:
        subprocess.run([str(x) for x in argv], cwd=cwd, env=env, check=True)


def source_checkout(source, workspace, logdir):
    target = workspace / source["path"]
    marker = target / ".git/earned-authority-reconstruction.json"
    patches = source.get("patches", [])
    expected = {"revision": source["revision"], "patches": patches}
    if target.exists():
        saved = json.loads(marker.read_text()) if marker.exists() else {}
        if saved.get("inputs") != expected or saved.get("source") != source_fingerprint(target):
            raise RuntimeError("Existing source is not this exact reconstruction: " + str(target))
        # Reuse only explicitly generated snapshots. Build fingerprints provide
        # consumed-file provenance; a new workspace is the clean-install gate.
        return expected
    log = logdir / ("checkout-" + source["name"] + ".log")
    target.parent.mkdir(parents=True, exist_ok=True)
    run(["git", "init", target], log=log)
    run(["git", "remote", "add", "origin", source["url"]], cwd=target, log=log)
    run(["git", "fetch", "--depth=1", "origin", source["revision"]], cwd=target, log=log)
    run(["git", "checkout", "--detach", "FETCH_HEAD"], cwd=target, log=log)
    head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=target, text=True).strip()
    if head != source["revision"]:
        raise RuntimeError("Source revision mismatch: " + source["name"])
    for patch in patches:
        path = KIT / patch["path"]
        if hashlib.sha256(path.read_bytes()).hexdigest() != patch["sha256"]:
            raise RuntimeError("Patch digest mismatch: " + str(path))
        run(["git", "apply", "--check", path], cwd=target, log=log)
        run(["git", "apply", path], cwd=target, log=log)
    marker.write_text(json.dumps({"inputs": expected, "source": source_fingerprint(target)}, sort_keys=True) + "\n")
    return expected


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--workspace", type=Path, required=True)
    p.add_argument("--instance", default="earned-authority")
    p.add_argument("--port-offset", type=int, default=0)
    p.add_argument("--sources-only", action="store_true")
    p.add_argument("--start", action="store_true")
    p.add_argument("--validate", action="store_true")
    args = p.parse_args()
    if not re.fullmatch(r"[a-z][a-z0-9-]{2,40}", args.instance):
        p.error("instance must be a short lowercase container-name prefix")
    if not 0 <= args.port_offset <= 30000:
        p.error("port offset must be between 0 and 30000")
    for executable in ("git", "uv", "go", "podman"):
        if not shutil.which(executable):
            p.error("Required prerequisite is missing: " + executable)
    workspace = args.workspace.resolve()
    logdir = workspace / "work/bootstrap-logs"
    logdir.mkdir(parents=True, exist_ok=True)
    os.chmod(workspace / "work", 0o700)
    manifest = json.loads((HERE / "sources.json").read_text())
    if any(s.get("reconstruction_status", "").startswith("PENDING") for s in manifest["sources"]):
        raise SystemExit("Canonical reconstruction manifest is incomplete")
    with ThreadPoolExecutor(max_workers=5) as pool:
        futures = [(s["name"], pool.submit(source_checkout, s, workspace, logdir)) for s in manifest["sources"]]
        sources, errors = [], []
        for name, future in futures:
            try:
                sources.append(future.result())
            except Exception as exc:
                errors.append({"source": name, "error": type(exc).__name__ + ": " + str(exc)})
    if errors:
        (logdir / "source-errors.json").write_text(json.dumps(errors, indent=2) + "\n")
        raise SystemExit(json.dumps({"source_errors": errors, "logs": str(logdir)}))
    print(json.dumps({"stage": "canonical_sources_reconstructed", "sources": len(sources), "workspace": str(workspace)}), flush=True)
    if args.sources_only:
        return
    env = {**os.environ, "EA_WORKSPACE": str(workspace), "EA_INSTANCE": args.instance, "EA_PORT_OFFSET": str(args.port_offset)}
    venv = workspace / "work/ledger-venv"
    if not (venv / "bin/python").exists():
        run(["uv", "venv", "--python", "3.12.13", venv], log=logdir / "python.log")
    python = venv / "bin/python"
    run(["uv", "pip", "install", "--python", python, "-r", HERE / "requirements.lock.txt"], log=logdir / "python.log")
    run([python, HERE / "prepare.py"], env=env)
    run([python, HERE / "prepare_policy.py"], env=env)
    run([python, KIT / "deploy/ledger/prepare.py", "--source", workspace / "work/ledger-track", "--runtime", workspace / "work/ledger-runtime", "--instance", args.instance, "--port-offset", str(args.port_offset)])
    run([python, HERE / "build.py"], env=env)
    arch = subprocess.check_output(["podman", "info", "--format", "{{.Host.Arch}}"], text=True).strip()
    rust = {"arm64": "sha256:4c632e493dfa97f0fe014c3910d1690c149bba85ed8678d47d3563ec6f258ead",
            "amd64": "sha256:3f6e6f8d8725a65a2db964bb828850f888d430c68784d661f753144e5d787207"}
    if arch not in rust:
        raise SystemExit("Reference build supports arm64 or amd64 only")
    run(["podman", "build", "--arch", arch, "--build-arg", "RUST_IMAGE=docker.io/library/rust@" + rust[arch],
         "-t", "localhost/earned-authority-ledger:2679c9e", "-f", KIT / "deploy/ledger/Dockerfile", workspace / "work/ledger-track"], log=logdir / "ledger-image.log")
    versions = {"go": subprocess.check_output(["go", "version"], text=True).strip(),
                "python": subprocess.check_output([python, "--version"], text=True).strip(),
                "podman": subprocess.check_output(["podman", "--version"], text=True).strip()}
    record = {"workspace": str(workspace), "instance": args.instance, "port_offset": args.port_offset,
              "sources": manifest["sources"], "tool_versions": versions, "source_reconstruction": "fresh pinned upstream + verified complete patches",
              "limits": "Reproduces source inputs and dependencies; does not claim byte-identical release, clean external host, or second-person validation."}
    (workspace / "work/reference-runtime/bootstrap-manifest.json").write_text(json.dumps(record, indent=2) + "\n")
    if args.start or args.validate:
        run([python, HERE / "reference.py", "start"], env=env)
    if args.validate:
        run([python, HERE / "validate_policy.py", "--report", workspace / "work/reference-runtime/policy.json"], env=env)
        run([python, HERE / "reference.py", "validate-services", "--report", workspace / "work/reference-runtime/services.json"], env=env)
        run([python, HERE / "reference.py", "validate-connected", "--report", workspace / "work/reference-runtime/connected.json"], env=env)
        run([python, HERE / "reference.py", "validate-adversarial", "--report", workspace / "work/reference-runtime/adversarial.json"], env=env)
        run([python, HERE / "reference.py", "validate-authority-recovery", "--report", workspace / "work/reference-runtime/authority-recovery.json"], env=env)
        run([python, HERE / "validate_restore.py", "--prior-report", workspace / "work/reference-runtime/connected.json", "--report", workspace / "work/reference-runtime/restore.json"], env=env)
        run([python, KIT / "tools/validate_authority_recovery.py", "--config", workspace / "work/reference-runtime/reference.env",
             "--ledger-config", workspace / "work/ledger-runtime/local.env", "--state-dir", workspace / "work/reference-runtime/connected-validation",
             "--verify-existing-report", workspace / "work/reference-runtime/authority-recovery.json", "--report", workspace / "work/reference-runtime/authority-recovery-restored.json"], env=env)
    print(json.dumps({"stage": "reference_built", "workspace": str(workspace), "started": args.start or args.validate, "validated": args.validate}))


if __name__ == "__main__":
    main()
