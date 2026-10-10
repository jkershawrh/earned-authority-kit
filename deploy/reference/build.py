"""Build canonical local sources and record the exact consumed runtime inputs."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

HERE = Path(__file__).resolve().parent
KIT = HERE.parents[1]
TASK = Path(os.environ.get("EA_WORKSPACE", str(KIT.parents[1]))).resolve()
RUNTIME = TASK / "work/reference-runtime"


def source_fingerprint(path):
    records = {}
    suffixes = {".go", ".mod", ".sum", ".proto", ".rego", ".py", ".toml", ".lock", ".rs"}
    for p in sorted(path.rglob("*")):
        relative = p.relative_to(path)
        if any(part in {".git", "target", "__pycache__", ".venv", "node_modules", "bin"} for part in relative.parts):
            continue
        if p.is_file() and p.suffix in suffixes:
            records[str(relative)] = hashlib.sha256(p.read_bytes()).hexdigest()
    encoded = json.dumps(records, sort_keys=True, separators=(",", ":")).encode()
    return {"runtime_source_sha256": hashlib.sha256(encoded).hexdigest(), "files_sha256": records}


def main():
    parser = argparse.ArgumentParser()
    selection = parser.add_mutually_exclusive_group()
    selection.add_argument("--foundation-only", action="store_true")
    selection.add_argument("--passport-only", action="store_true")
    parser.add_argument("--report", type=Path, default=RUNTIME / "reference-build-manifest.json")
    args = parser.parse_args()
    values = dict(line.split("=", 1) for line in (RUNTIME / "reference.env").read_text().splitlines() if "=" in line)
    source = Path(values["FOUNDATION_SOURCE_DIR"])
    build_dir = RUNTIME / "build"
    build_dir.mkdir(exist_ok=True)
    arch = subprocess.check_output(["podman", "info", "--format", "{{.Host.Arch}}"], text=True).strip()
    commands = []
    before = source_fingerprint(source)
    components = () if args.passport_only else (("bff", "s0s1-rest-bff"), ("gateway", "are-api-gateway"))
    for component, package in components:
        binary = "foundation-" + component
        command_name = "are-s0s1-rest-bff" if component == "bff" else "are-api-gateway"
        command = ["go", "build", "-mod=readonly", "-o", str(build_dir / binary), "./cmd/" + command_name]
        commands.append({"argv": command, "cwd": str(source / "sx" / package), "GOOS": "linux", "GOARCH": arch})
        with (RUNTIME / ("build-" + component + ".log")).open("w") as log:
            subprocess.run(command, cwd=source / "sx" / package, check=True, env={**os.environ, "CGO_ENABLED": "0", "GOOS": "linux", "GOARCH": arch}, stdout=log, stderr=subprocess.STDOUT)
            image_command = ["podman", "build", "--build-arg", "BINARY=" + binary, "-t", "localhost/earned-authority-foundation-" + component + ":reference", "-f", str(HERE / "Foundation.Dockerfile"), str(build_dir)]
            subprocess.run(image_command, check=True, stdout=log, stderr=subprocess.STDOUT)
            commands.append({"argv": image_command})
    after = source_fingerprint(source)
    if before != after:
        raise SystemExit("Foundation source changed during build; rerun after the editing lane is stable")
    manifest = {"architecture": arch, "commands": commands}
    if not args.passport_only:
        manifest.update(foundation=after,
                binary_sha256={p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in build_dir.glob("foundation-*")})
    if not args.foundation_only:
        passport = Path(values["PASSPORT_SOURCE_DIR"])
        passport_before = source_fingerprint(passport)
        (passport / "bin").mkdir(exist_ok=True)
        subprocess.run(["go", "build", "-mod=readonly", "-o", str(passport / "bin/agent-passport"), "./cmd/agent-passport"], cwd=passport, check=True)
        manifest["passport"] = source_fingerprint(passport)
        if passport_before != manifest["passport"]:
            raise SystemExit("Passport source changed during build; wait for the source lane to freeze")
        manifest["passport_binary_sha256"] = hashlib.sha256((passport / "bin/agent-passport").read_bytes()).hexdigest()
        sdk = Path(values["PASSPORT_SDK_DIR"])
        sdk.mkdir(parents=True, exist_ok=True)
        proto = passport / "proto"
        command = [sys.executable, "-m", "grpc_tools.protoc", "-I", str(proto), "--python_out=" + str(sdk),
                   "--grpc_python_out=" + str(sdk), str(proto / "passport_issuance.proto")]
        subprocess.run(command, check=True)
        commands.append({"argv": command})
        manifest["passport_sdk_sha256"] = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(sdk.glob("passport_issuance_pb2*.py"))}
        manifest["passport_proto_sha256"] = hashlib.sha256((proto / "passport_issuance.proto").read_bytes()).hexdigest()
    for name in ("CASCADE_SOURCE_DIR", "GCL_SOURCE_DIR"):
        manifest[name] = source_fingerprint(Path(values[name]))
    report = args.report
    report.parent.mkdir(parents=True, exist_ok=True)
    report.write_text(json.dumps(manifest, indent=2) + "\n")
    print(json.dumps({"manifest": str(report), "architecture": arch, "foundation_only": args.foundation_only, "passport_only": args.passport_only}))


if __name__ == "__main__":
    main()
