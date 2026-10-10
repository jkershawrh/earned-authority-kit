# Local reference deployment

This profile runs canonical Foundation gateway/BFF, Agent Passport, ARE Immutable Ledger, PostgreSQL and OPA. Cascade and deterministic GCL execute their pinned canonical code through the kit adapters. Foundation delegates Passport lifecycle; it does not maintain a second authority store. The disposable model registry and its outcome checker run in the kit process, with persistent local SQLite state.

`sources.json` fixes upstream revisions and complete patch hashes. The Foundation patch includes the tracked baseline changes present at review plus the authority, delegation and policy-binding fixes. These are explicit local reference changes, not claims that upstream releases already provide the same behavior. `requirements.lock.txt` fixes the Python dependencies. Go and Cargo resolve their checked-in lock data; build manifests record tool versions, consumed source and binary hashes. The installer needs network access to the pinned Git sources, Python packages, Go/Cargo modules, and container registries.

## Reconstruct and start

Prerequisites are Git, uv, Go, and a running Podman engine. The validated host uses Go 1.26.4 and Python 3.12.13. Python is provisioned into an isolated environment by uv. Container build architectures are arm64 and amd64; the current pinned OPA image is amd64 and runs under emulation on the validated arm64 host. Performance measurements from this profile would need to record that fact.

From the delivered kit directory, choose a new workspace and a unique container prefix. A port offset separates a second instance from the default instance. The following builds and runs actual services, then validates their live interfaces and the connected lifecycle:

```sh
python3 deploy/reference/bootstrap.py --workspace /absolute/path/to/reference-workspace --instance ea-reference --port-offset 1000 --validate
```

The workspace must be new or an unchanged reconstruction made by this installer. It never resets an existing user checkout. Failed partial source downloads are retained; choose another workspace after inspecting the recorded error. The installer applies complete patches once, checks their hashes and applicability, generates the exact Passport protobuf SDK, creates private local configuration, freezes policy files, builds the services, and starts only containers with the chosen prefix. `--validate` runs policy, interface, connected lifecycle, adversarial, authority-operation recovery and full stop/restore checks, then reads back the historical operation and ledger receipts after restart. Omit `--validate` and supply `--start` to start without executing behavioral validation. With neither flag, it builds and prepares without starting.

The executable kit remains where it was delivered; the selected workspace holds only source, dependencies, keys, logs and durable process state. Keep both locations available. Container image tags are shared build outputs; existing running containers retain their image identity. Stop unrelated build jobs before rebuilding the same tags.

The default loopback ports are Foundation 29585, OPA 29582, Passport gRPC 29594 and health 29580, and Ledger gRPC 29492 and health 29480. Every port in the two profiles receives the selected offset. Foundation uses a real local RS256 JWT and JWKS server with gateway-to-BFF mTLS. Local host-facing HTTP and gRPC remain plaintext loopback reference transports. This is not a remote production deployment or a credential-management design.

## Validate and retain state

Set the same workspace for every lifecycle command. The private configuration is read directly; do not source or print it.

```sh
EA_WORKSPACE=/absolute/path/to/reference-workspace /absolute/path/to/reference-workspace/work/ledger-venv/bin/python deploy/reference/reference.py validate-services --report reports/reference-services.json
EA_WORKSPACE=/absolute/path/to/reference-workspace /absolute/path/to/reference-workspace/work/ledger-venv/bin/python deploy/reference/validate_policy.py --report reports/reference-policy.json
EA_WORKSPACE=/absolute/path/to/reference-workspace /absolute/path/to/reference-workspace/work/ledger-venv/bin/python deploy/reference/reference.py validate-connected --report reports/reference-connected.json
EA_WORKSPACE=/absolute/path/to/reference-workspace /absolute/path/to/reference-workspace/work/ledger-venv/bin/python deploy/reference/reference.py validate-adversarial --report reports/reference-adversarial.json
EA_WORKSPACE=/absolute/path/to/reference-workspace /absolute/path/to/reference-workspace/work/ledger-venv/bin/python deploy/reference/reference.py validate-authority-recovery --report reports/authority-recovery.json
EA_WORKSPACE=/absolute/path/to/reference-workspace /absolute/path/to/reference-workspace/work/ledger-venv/bin/python deploy/reference/validate_restore.py --prior-report reports/reference-connected.json --report reports/reference-restore.json
```

The last command stops and restores that entire owned stack, preserving its named volumes and private keys. It checks the earlier agent identity, current signed authority and revision, registry mutation count, and every earlier canonical ledger receipt. This is process/container restart recovery. It does not simulate loss of a disk, backup restoration, or a different administrator installing on another machine.

The authority recovery runner creates separate coordinator subprocesses and exits them at the durable-intent, remote-commit, local-event and acknowledged-withdrawal boundaries. It also uses a separate forwarding proxy to drop a real successful canonical reply, and a real read-only SQLite connection to reject a local write after remote commit. The tests distinguish a historical committed operation from current authority: a later replacement must remain unchanged when the earlier event is recovered. No proxy creates credentials or substitutes for canonical Passport.

After the full stack restart, verify the earlier operation history without issuing new authority:

```sh
/absolute/path/to/reference-workspace/work/ledger-venv/bin/python tools/validate_authority_recovery.py --config /absolute/path/to/reference-workspace/work/reference-runtime/reference.env --ledger-config /absolute/path/to/reference-workspace/work/ledger-runtime/local.env --state-dir /absolute/path/to/reference-workspace/work/reference-runtime/connected-validation --verify-existing-report reports/authority-recovery.json --report reports/authority-recovery-restored.json
```

`build.py --passport-only` rebuilds the configured canonical Passport binary and regenerates its exact Python SDK together. Its manifest records the consumed source, protobuf and SDK hashes. Stop the owned Passport process before a protocol cutover, wait for the source to be stable, build, restore, and rerun the connected checks. A new complete source patch changes the installer reconstruction identity; use a new clean workspace rather than modifying an earlier validated checkout in place.

`reference.py stop` gracefully stops the host Passport process and the owned containers. `reference.py restore` restarts them using the same state and keys. Never remove the named Ledger or Foundation volumes when evidence must be retained. The installer does not remove volumes. Runtime handles are recorded in `work/reference-runtime/passport-process.json`; logs and secret configuration stay under the selected workspace. A stop verifies the recorded process command before sending SIGTERM and does not force-kill a mismatching PID.

For the full Ledger component validation, run `deploy/ledger/validate.py` with the selected workspace's `work/ledger-runtime/local.env` as `--env-file`. That validator restarts its owned database and service, checks authenticated writes, content/signature binding and idempotency, and alters then restores one owned probe row to verify tamper detection. Its test uses administrative access intentionally and does not claim administrators cannot rewrite storage.

## Policy and authority boundaries

`prepare_policy.py` copies the final domain Rego and its exact SHA-256 binding into the same frozen snapshot. OPA loads both in one startup operation. Its decision returns the loaded policy ID/digest and echoes the exact decision ID, agent, action and resource. The BFF and kit require that binding. The kit also checks the exact two-module inventory before and after evaluation.

OPA starts with `--authorization=basic`, readonly mounts, and no file watch, bundle discovery or network policy updates. Its separate `system.authz` module permits only health, policy inventory and the exact decision query. Policy/data writes, query and compile administration are denied. See the [OPA authorization documentation](https://www.openpolicyagent.org/docs/security) for the upstream mechanism. `validate_policy.py` proves the expected denials against the running instance. Host/container administrators remain trusted; a hostile operator changing files, processes or network configuration is outside this local guarantee.

The Passport process and fenced model-registry executor must run on the same host operating system using the configured `authority.fence`. Do not move only Passport into a Podman container on macOS: a VM lock and a host lock are different coordination domains. The reference keeps Passport on the host and runs the supporting services in containers.

Ledger receipts preserve signed assertions. They do not establish outcome truth or authorize execution. The adapter distinguishes verified content, positively detected mismatch, unavailable service, stale evidence and unknown trust. Dependency failure holds new authority rather than declaring a known task failure or tampering.

## Renewal and scope

Local JWTs expire after one day and TLS certificates after 30 days. Running `prepare.py` again with the same workspace refreshes the JWT while preserving keys, database credentials, prefix and ports. Then stop and restore the reference so the host Passport loads its refreshed registry token. TLS renewal is an explicit operation; this profile does not silently replace a running trust root. `prepare_policy.py` refuses source changes unless `--refresh` is supplied explicitly; refresh requires a coordinated service rebuild/restart and revalidation.

Successful fixture, interface, lifecycle and restart runs establish the behaviors covered by those runs. They do not validate product value, customer adoption, a universal zero-risk claim, robotics safety, Red Hat support, or a distributed mutation/revocation protocol. EDD comparators, risk budget and sample-size adequacy remain separate acceptance work. A second clean workspace on the same host is distinct from an independent installer or cross-host gate.
