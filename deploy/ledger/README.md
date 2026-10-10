# Canonical ARE Ledger component

This profile runs the real standalone ARE Immutable Ledger and PostgreSQL locally. It does not replace the ledger with the kit's fixture implementation. Source is pinned to `2679c9e0a5430cde9e435339e441a94989d2bcd6` from `jkershawrh/are-immutable-ledger`. The service source remains unchanged; this directory supplies a locked build, restricted runtime user, local configuration, and validation harness.

This is a local reference deployment. The upstream Python SDK uses plaintext gRPC, so the adapter accepts loopback endpoints only. The container publishes ports only on `127.0.0.1`. Authenticated transport to remote hosts, production key management, and external ledger anchoring require separate work.

## Start from the task directory

The following assumes the kit is at `outputs/earned-authority-kit`. Use an isolated canonical checkout and a private runtime directory. Existing user project files are not changed.

```sh
git clone https://github.com/jkershawrh/are-immutable-ledger.git work/ledger-track
git -C work/ledger-track checkout --detach 2679c9e0a5430cde9e435339e441a94989d2bcd6
uv venv --python 3.12 work/ledger-venv
uv pip install --python work/ledger-venv/bin/python -r outputs/earned-authority-kit/deploy/ledger/requirements.txt
work/ledger-venv/bin/python outputs/earned-authority-kit/deploy/ledger/prepare.py
work/ledger-venv/bin/podman-compose --env-file work/ledger-runtime/local.env -f outputs/earned-authority-kit/deploy/ledger/compose.yaml up -d --build
```

Skip clone/venv creation when the supplied workspace already has them. `prepare.py` verifies the source revision and refuses tracked modifications. It generates an API token, independent database credentials, and an Ed25519 writer key in `work/ledger-runtime`, with private permissions. It preserves existing configuration on repeat runs. Do not put that directory into a shared artifact or repository.

`Dockerfile` compiles canonical source using `cargo build --release --locked`. Source and Cargo dependencies are pinned; base image tags are not a claim of a fully reproducible release. Record the resulting image ID with every run. To use an already cached matching Rust base on ARM64, the validated build command is:

```sh
podman build --pull=never --arch arm64 --build-arg RUST_IMAGE=localhost/earned-ledger-rust:1.90-arm64 --tag localhost/earned-authority-ledger:2679c9e -f outputs/earned-authority-kit/deploy/ledger/Dockerfile work/ledger-track
```

That optional cache tag is local to this workstation and is not needed for the ordinary build. A fresh machine should use the default public image and its matching architecture.

## Owned resources

- PostgreSQL container: `earned-authority-ledger-db`; loopback port `29432`.
- Canonical service container: `earned-authority-ledger-service`; gRPC `29492`, health `29480`, metrics `29483` on loopback.
- Durable named volume: `earned-authority-ledger-data`.
- Private environment file: `work/ledger-runtime/local.env`.
- Private writer key: `work/ledger-runtime/writer-private.pem`; public verifier key beside it.

The restricted `ledger_app` database role has INSERT and SELECT on ledger entries, with no UPDATE or DELETE. The canonical service verifies that boundary at startup. Database administration can still modify stored bytes; the tamper probe checks that the changed assertion is detected, not that privileged rewriting or whole-history replacement is impossible.

To stop and retain evidence, run `podman-compose` with the same env file and compose file followed by `stop`. To resume, use `start`. Do not use `down -v` or remove `earned-authority-ledger-data` when evidence must be retained. No automatic cleanup removes the volume.

## Adapter interface

`earned_authority.ledger_client.LedgerClient` uses the canonical gRPC Python SDK from the pinned checkout. The two operations are:

```python
receipt = client.append(event, idempotency_key)
verified = client.verify(receipt, event)
```

An event must include nonempty string `agent_id`, `attempt_id`, `correlation_id`, and `event_type`. It may include qualification, skill/context, policy, authority revision, and outcome fields; the full event is bound. The event and stable idempotency key must be exactly the same for a retry.

Constructor arguments are endpoint, explicit API token, canonical `sdk_path`, Ed25519 `signer_private_key`, `signer_key_id`, and a `trusted_writers` mapping of key IDs to Ed25519 public keys. The mapping is an explicit local trust policy. Verification never trusts a key merely because its identifier appears in a ledger receipt.

For local orchestration, the validation module exposes `read_config(path)` and `client_from_config(config)`. They load the prepared private configuration without logging secrets. Call `client.close()` after use.

Each append signs a domain-separated canonical envelope binding the complete event digest, actor, attempt, correlation, event type, source, content type, idempotency key, and signing-key reference. `IssueReceipt` stores the assertion in the real ledger. The adapter then verifies it before returning a receipt.

Verification fetches the stored entry and requires exact event bytes and receipt metadata, reconstructs the ledger's V3 canonical hash independently, verifies the writer signature against the pinned local key, and asks the canonical server to verify both proof and entry chain link. V2 and unknown hash versions are rejected. Changing an event, attempt, signature, receipt, or trust policy cannot silently preserve verification.

`append` raises `LedgerError` when no verified receipt is available. A failed acknowledgement can occur after an actual commit; retry the same key and content. `verify` returns false on a mismatch or unavailable dependency. Neither result grants execution authority or proves an asserted outcome was true. Freshness and eligibility for any reuse remain the consumer's policy.

Controllers should use `verify_detailed(receipt, event, max_age_ms=None, now_ms=None)` when deciding how to handle a failed verification. It returns `verified`, `status`, `reason`, and `integrity`. A successful result is `VERIFIED`/`INTACT`. A positively detected content, hash or signature mismatch is `REJECTED`/`MISMATCH`. A transport outage is `UNAVAILABLE`/`UNKNOWN`; age-policy rejection is `STALE`/`UNKNOWN`; malformed or untrusted evidence is `REJECTED`/`UNKNOWN`. An unavailable service or missing trust key must not be recorded as known tampering or a known task failure. No age limit is imposed unless the consumer selects one.

## Validate the real services

```sh
work/ledger-venv/bin/python outputs/earned-authority-kit/deploy/ledger/validate.py --env-file work/ledger-runtime/local.env --report outputs/earned-authority-kit/reports/ledger-connected.json
```

This command makes real authenticated gRPC requests, checks missing/wrong API-token rejection, verifies Ed25519 trust and exact content/attempt binding, checks duplicate and conflicting idempotency, and tests database application-role permissions. It restarts only the two owned containers and verifies persisted receipts and idempotency afterwards.

It then alters a single owned probe row as the database administrator, checks that both the adapter and canonical server detect the corruption, and restores that row's original content in a `finally` block. It verifies the restored chain. The report records actual checks, source revision, container/image identities, timestamps, receipts, and secret-free command arguments. It never records the API token or private key.

`--skip-restart` is available for a non-disruptive check, but its report remains AMBER for this full component gate. Do not use it as evidence of restart preservation.

Unit tests in `tests/test_ledger_client.py` use an explicitly labelled fake transport to test adapter rejection behavior. Their results are distinct from `reports/ledger-connected.json`, which must say `REAL_LOCAL_SERVICES`. Neither suite measures adaptive-controller product value; the EDD comparator protocol remains a separate evaluation.

Run the 25 adapter tests with `python -m pytest tests/test_ledger_client.py -v` from the kit directory using the prepared Python environment. They are pytest tests; unittest discovery alone does not collect them.
