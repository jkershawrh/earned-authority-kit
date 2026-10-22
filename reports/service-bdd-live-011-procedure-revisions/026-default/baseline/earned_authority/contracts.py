"""Draft local contract checks. Schema validity never grants authority."""
import hashlib
import json
from pathlib import Path
from jsonschema import Draft202012Validator

CONTRACTS = Path(__file__).resolve().parents[1] / "contracts"


def validate(kind, value):
    if kind not in {"qualification", "authority", "attempt", "outcome", "lifecycle-event"}:
        raise ValueError("unknown contract")
    canonical_digest(value)  # The accepted shape must have an unambiguous encoding.
    schema = json.loads((CONTRACTS / (kind + ".schema.json")).read_text())
    Draft202012Validator(schema).validate(value)
    if kind == "qualification":
        start, end = value["observed_from_ms"], value["observed_until_ms"]
        if (start is None) != (end is None):
            raise ValueError("qualification observation window endpoints must both be null or integers")
        if not value["outcome_refs"] and start is not None:
            raise ValueError("qualification without evidence must not invent an observation window")
        if value["outcome_refs"] and start is None:
            raise ValueError("qualification evidence references require an observation window")
        if start is not None and start > end:
            raise ValueError("qualification observation window is reversed")
        if value['disposition'] == 'ELIGIBLE' and not end < value["expires_at_ms"]:
            raise ValueError("qualification observation and validity windows conflict")
    if kind == "authority":
        start, end = value["issued_at_ms"], value["expires_at_ms"]
        if start >= end:
            raise ValueError("authority validity window is empty")
        ids = [g["grant_id"] for g in value["grants"]]
        if len(ids) != len(set(ids)):
            raise ValueError("duplicate grant id")
        for grant in value["grants"]:
            if not start < grant["expires_at_ms"] <= end:
                raise ValueError("grant validity exceeds its authority window")
    return value


def load_unique_json(text):
    def unique(pairs):
        out = {}
        for key, value in pairs:
            if key in out:
                raise ValueError("duplicate JSON key: " + key)
            out[key] = value
        return out
    return json.loads(text, object_pairs_hook=unique,
                      parse_constant=lambda value: (_ for _ in ()).throw(ValueError("non-finite number")))


def canonical_digest(value):
    """Draft v0.1 encoding: UTF-8, sorted keys, compact, integer-only numbers.

    No Unicode normalization. This is NOT a signature or an implementation of
    an external canonicalization standard. Consumers must pass shared vectors.
    """
    def check(node):
        if node is None or type(node) in (str, bool, int):
            return
        if isinstance(node, list):
            for item in node: check(item)
            return
        if isinstance(node, dict) and all(isinstance(k, str) for k in node):
            for item in node.values(): check(item)
            return
        raise ValueError("canonical contract payloads permit only JSON with integer numbers")
    check(value)
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()
