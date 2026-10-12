"""Exact grant lookup for fixture maps and connected grant lists.

A fixture authority may still store one grant per skill in a dictionary. The
connected adapter stores every current grant in a list. Callers use these
helpers instead of assuming either shape. A list is never folded back into a
skill-keyed dictionary.
"""
import copy

from .contracts import canonical_digest
from .runtime import Denied

_SLOT = ('skill', 'action', 'resource', 'context_digest')
_REQUIRED = ('grant_id', 'skill', 'version', 'action', 'resource', 'qualification_id',
             'qualification_digest', 'policy_digest', 'skill_digest', 'context_digest')
_TARGET = ('grant_id', 'qualification_id', 'skill', 'version', 'context', 'action', 'resource', 'expires_at_ms')


def slot(grant):
    return tuple(grant[key] for key in _SLOT)


def iter_grants(authority):
    """Return every grant, rejecting duplicate identities, scopes, and slots."""
    try:
        raw = authority['grants']
        if isinstance(raw, dict):
            if any(key != grant['skill'] for key, grant in raw.items()):
                raise ValueError('fixture key mismatch')
            records = tuple(raw.values())
        elif isinstance(raw, (list, tuple)):
            records = tuple(raw)
        else:
            raise ValueError('invalid grants container')
        ids = set()
        scope_ids = set()
        slots = set()
        for grant in records:
            for key in _REQUIRED:
                if not isinstance(grant[key], str) or not grant[key]:
                    raise ValueError('invalid binding field')
            if type(grant['expires_at_ms']) is not int:
                raise ValueError('invalid expiry')
            if grant['skill_digest'] != canonical_digest({'skill': grant['skill'], 'version': grant['version']}):
                raise ValueError('skill digest')
            if grant['context_digest'] != canonical_digest({'environment': grant['context']}):
                raise ValueError('context digest')
            identity = grant['grant_id']
            grant_slot = slot(grant)
            if identity in ids or grant_slot in slots:
                raise ValueError('duplicate binding')
            ids.add(identity)
            slots.add(grant_slot)
            if 'canonical_scope_id' in grant:
                scope_id = grant['canonical_scope_id']
                if not isinstance(scope_id, str) or not scope_id or scope_id in scope_ids:
                    raise ValueError('duplicate scope')
                scope_ids.add(scope_id)
        return records
    except Denied:
        raise
    except (KeyError, TypeError, ValueError) as exc:
        raise Denied('BINDING_MISMATCH') from exc


def grants_for_skill(authority, skill):
    return tuple(grant for grant in iter_grants(authority) if grant['skill'] == skill)


def has_skill(authority, skill):
    return bool(grants_for_skill(authority, skill))


def grant_by_id(authority, grant_id):
    matches = [grant for grant in iter_grants(authority) if grant['grant_id'] == grant_id]
    if len(matches) > 1:
        raise Denied('BINDING_MISMATCH')
    return matches[0] if matches else None


def unique_grant(authority, skill):
    """Return the only grant for a skill. Several current grants are explicit ambiguity."""
    matches = grants_for_skill(authority, skill)
    if len(matches) > 1:
        raise Denied('AMBIGUOUS_GRANT')
    return matches[0] if matches else None


def select_grant(authority, *, skill, version, context, action, resource, grant_id=None,
                 qualification_id=None, qualification_digest=None):
    """Select one exact binding. Never take the first candidate or a wildcard resource."""
    candidates = grants_for_skill(authority, skill)
    if not candidates:
        raise Denied('REVOKED_AUTHORITY')
    context_key = canonical_digest({'environment': context})
    matches = []
    for grant in candidates:
        if grant['version'] != version or grant['action'] != action or grant['resource'] != resource:
            continue
        if grant['context'] != context or grant['context_digest'] != context_key:
            continue
        if grant_id is not None and grant['grant_id'] != grant_id:
            continue
        if qualification_id is not None and grant['qualification_id'] != qualification_id:
            continue
        if qualification_digest is not None and grant['qualification_digest'] != qualification_digest:
            continue
        matches.append(grant)
    if not matches:
        raise Denied('SCOPE_MISMATCH')
    if len(matches) != 1:
        raise Denied('BINDING_MISMATCH')
    return matches[0]


def upsert_grant(authority, new):
    """Replace the same logical slot or append a different resource. Leave the input unchanged."""
    iter_grants({'grants': [new]})
    kept = [copy.deepcopy(grant) for grant in iter_grants(authority) if slot(grant) != slot(new)]
    result = kept + [copy.deepcopy(new)]
    iter_grants({'grants': result})
    return result


def target_view(grant):
    return {key: copy.deepcopy(grant[key]) for key in _TARGET}
