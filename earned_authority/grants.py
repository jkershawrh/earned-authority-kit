"""Complete grant iteration and exact selection; these helpers grant no authority."""
import copy
from .contracts import canonical_digest
from .runtime import Denied


def grant_slot(grant):
    return tuple(grant[k] for k in ('skill', 'action', 'resource', 'context_digest'))


def iter_grants(authority):
    """Read all connected grants or every entry in the single-resource fixture."""
    try:
        raw = authority['grants']
        if isinstance(raw, dict):
            if any(key != g['skill'] for key, g in raw.items()):
                raise ValueError('fixture skill key mismatch')
            records = tuple(raw.values())
        elif isinstance(raw, list):
            records = tuple(raw)
        else:
            raise ValueError('invalid grant collection')
        ids, scopes, slots = set(), set(), set()
        for grant in records:
            for field in ('grant_id', 'skill', 'version', 'action', 'resource',
                          'qualification_id', 'qualification_digest', 'policy_digest'):
                if not isinstance(grant[field], str) or not grant[field]:
                    raise ValueError('invalid binding field')
            if type(grant['expires_at_ms']) is not int:
                raise ValueError('invalid grant binding')
            if grant['context_digest'] != canonical_digest({'environment': grant['context']}):
                raise ValueError('context digest mismatch')
            if grant['skill_digest'] != canonical_digest({'skill': grant['skill'], 'version': grant['version']}):
                raise ValueError('skill digest mismatch')
            slot = grant_slot(grant)
            if grant['grant_id'] in ids or slot in slots:
                raise ValueError('duplicate grant or slot')
            ids.add(grant['grant_id']); slots.add(slot)
            if 'canonical_scope_id' in grant:
                sid = grant['canonical_scope_id']
                if not isinstance(sid, str) or not sid or sid in scopes:
                    raise ValueError('duplicate or invalid canonical scope id')
                scopes.add(sid)
        return records
    except (KeyError, TypeError, ValueError) as exc:
        raise Denied('BINDING_MISMATCH') from exc


def grants_for_skill(authority, skill):
    return tuple(g for g in iter_grants(authority) if g['skill'] == skill)


def has_skill(authority, skill):
    return bool(grants_for_skill(authority, skill))


def grant_by_id(authority, grant_id):
    return next((g for g in iter_grants(authority) if g['grant_id'] == grant_id), None)


def unique_grant(authority, skill):
    records = grants_for_skill(authority, skill)
    if len(records) > 1:
        raise Denied('AMBIGUOUS_GRANT')
    return records[0] if records else None


def select_grant(authority, *, skill, version, context, action, resource, grant_id=None):
    records = grants_for_skill(authority, skill)
    if not records:
        raise Denied('REVOKED_AUTHORITY')
    try:
        context_digest = canonical_digest({'environment': context})
    except ValueError as exc:
        raise Denied('SCOPE_MISMATCH') from exc
    matches = [g for g in records if g['version'] == version and g['context_digest'] == context_digest
               and g['action'] == action and g['resource'] == resource
               and (grant_id is None or g['grant_id'] == grant_id)]
    if not matches:
        raise Denied('SCOPE_MISMATCH')
    if len(matches) != 1:
        raise Denied('AMBIGUOUS_GRANT')
    return matches[0]


def upsert_grant(authority, grant):
    iter_grants({'grants': [grant]})
    records = [copy.deepcopy(g) for g in iter_grants(authority) if grant_slot(g) != grant_slot(grant)]
    records.append(copy.deepcopy(grant))
    iter_grants({'grants': records})
    return records
