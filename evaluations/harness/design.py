"""Closed pilot design and explicit ancestry checks."""
STRATA = ('stable', 'new_version', 'new_context', 'known_failure', 'unknown_support',
          'revoked_before_commit', 'expired_before_commit', 'authority_outage',
          'ledger_outage', 'wrong_postcondition')


def audit_partitions(families):
    owner, ids = {}, set()
    for family in families:
        if not isinstance(family.get('family_id'), str) or not family['family_id']:
            raise ValueError('Explicit family identity required')
        if family['family_id'] in ids:
            raise ValueError('Duplicate family identity')
        ids.add(family['family_id'])
        if family['split'] not in ('development', 'calibration', 'held_out'):
            raise ValueError('Unknown split')
        for kind in ('procedure_ancestors', 'context_ancestors'):
            values = family.get(kind)
            if not isinstance(values, list) or not values or any(not isinstance(v, str) or not v for v in values):
                raise ValueError('Missing ancestry')
            for ancestor in values:
                if (kind, ancestor) in owner and owner[kind, ancestor] != family['split']:
                    raise ValueError('Family ancestry leakage')
                owner[kind, ancestor] = family['split']
    return True


def validate_manifest(manifest):
    if manifest.get('mode') != 'DEVELOPMENT_PILOT' or manifest.get('split') != 'development':
        raise ValueError('Confirmatory execution is not implemented; pilot requires development families')
    if manifest.get('comparators') != ['fixed_deterministic', 'adaptive_qualification']:
        raise ValueError('Only the two declared automatic pilot arms are implemented')
    seeds = manifest.get('seeds')
    if not seeds or any(type(s) is not int or s < 0 for s in seeds) or len(seeds) != len(set(seeds)):
        raise ValueError('Unique nonnegative integer seeds required')
    if manifest.get('strata') != list(STRATA):
        raise ValueError('All declared pilot strata required in fixed order')
    if type(manifest.get('deadline_ms')) is not int or manifest['deadline_ms'] <= 0 or type(manifest.get('retry_budget')) is not int or manifest['retry_budget'] != 0:
        raise ValueError('Positive integer deadline and zero retry budget required')
    families = manifest.get('families', [])
    if len(families) != len(STRATA) or {f.get('stratum') for f in families} != set(STRATA):
        raise ValueError('One family per stratum required')
    if any(f.get('split') != 'development' for f in families):
        raise ValueError('No held-out or calibration execution in development pilot')
    audit_partitions(families)
    return manifest
