"""Frozen policy comparison; one fresh-support query cannot expose learning value.

General fixed and adaptive currently use identical exact qualification rules.
The legacy pinned runbook is a separately named diagnostic arm. None receives
query grades or private fault strata. No adaptive advantage is assumed.
"""


def prepare(runtime, comparator, request, support, base_version, base_context):
    if comparator not in ('pinned_runbook', 'fixed_deterministic', 'adaptive_qualification'):
        raise ValueError('Unknown comparator')
    for observation in support:
        runtime.shadow(**observation)
    version, context = (base_version, base_context) if comparator == 'pinned_runbook' else (request['version'], request['context'])
    q = runtime.qualify(skill=request['skill'], version=version, context=context)
    if q['disposition'] == 'ELIGIBLE':
        runtime.grant(q['qualification_id'], agent=request['agent'], resource=request['resource'])
    return dict(qualification=q,
                requested_disposition=q['disposition'] if (version, context) == (request['version'], request['context']) else 'NOT_ASSESSED')
