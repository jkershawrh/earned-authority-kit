"""Two frozen pilot policies with the same fixture qualification/enforcement.

The fixed runbook can grant only its original exact procedure/context. The
adaptive arm can qualify the requested exact binding from fresh support. This
is a declared policy contrast, not the strongest possible deterministic baseline.
Neither receives query grades or the driver's private fault reference.
"""


def prepare(runtime, comparator, request, support, base_version, base_context):
    for observation in support:
        runtime.shadow(**observation)
    version, context = (base_version, base_context) if comparator == 'fixed_deterministic' else (request['version'], request['context'])
    q = runtime.qualify(skill=request['skill'], version=version, context=context)
    if q['disposition'] == 'ELIGIBLE':
        runtime.grant(q['qualification_id'], agent=request['agent'], resource=request['resource'])
    return dict(qualification=q,
                requested_disposition=q['disposition'] if (version, context) == (request['version'], request['context']) else 'NOT_ASSESSED')
