"""Two real deterministic lookup procedures with host-owned read instrumentation."""
import copy


def metered_catalog(records):
    # Procedures get read access; execute retains the actual trace in a closure.
    frozen=copy.deepcopy(records);trace=[]
    class CatalogView:
        __slots__=()
        def __len__(self): return len(frozen)
        def __getitem__(self,index):
            trace.append(index)
            return dict(frozen[index])
    return CatalogView(),trace


def scan_forward(catalog,key):
    for index in range(len(catalog)):
        record=catalog[index]
        if record['key']==key: return record['model']
    return None


def scan_reverse(catalog,key):
    for index in range(len(catalog)-1,-1,-1):
        record=catalog[index]
        if record['key']==key: return record['model']
    return None


def execute(direction,records,key):
    if direction not in ('forward','reverse'): raise ValueError('Unknown procedure')
    meter,trace=metered_catalog(records)
    model=(scan_forward if direction=='forward' else scan_reverse)(meter,key)
    return dict(model=model,reads=len(trace),trace=list(trace))


def check_reads(direction,records,key,result):
    """Check the host trace against independently located unique catalog position."""
    try:
        if direction not in ('forward','reverse') or not isinstance(records,list) or not records: return False
        if any(not isinstance(x,dict) or type(x.get('key')) is not str or type(x.get('model')) is not str for x in records): return False
        if len({x['key'] for x in records})!=len(records): return False
        positions=[i for i,row in enumerate(records) if row['key']==key]
        if len(positions)!=1: return False
        index=positions[0]
        expected=list(range(index+1)) if direction=='forward' else list(range(len(records)-1,index-1,-1))
        trace=result['trace']
        return (isinstance(trace,list) and all(type(i) is int for i in trace) and trace==expected
                and type(result['reads']) is int and result['reads']==len(trace)
                and result['model']==records[index]['model'])
    except (KeyError,TypeError): return False
