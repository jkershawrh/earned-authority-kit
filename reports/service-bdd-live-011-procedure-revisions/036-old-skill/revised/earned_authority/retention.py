"""Local receipt archive compaction.

Cited receipts are those embedded in an applied authority-journal operation or a
local event. Compaction may remove other disposable archive rows. It never
removes a cited receipt. Growth of cited receipts stays unbounded.
"""
import json
from .contracts import canonical_digest
from .runtime import Denied


def _ensure(db):
    db.execute('CREATE TABLE IF NOT EXISTS receipt_archive(receipt_id TEXT PRIMARY KEY, body TEXT NOT NULL, disposable INTEGER NOT NULL)')


def _identity(receipt):
    if not isinstance(receipt, dict):
        raise Denied('INVALID_OPERATION_RECEIPT')
    try:
        return canonical_digest(receipt)
    except ValueError as exc:
        raise Denied('INVALID_OPERATION_RECEIPT') from exc


def cited_receipt_ids(runtime, db):
    cited = set()
    for operation in runtime._read_authority_operations(db):
        receipt = operation.get('receipt')
        if operation['state'] == 'APPLIED' and receipt:
            cited.add(_identity(receipt))
    for body_raw, receipt_raw in db.execute('SELECT body, receipt FROM events'):
        if receipt_raw:
            cited.add(_identity(json.loads(receipt_raw)))
        body = json.loads(body_raw)
        embedded = body.get('operation_receipt') if isinstance(body, dict) else None
        if embedded:
            cited.add(_identity(embedded))
    return cited


def retain_receipt(runtime, receipt, *, disposable):
    if type(disposable) is not bool:
        raise Denied('INVALID_OPERATION_RECEIPT')
    rid = _identity(receipt)
    with runtime._tx() as db:
        _ensure(db)
        row = db.execute('SELECT body, disposable FROM receipt_archive WHERE receipt_id=?', (rid,)).fetchone()
        encoded = json.dumps(receipt, sort_keys=True)
        if row:
            if json.loads(row[0]) != receipt:
                raise Denied('INVALID_OPERATION_RECEIPT')
            if row[1] == 0:
                return rid
            if not disposable:
                db.execute('UPDATE receipt_archive SET disposable=0 WHERE receipt_id=?', (rid,))
        else:
            db.execute('INSERT INTO receipt_archive VALUES (?,?,?)', (rid, encoded, int(disposable)))
    return rid


def compact_receipts(runtime, drop_ids=None):
    """Remove disposable archive rows that no applied operation or local event cites.

    An explicit drop list that includes a cited receipt is refused and removes nothing.
    """
    with runtime._tx() as db:
        _ensure(db)
        cited = cited_receipt_ids(runtime, db)
        if drop_ids is None:
            chosen = [rid for rid, flag in db.execute('SELECT receipt_id, disposable FROM receipt_archive') if flag and rid not in cited]
        else:
            if type(drop_ids) not in (list, tuple) or any(type(rid) is not str or not rid for rid in drop_ids):
                raise Denied('INVALID_OPERATION_RECEIPT')
            chosen = list(drop_ids)
            if set(chosen) & cited:
                raise Denied('RECEIPT_STILL_CITED')
        removed = []
        for rid in chosen:
            if rid in cited:
                raise Denied('RECEIPT_STILL_CITED')
            cursor = db.execute('DELETE FROM receipt_archive WHERE receipt_id=? AND disposable=1', (rid,))
            if cursor.rowcount:
                removed.append(rid)
        archive = {rid: json.loads(body) for rid, body in db.execute('SELECT receipt_id, body FROM receipt_archive')}
        return {'removed': removed, 'cited': sorted(cited), 'archive': archive}
