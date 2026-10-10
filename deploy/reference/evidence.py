"""Bind local service checks to the exact adapter and deployment source files."""
import hashlib
from pathlib import Path


KIT = Path(__file__).resolve().parents[2]


def source_hashes():
    files = {p for pattern in ("earned_authority/*.py", "deploy/reference/*", "deploy/ledger/*.py", "tools/validate_connected.py")
             for p in KIT.glob(pattern) if p.is_file()}
    return {str(p.relative_to(KIT)): "sha256:" + hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(files)}


def bind_sources(report, before):
    report["source_hashes_before"] = before
    report["source_hashes"] = source_hashes()
    if before != report["source_hashes"]:
        report.update(execution_state="ABORTED", acceptance_color="AMBER", error="SOURCE_CHANGED_DURING_RUN")
