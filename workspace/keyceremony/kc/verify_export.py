"""Offline verifier for exported ceremony records.

Usage:
    python -m kc.verify_export path/to/export.json

Exit code 0 = bundle signature, audit hash chain, lifecycle provenance and
single-current-key invariants all verified. Works on any machine with the
source code; no state directory or secrets required.
"""

from __future__ import annotations

import argparse
import json
import sys

from . import export as export_mod
from .ceremony import Orchestrator
from .storage import Store


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("bundle", nargs="?", help="path to export.json to verify")
    ap.add_argument("--from-store", metavar="ROOT",
                    help="build an export bundle from this state directory")
    ap.add_argument("--outdir",
                    help="with --from-store: write export.json/audit.txt here")
    a = ap.parse_args(argv)

    if a.from_store:
        store = Store(a.from_store)
        with store.locked():
            orch = Orchestrator(store)
            if a.outdir:
                path = export_mod.write_export(orch, a.outdir)
                print("wrote", path)
                bundle_path = path
            else:
                bundle = export_mod.build_bundle(orch)
                print(json.dumps(bundle, sort_keys=True))
                return 0
    else:
        bundle_path = a.bundle
    if not bundle_path:
        ap.error("provide an export.json path or --from-store ROOT")
    with open(bundle_path, encoding="utf-8") as f:
        bundle = json.load(f)
    v = export_mod.verify_bundle(bundle)
    for name, ok in v["checks"].items():
        if isinstance(ok, bool):
            print(f"  [{'PASS' if ok else 'FAIL'}] {name}")
        else:
            print(f"  [INFO] {name}: {ok}")
    if v["ok"]:
        print(f"VERIFIED OK ({bundle.get('format')}, "
              f"{len(bundle.get('audit', []))} audit entries)")
        return 0
    print("PROBLEMS:")
    for p in v["problems"]:
        print("  -", p)
    return 2


if __name__ == "__main__":
    sys.exit(main())
