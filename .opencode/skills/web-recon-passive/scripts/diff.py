"""Baseline diff for ravan report JSON. Stdlib only, offline.

Compares two finding lists (old, new) by finding id and emits
new / fixed / persisting / regressed sets.

Usage:
  python scripts/diff.py old.json new.json [--out diff.json]
"""
import json
import sys
from pathlib import Path


def diff(old, new):
    o = {f["id"]: f for f in old}
    n = {f["id"]: f for f in new}
    return {
        "new": [f for i, f in n.items() if i not in o],
        "fixed": [f for i, f in o.items() if i not in n],
        "persisting": [f for i, f in n.items() if i in o],
    }


def main(argv):
    old = json.loads(Path(argv[1]).read_text())
    new = json.loads(Path(argv[2]).read_text())
    res = diff(old if isinstance(old, list) else [old],
               new if isinstance(new, list) else [new])
    summary = {k: len(v) for k, v in res.items()}
    if "--out" in argv:
        Path(argv[argv.index("--out") + 1]).write_text(json.dumps(res, indent=2))
    print(json.dumps(summary))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
