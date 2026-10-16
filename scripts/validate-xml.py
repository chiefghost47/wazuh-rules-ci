#!/usr/bin/env python3
"""Repository-side checks for Wazuh rule files. Standard library only.

Fails (exit 1) when any rule file is not well-formed XML, holds no <rule>, has a rule
without a numeric id, when an id repeats across files, or when an id falls outside the
range this repository owns (RULE_ID_MIN..RULE_ID_MAX, both inclusive).

This proves the XML is sound and the ids are unique. It does NOT prove the engine will
load the rules; the workflow's last step does that.
"""
from __future__ import annotations

import os
import sys
import xml.etree.ElementTree as ET
from collections import Counter
from pathlib import Path

RULES_DIR = Path(os.environ.get("RULES_DIR", "rules"))
ID_MIN = int(os.environ.get("RULE_ID_MIN", "100100"))  # keep in step with the workflow env
ID_MAX = int(os.environ.get("RULE_ID_MAX", "100999"))


def main() -> int:
    files = sorted(p for p in RULES_DIR.glob("*.xml"))
    if not files:
        print(f"FAIL: no rule files under {RULES_DIR}/", file=sys.stderr)
        return 1

    occurrences: list[tuple[int, str]] = []
    failures = 0
    for path in files:
        content = path.read_text(encoding="utf-8-sig")
        try:
            # A Wazuh rule file may hold several top-level <group> elements, so wrap it.
            root = ET.fromstring(f"<wazuh_rules>{content}</wazuh_rules>")
        except ET.ParseError as exc:
            print(f"FAIL: {path}: not well-formed XML: {exc}", file=sys.stderr)
            failures += 1
            continue
        rules = root.findall(".//rule")
        if not rules:
            print(f"FAIL: {path}: no <rule> elements", file=sys.stderr)
            failures += 1
            continue
        for rule in rules:
            raw = rule.get("id")
            if not raw or not raw.isdigit():
                print(f"FAIL: {path}: rule with invalid id {raw!r}", file=sys.stderr)
                failures += 1
                continue
            rule_id = int(raw)
            if not ID_MIN <= rule_id <= ID_MAX:
                print(
                    f"FAIL: {path}: rule {rule_id} is outside this repository's range "
                    f"{ID_MIN}-{ID_MAX}",
                    file=sys.stderr,
                )
                failures += 1
            occurrences.append((rule_id, str(path)))
        print(f"ok  {path} ({len(rules)} rules)")

    counts = Counter(rule_id for rule_id, _ in occurrences)
    for rule_id in sorted(i for i, n in counts.items() if n > 1):
        where = sorted({p for i, p in occurrences if i == rule_id})
        print(f"FAIL: rule id {rule_id} appears in more than one file: {where}", file=sys.stderr)
        failures += 1

    if failures:
        print(f"FAIL: {failures} problem(s)", file=sys.stderr)
        return 1
    print(f"validated {len(files)} files, {len(occurrences)} unique rule ids in {ID_MIN}-{ID_MAX}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
