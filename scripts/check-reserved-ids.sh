#!/usr/bin/env bash
# Fails when a repository rule id is already taken by a rule that lives only on the manager.
#
# The manager would reject such a rule as a duplicate at deploy time, after every
# repository-side check had passed. rules/reserved-rule-ids.txt is the repository's view of
# that namespace: one id or one inclusive range (a-b) per line, '#' comments allowed. Export
# it from the manager and keep it current; this check only knows what you tell it.
#
# Rule ids are read with an XML parser (the same wrapping as validate-xml.py), so quoting,
# attribute order, whitespace and multi-line start tags cannot hide an id from this check.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
RULES_DIR="${RULES_DIR:-$ROOT/rules}"
MANIFEST="${RESERVED_IDS:-$RULES_DIR/reserved-rule-ids.txt}"

[[ -f "$MANIFEST" ]] || { echo "FAIL: reserved-id list not found at $MANIFEST"; exit 2; }

# Every non-blank, non-comment line must be an id or an ascending range; anything else fails.
reserved=$(
  lineno=0; bad=0
  while IFS= read -r raw || [[ -n "$raw" ]]; do
    lineno=$((lineno + 1))
    line=${raw%%#*}; line=${line//[[:space:]]/}; line=${line//$'\r'/}
    [[ -z "$line" ]] && continue
    if [[ "$line" =~ ^([0-9]+)-([0-9]+)$ ]]; then
      a=${BASH_REMATCH[1]}; b=${BASH_REMATCH[2]}
      if (( 10#$a > 10#$b )); then echo "FAIL: $MANIFEST:$lineno: reversed range '$line'" >&2; bad=1; continue; fi
      seq "$a" "$b"
    elif [[ "$line" =~ ^[0-9]+$ ]]; then
      echo "$line"
    else
      echo "FAIL: $MANIFEST:$lineno: not an id or a-b range: '$line'" >&2; bad=1
    fi
  done < "$MANIFEST"
  (( bad == 0 )) || exit 3
) || { echo "FAIL: reserved-id list has invalid entries"; exit 2; }
reserved=$(printf '%s\n' "$reserved" | sed '/^$/d' | sort -un)

repo_ids=$(RULES_DIR="$RULES_DIR" python3 - <<'PY'
import os, sys
import xml.etree.ElementTree as ET
from pathlib import Path
ids = set()
for path in sorted(Path(os.environ["RULES_DIR"]).glob("*.xml")):
    root = ET.fromstring("<wazuh_rules>" + path.read_text(encoding="utf-8-sig") + "</wazuh_rules>")
    for rule in root.iter("rule"):
        raw = rule.get("id", "")
        if not raw.isdigit():
            sys.exit(f"FAIL: {path}: rule with non-numeric id {raw!r}")
        ids.add(int(raw))
if not ids:
    sys.exit("FAIL: no rule ids found")
print("\n".join(str(i) for i in sorted(ids)))
PY
)

collisions=$(comm -12 <(printf '%s\n' "$repo_ids") <(printf '%s\n' "$reserved") || true)
if [[ -n "$collisions" ]]; then
  echo "FAIL: repository rule ids collide with ids reserved on the manager:"
  while IFS= read -r id; do echo "  $id  (defined by a rule file the manager has and this repository does not)"; done <<<"$collisions"
  echo "Pick free ids. Check the list against the manager before assigning a new block."
  exit 1
fi
echo "OK: $(printf '%s\n' "$repo_ids" | grep -c .) repository rule ids, 0 collisions with $(printf '%s\n' "$reserved" | grep -c .) reserved ids"
