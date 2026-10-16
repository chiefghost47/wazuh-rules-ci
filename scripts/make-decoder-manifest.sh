#!/usr/bin/env bash
# Regenerates decoders/decoder-manifest.sha256, or with --check verifies it.
#
# The manager compares the decoders it runs against this manifest on a schedule. If the
# manifest can drift from the repository, the manager reports drift that is really a stale
# manifest. So the manifest is generated, never edited, and CI verifies it on every change.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DIR="${DECODERS_DIR:-$(cd "$HERE/.." && pwd)/decoders}"
MANIFEST="$DIR/decoder-manifest.sha256"
cd "$DIR"

files=$(ls -1 ./*.xml 2>/dev/null | sed 's#^\./##' | sort)
[[ -n "$files" ]] || { echo "FAIL: no decoder files in $DIR"; exit 2; }

if [[ "${1:-}" == "--check" ]]; then
  [[ -f "$MANIFEST" ]] || { echo "FAIL: $MANIFEST missing; run $0 to create it"; exit 1; }
  sha256sum -c --quiet "$MANIFEST"
  listed=$(sed -E 's/^[0-9a-f]{64} [ *]//' "$MANIFEST" | sort)   # tolerate a binary-mode "*" marker
  if [[ "$listed" != "$files" ]]; then
    echo "FAIL: manifest and decoder set disagree; regenerate the manifest"
    diff <(echo "$listed") <(echo "$files") || true
    exit 1
  fi
  echo "OK: manifest covers all $(echo "$files" | wc -l) decoder files"
else
  # shellcheck disable=SC2086  # word splitting on file names is intended
  sha256sum --text $files > "$MANIFEST"   # text mode: same " name" format on every platform
  echo "wrote $MANIFEST ($(echo "$files" | wc -l) files)"
fi
