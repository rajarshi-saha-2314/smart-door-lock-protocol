#!/usr/bin/env bash
# Run every ProVerif model in formal/ and save the full output to formal/results.txt.
#
# Install ProVerif first, one of:
#   sudo apt-get install -y proverif            (Debian/Ubuntu)
#   opam install proverif                       (any OS with opam)
#   Windows: unpack the official binary package proverifbin2.05.tar.gz from
#            https://bblanche.gitlabpages.inria.fr/proverif/ and set PROVERIF=/path/to/proverif.exe
set -euo pipefail
cd "$(dirname "$0")"

PV="${PROVERIF:-}"
if [[ -z "$PV" ]]; then
  if command -v proverif >/dev/null 2>&1; then
    PV=proverif
  else
    for cand in "$HOME"/tools/proverif/proverif*/proverif.exe "$HOME"/tools/proverif/proverif*/proverif; do
      [[ -x "$cand" ]] && PV="$cand" && break
    done
  fi
fi
if [[ -z "$PV" ]]; then
  echo "ProVerif not found. Install it (see the header of this script) or set PROVERIF=/path/to/proverif" >&2
  exit 1
fi

OUT=results.txt
{
  echo "ProVerif results - generated $(date -u +%Y-%m-%dT%H:%M:%SZ) by formal/run_proverif.sh"
  echo "Binary: $PV ($("$PV" -help 2>&1 | head -n 1 || true))"
  echo
} > "$OUT"

SUMMARY=""
for model in door_lock.pv guessing_stolen_card.pv guessing_stolen_card_original.pv; do
  echo "=== $model ===" | tee -a "$OUT"
  "$PV" "$model" > "$model.log" 2>&1 || true
  cat "$model.log" >> "$OUT"
  echo >> "$OUT"
  grep -E "^RESULT|Error|error" "$model.log" || true
  SUMMARY+="$(grep -E "^RESULT" "$model.log" | sed "s/^/[$model] /" || true)"$'\n'
  rm -f "$model.log"
done

printf '=== Summary ===\n%s\n' "$SUMMARY" >> "$OUT"
printf '\n=== Summary ===\n%s\n' "$SUMMARY"
echo "Full output written to formal/$OUT"
