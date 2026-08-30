#!/bin/zsh
# Append one sweep sample to the time series.
#
# `sweep` is a snapshot: it says what a room's readable history is right now.
# The interesting question is how that moves — the service's counters went from
# 8,348 rooms to 42,118 in a day, and lobby's readable history halved from 7
# seconds to 3.6 in an afternoon. A snapshot cannot show that; a series can.
#
# Read-only against the service. Writes only to data/sweep.jsonl.

set -u

DIR="${0:A:h:h}"          # repo root
DATA="$DIR/data"
OUT="$DATA/sweep.jsonl"
TMP="$(mktemp)"

mkdir -p "$DATA"

if /usr/bin/python3 "$DIR/technocore_scan.py" sweep --jsonl > "$TMP" 2>/dev/null && [[ -s "$TMP" ]]; then
    # only accept a sample that actually parses as JSON lines
    if /usr/bin/python3 -c '
import json,sys
n=0
for line in open(sys.argv[1]):
    line=line.strip()
    if line:
        json.loads(line); n+=1
sys.exit(0 if n else 1)
' "$TMP" 2>/dev/null; then
        cat "$TMP" >> "$OUT"
        print "$(date -u +%Y-%m-%dT%H:%M:%SZ) ok $(wc -l < "$TMP" | tr -d ' ') rows" >> "$DATA/collect.log"
    else
        print "$(date -u +%Y-%m-%dT%H:%M:%SZ) skipped: unparseable sample" >> "$DATA/collect.log"
    fi
else
    print "$(date -u +%Y-%m-%dT%H:%M:%SZ) skipped: sweep produced nothing" >> "$DATA/collect.log"
fi

rm -f "$TMP"

# keep the collector log bounded; the series itself is the point, so it grows
if [[ -f "$DATA/collect.log" ]] && (( $(wc -l < "$DATA/collect.log") > 500 )); then
    tail -250 "$DATA/collect.log" > "$DATA/collect.log.tmp" && mv "$DATA/collect.log.tmp" "$DATA/collect.log"
fi

# --- publish ---------------------------------------------------------------
# Append hourly, publish daily. The series is only worth something in public.
zsh "$DIR/tools/publish_sweep.sh" 2>/dev/null
