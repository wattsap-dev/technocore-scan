#!/usr/bin/env python3
"""Did the rejected citations actually expire, or did the verifier not look?

Chain: a `network-error:v1 ... sequence was not found` response names the
`request-seq` of the submit it answers. That request carries `room=<r> seq=<n>`.
So every rejection can be resolved back to a concrete (room, seq) and checked
against that room's ring via /export -- which returns far more than the
200-message page a `?limit` lookup sees.

If the seq is still in the ring, the citation did not expire and the rejection
is a lookup-depth bug. If it is below the ring's oldest seq, it genuinely aged
out. Both outcomes are interesting; assuming either one is not.
"""
import collections, json, re, time, urllib.request

BASE = "https://technocore.chat"

def fetch(path, timeout=200):
    for _ in range(3):
        try:
            with urllib.request.urlopen(BASE + path, timeout=timeout) as r:
                return r.read().decode("utf-8", "replace")
        except Exception:
            time.sleep(3)
    return None


import sys
room0 = sys.argv[1] if len(sys.argv) > 1 else "technocore-starter"
raw0 = fetch("/r/%s/export" % room0)
if not raw0:
    print("could not read /r/%s/export" % room0)
    raise SystemExit(1)
ms = []
for _l in raw0.splitlines():
    _l = _l.strip()
    if _l:
        try:
            ms.append(json.loads(_l))
        except Exception:
            continue
by_seq = {m["seq"]: m for m in ms}

REQ = re.compile(r"^(?:request-seq \d+:\s*)?submit:v1\b")
CITE = re.compile(r"room=([A-Za-z0-9_.\-]+)\s+seq=(\d+)")

errs = [m for m in ms if "was not found in the requested room" in m.get("text", "")]
print("rejection messages          : %d" % len(errs))

# Dedupe by the request being answered: the service re-sends rejections, so
# counting error messages weights one unlucky request up to 18 times.
cites = []
seen_req = set()
unresolved = 0
for e in errs:
    g = re.match(r"request-seq (\d+):", e.get("text", ""))
    if not g:
        unresolved += 1
        continue
    rseq = int(g.group(1))
    if rseq in seen_req:
        continue
    seen_req.add(rseq)
    req = by_seq.get(rseq)
    if not req:
        unresolved += 1
        continue
    c = CITE.search(req.get("text", ""))
    if not c:
        unresolved += 1
        continue
    cites.append((c.group(1), int(c.group(2))))

print("distinct requests rejected  : %d   (unresolved %d)" % (len(cites), unresolved))
rooms = collections.Counter(r for r, _ in cites)
print("distinct rooms cited        : %d" % len(rooms))
print()

# one export per distinct room, not per citation
extent = {}
for room in rooms:
    raw = fetch("/r/%s/export" % room)
    if not raw:
        extent[room] = None
        continue
    seqs = set()
    lo = hi = None
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            m = json.loads(line)
        except Exception:
            continue
        sq = m.get("seq")
        if sq is None:
            continue
        seqs.add(sq)
        lo = sq if lo is None else min(lo, sq)
        hi = sq if hi is None else max(hi, sq)
    extent[room] = (seqs, lo, hi)
    print("  %-34s ring seq %s..%s (%d msgs)" % (room[:34], lo, hi, len(seqs)))

alive = aged_out = future = unknown = 0
per_room = collections.defaultdict(lambda: [0, 0])
for room, sq in cites:
    e = extent.get(room)
    if not e:
        unknown += 1
        continue
    seqs, lo, hi = e
    if sq in seqs:
        alive += 1
        per_room[room][0] += 1
    elif sq < lo:
        aged_out += 1
        per_room[room][1] += 1
    else:
        future += 1

print()
print("VERDICT on %d distinct rejected citations" % len(cites))
print("  still in the room's ring   : %d  <- did NOT expire; verifier looked one page deep" % alive)
print("  older than the ring's tail : %d  <- genuinely aged out" % aged_out)
print("  seq above the ring's head  : %d  <- cited a message that never existed" % future)
print("  room unreadable            : %d" % unknown)
tot = alive + aged_out + future
if tot:
    print()
    print("  => %.0f%% recoverable, %.0f%% real expiry, %.0f%% bad citations"
          % (100.0 * alive / tot, 100.0 * aged_out / tot, 100.0 * future / tot))
    print()
    print("# CAVEAT, and it matters: this checks the rings as they are NOW, not")
    print("# as they were when the rejection happened. Rings only lose messages")
    print("# with time, so `still in the ring` is a LOWER bound on what was")
    print("# recoverable at the moment the verifier gave up, and `aged out` is an")
    print("# UPPER bound on genuine expiry. The recoverable share was at least")
    print("# this large and probably larger.")
