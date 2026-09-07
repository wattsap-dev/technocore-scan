#!/usr/bin/env python3
"""What is actually happening in /r/faucet.

The room is at seq 3.5M and every message is "FLOP testnet faucet claim" with a
did:key. There is no testnet: flop-labs has three public repositories and none
of them is one, and the tokenomics AMA put the faucet after a testnet that has
not opened. So this is 3.5 million signed claims against a faucet that does not
exist, and the question worth answering is whether that is many agents or one
operator with many keys -- the AMA said mass DID creation earns nothing and that
fake traffic risks a 100% slash, so the difference matters to whoever is doing it.
"""
import collections, json, time, urllib.request

BASE = "https://technocore.chat"


def get(p, timeout=240, tries=5):
    for _ in range(tries):
        try:
            with urllib.request.urlopen(BASE + p, timeout=timeout) as r:
                return r.read().decode("utf-8", "replace")
        except Exception:
            time.sleep(5)
    return None


page = json.loads(get("/r/faucet?limit=200&format=json", 40))
print("room head seq : %s" % page["last_seq"])
print("generation    : %s" % page.get("generation"))

raw = get("/r/faucet/export")
if not raw:
    print("export unreachable"); raise SystemExit(1)

ms = []
for line in raw.splitlines():
    line = line.strip()
    if line:
        try:
            ms.append(json.loads(line))
        except Exception:
            continue

print("ring          : %d messages, seq %d..%d" % (len(ms), ms[0]["seq"], ms[-1]["seq"]))

import datetime as dt
f = lambda s: dt.datetime.fromisoformat(s.replace("Z", "+00:00"))
span = (f(ms[-1]["ts"]) - f(ms[0]["ts"])).total_seconds()
print("ring span     : %.1f minutes  -> %.1f messages/second" % (span / 60, len(ms) / max(1, span)))

import re

# Extract the DID by its own grammar, not by position. Splitting on "DID:" and
# taking the tail only yields a bare DID when the DID is the LAST thing on the
# line; the room carries over a hundred templates and most put it first, so
# that split measured text layout and called it identity. The [:64] truncation
# compounded it -- a did:key is 56-58 characters, so 64 silently appended
# whatever prose followed.
DIDRE = re.compile(r"did:key:z[1-9A-HJ-NP-Za-km-z]{40,60}")

writers = collections.Counter(m.get("from", "?") for m in ms)
claimed = collections.Counter()
for m in ms:
    hit = DIDRE.search(m.get("text", ""))
    if hit:
        claimed[hit.group(0)] += 1

print()
print("distinct WRITERS (the signing key)  : %d" % len(writers))
print("distinct DIDs named in the text     : %d" % len(claimed))
print()
print("top writers:")
for did, n in writers.most_common(6):
    print("   %-46s %6d  (%.1f%% of the ring)" % (did[:46], n, 100.0 * n / len(ms)))

same = mismatch = neither = 0
for m in ms:
    hit = DIDRE.search(m.get("text", ""))
    if not hit:
        neither += 1
    elif hit.group(0) == m.get("from", ""):
        same += 1
    else:
        mismatch += 1
print()
print("messages naming a did:key in the text            : %d" % (same + mismatch))
print("  ... where that DID is the signing key          : %d (%.1f%%)"
      % (same, 100.0 * same / max(1, same + mismatch)))
print("  ... where it names someone else                : %d" % mismatch)
print("  no did:key in the text at all                  : %d" % neither)

tmpl = collections.Counter(
    DIDRE.sub("<did>", " ".join(m.get("text", "").split()))[:90] for m in ms)
print()
print("distinct message templates (DID elided): %d" % len(tmpl))
for t, n in tmpl.most_common(4):
    print("   x%-6d %s" % (n, t))
print()
if len(writers) < len(ms) * 0.05:
    print("=> a small number of keys is writing the whole room: this is one")
    print("   operation, not a crowd.")
else:
    print("=> the writers are almost as numerous as the messages: mass identity")
    print("   creation, one claim each.")
extrapolated = ms[-1]["seq"]
print()
print("claims implied by the seq counter, all time: ~%s" % f"{extrapolated:,}")
