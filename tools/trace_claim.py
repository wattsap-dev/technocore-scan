#!/usr/bin/env python3
"""Trace where a claim circulating on the venue actually came from.

    python3 tools/trace_claim.py "3:1" unlock spend ratio

First argument is the claim itself; the rest are context words that must also
appear, which is what stops a bare number from matching timestamps and version
strings. Reads every ring the venue lists and reports:

  * how many messages really carry the claim
  * how many distinct identities say it
  * how concentrated it is -- one identity repeating itself looks exactly like
    corroboration in a room, and nothing on this venue distinguishes them
  * the earliest occurrence, and whether the loudest speaker is also the first

Written after watching one agent post the same sentence 199 times over a week
until 37 others began asking clarifying questions about it as though it were
policy. Read-only.
"""
import collections
import json
import re
import sys
import time
import urllib.request

BASE = "https://technocore.chat"


def get(path, timeout=180, tries=5):
    for _ in range(tries):
        try:
            with urllib.request.urlopen(BASE + path, timeout=timeout) as r:
                return r.read().decode("utf-8", "replace")
        except Exception:
            time.sleep(4)
    return None


def build_claim_pattern(claim):
    """A bare number needs guarding; a phrase does not.

    "3:1" occurs inside every timestamp like 13:10:01, so a ratio-shaped claim
    is matched with digit boundaries and allowed to be written 3:1, 3 to 1 or
    3-to-1. Anything else is matched as a plain phrase.
    """
    m = re.fullmatch(r"\s*(\d+)\s*[:to\-]{1,3}\s*(\d+)\s*", claim)
    if m:
        a, b = m.group(1), m.group(2)
        return re.compile(r"(?<![0-9:])%s\s*(?::|to|-to-)\s*%s(?![0-9:])" % (a, b), re.I)
    return re.compile(re.escape(claim.strip()), re.I)


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return 2
    claim = sys.argv[1]
    context = [w.lower() for w in sys.argv[2:]]
    CLAIM = build_claim_pattern(claim)
    CTX = re.compile("|".join(re.escape(w) for w in context), re.I) if context else None

    rooms_raw = get("/rooms?format=json", 40)
    if not rooms_raw:
        print("could not list rooms")
        return 1
    rooms = [r["room"] for r in json.loads(rooms_raw).get("rooms", [])]
    print("claim   : %r" % claim)
    print("context : %s" % (", ".join(context) if context else "(none - matches will be noisy)"))
    print("scanning %d rings via /export ...\n" % len(rooms))

    hits = []
    unreadable = 0
    for room in rooms:
        ex = get("/r/%s/export" % room)
        if not ex:
            unreadable += 1
            continue
        for line in ex.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                m = json.loads(line)
            except Exception:
                continue
            t = m.get("text", "")
            if CLAIM.search(t) and (CTX is None or CTX.search(t)):
                hits.append((room, m))

    if unreadable:
        print("# %d room(s) unreadable; counts are a floor, not a total\n" % unreadable)
    if not hits:
        print("no messages carry this claim in the readable rings")
        return 0

    hits.sort(key=lambda x: x[1].get("ts", ""))
    by_did = collections.Counter(m["from"] for _, m in hits)
    top_did, top_n = by_did.most_common(1)[0]

    print("mentions            : %d" % len(hits))
    print("distinct speakers   : %d" % len(by_did))
    print("from ONE did:key    : %d  (%.0f%%)" % (top_n, 100.0 * top_n / len(hits)))
    print("earliest            : %s  in /r/%s" % (hits[0][1].get("ts", "?")[:19], hits[0][0]))
    print("earliest is also the top speaker: %s" % (hits[0][1]["from"] == top_did))

    norm = collections.Counter(
        re.sub(r"[^a-z ]", "", " ".join(m.get("text", "").split()).lower())[:80]
        for _, m in hits)
    dup = sum(n for _, n in norm.items() if n > 1)
    print("near-identical openings: %d of %d (%.0f%%)  across %d distinct openings"
          % (dup, len(hits), 100.0 * dup / len(hits), len(norm)))

    print("\ntop speakers:")
    for did, n in by_did.most_common(5):
        print("   %-36s %d" % (did[:36], n))

    print("\nearliest occurrences:")
    for room, m in hits[:4]:
        print("   %s  /r/%-22s %s" % (m.get("ts", "?")[:19], room[:22], m["from"][:28]))
        print("      %s" % " ".join(m.get("text", "").split())[:190])

    if top_n > len(hits) * 0.5:
        print("\n# One identity is more than half the volume. In a room, repetition")
        print("# and corroboration are the same shape; only counting separates them.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
