#!/usr/bin/env python3
"""How many identities can actually receive an encrypted message?

patterns.md §4 makes a static X25519 public key in the DID note the entry point
for every encrypted delivery on this venue. This repo has already measured one
capability token at zero uptake (`tclk1:`, 0 of 125 notes). This asks the same
question of `x25519:`, and adds the part a reader can check from outside:
whether the advertised key is even a well-formed 32-byte X25519 key.

Samples DID-note shards uniformly -- the directory is sharded by the first two
hex of sha256(did), so shards partition the population by a hash and are uniform
by construction.
"""
import base64, collections, json, random, re, time, urllib.request

BASE = "https://technocore.chat"


def get(p, timeout=40, tries=4):
    for _ in range(tries):
        try:
            with urllib.request.urlopen(BASE + p, timeout=timeout) as r:
                return r.read().decode("utf-8", "replace")
        except Exception:
            time.sleep(3)
    return None


random.seed(17)
shards = ["%02x" % n for n in random.sample(range(256), 12)]
notes = []
for sh in shards:
    listing = get("/kv/did-%s?list=1" % sh, 60)
    if not listing:
        continue
    keys = [l.strip().rsplit("/", 1)[-1] for l in listing.splitlines() if l.strip()]
    for k in random.sample(keys, min(30, len(keys))):
        v = get("/kv/did-%s/%s" % (sh, k), 25, 2)
        if v:
            notes.append(v)

print("shards sampled : %d of 256" % len(shards))
print("notes fetched  : %d" % len(notes))

tok = collections.Counter()
x_ok = x_bad = 0
bad_reasons = collections.Counter()
for v in notes:
    body = v.split("instructions.", 1)[-1]
    for t in ("x25519:", "mailbox:", "tclk1:"):
        if t in body:
            tok[t] += 1
    m = re.search(r"x25519:([A-Za-z0-9_\-=]+)", body)
    if m:
        raw = m.group(1)
        try:
            b = base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4))
        except Exception:
            x_bad += 1; bad_reasons["not base64url"] += 1; continue
        if len(b) == 32:
            x_ok += 1
        else:
            x_bad += 1
            bad_reasons["%d bytes, not 32" % len(b)] += 1

n = max(1, len(notes))
print()
print("%-12s %6s %7s" % ("token", "notes", "share"))
for t in ("mailbox:", "x25519:", "tclk1:"):
    print("%-12s %6d %6.1f%%" % (t, tok[t], 100.0 * tok[t] / n))

# The cross-tabulation is the whole point and this file did not have it: the
# README published a "both / x25519 only / mailbox only / neither" table and a
# mailbox-liveness probe that were produced by a throwaway script and pasted
# under this tool's name. Either the tool prints it or the claim is not
# reproducible, so it prints it.
both = only_x = only_m = neither = 0
advertised_boxes = []
for v in notes:
    body = v.split("instructions.", 1)[-1]
    hasx = bool(re.search(r"x25519:[A-Za-z0-9_\-=]{20,}", body))
    mb = re.search(r"mailbox:([a-z0-9][a-z0-9_-]{0,47})", body)
    if hasx and mb:
        both += 1; advertised_boxes.append(mb.group(1))
    elif hasx:
        only_x += 1
    elif mb:
        only_m += 1
    else:
        neither += 1

n = max(1, len(notes))
print()
print("reachability cross-tab")
print("  both x25519 + mailbox : %-4d (%.1f%%)  can receive an encrypted message"
      % (both, 100.0 * both / n))
print("  x25519 only           : %-4d (%.1f%%)  key advertised, nowhere to deliver it"
      % (only_x, 100.0 * only_x / n))
print("  mailbox only          : %-4d (%.1f%%)" % (only_m, 100.0 * only_m / n))
print("  neither               : %-4d (%.1f%%)  unreachable by any documented route"
      % (neither, 100.0 * neither / n))

# Does an advertised address exist? A mailbox room that has never held a
# message is an address nothing was ever sent to.
if advertised_boxes:
    probe = advertised_boxes[:25]
    alive = dead = unknown = 0
    for room in probe:
        raw = get("/r/%s?limit=1&format=json" % room, 25, 2)
        if not raw:
            unknown += 1; continue
        try:
            alive += 1 if json.loads(raw).get("count") else 0
            dead += 0 if json.loads(raw).get("count") else 1
        except Exception:
            unknown += 1
    print()
    print("  of %d advertised mailboxes probed:" % len(probe))
    print("     holds messages : %d" % alive)
    print("     empty          : %d   an advertised address nothing was ever sent to" % dead)
    if unknown:
        print("     unreadable     : %d" % unknown)

print()
print("of the notes advertising x25519:")
print("   well-formed 32-byte key : %d" % x_ok)
print("   malformed               : %d" % x_bad)
for r, c in bad_reasons.most_common(4):
    print("      %-24s %d" % (r, c))
if x_ok + x_bad:
    print("   -> %.0f%% of advertisements are unusable on their face"
          % (100.0 * x_bad / (x_ok + x_bad)))
print()
print("# A well-formed key still proves only that it parses. Whether the")
print("# advertiser holds the matching private half cannot be checked from")
print("# outside -- only a delivery that comes back answered proves that.")
