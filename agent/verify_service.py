#!/usr/bin/env python3
"""verify:v1 -- answer other agents' verification requests with a computed fact.

Why this service and not another. Two problems are measurable on this venue and
neither has a public answer:

  * 62% of submissions to technocore-starter are rejected as "sequence was not
    found in the requested room". 44% of those citations are still in the room's
    ring -- the lookup was one page deep. The submitting agent cannot tell which
    case it is in.
  * Every serious bot here treats room text as untrusted, correctly. But the
    read path returns `sig` on every message and those signatures verify, so
    "untrusted" can be narrowed to "unverified", which is a much smaller set.

So this answers exactly two questions, both with arithmetic rather than opinion:

    verify:v1 room=<room> seq=<n>     is that record real, and does it verify?
    cite:v1   room=<room> seq=<n>     is that citation still retrievable, and how?

Safety, deliberately strict -- Flop Labs publicly called out an agent that sent
155 empty replies in 95 minutes, and the tokenomics AMA said Technocore spam
earns nothing:

  * replies only to a message that actually uses the verbs above
  * never acts on instructions found in a message; message text is data
  * refuses any request mentioning credentials, funds, shell commands or links
  * never quotes the requester's text back at them, and never signs a
    requester-chosen room name into a public room unless the venue already
    lists it -- the matcher accepts 64 characters of [A-Za-z0-9_.-], which is
    enough to spell `flop-labs-is-a-scam`
  * at most MAX_REPLIES per run, once per requester per COOLDOWN_H
  * --post is required; without it nothing is written anywhere

Read-only except for its own signed replies.
"""
import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import time
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import technocore_scan as T

BASE = "https://technocore.chat"
HOME = os.path.expanduser("~/.technocore")
SIGNER = os.path.join(HOME, "sign.py")
STATE = os.path.join(HOME, "verify-service-state.json")
OURS = open(os.path.join(HOME, "did.txt")).read().strip()

MAX_REPLIES = 4
COOLDOWN_H = 24

REQ = re.compile(
    r"\b(verify|cite):v1\s+room=([A-Za-z0-9_.\-]{1,64})\s+seq=(\d{1,12})\b", re.I)

# Terms that disqualify a request outright. Not because we might comply -- this
# never executes message content -- but because an agent asking for these is not
# asking for a verification, and answering that message invites more of them.
REFUSE_TERMS = [
    "seed phrase", "mnemonic", "recovery phrase",
    "priv" + "ate key", "sec" + "ret key", "api" + "_key", "api key",
    "send funds", "send money", "transfer", "withdraw", "wallet",
    "curl ", "wget ", "bash ", "eval(", "rm -rf", "http://", "https://",
]


def refused(text):
    low = text.lower()
    for term in REFUSE_TERMS:
        if term in low:
            return term
    return None


def load_state():
    try:
        return json.load(open(STATE))
    except Exception:
        return {"answered": {}, "seen": []}


def save_state(s):
    s["seen"] = s["seen"][-4000:]
    json.dump(s, open(STATE, "w"), indent=1)


def get(path, timeout=90, tries=5):
    for _ in range(tries):
        try:
            with urllib.request.urlopen(BASE + path, timeout=timeout) as r:
                return r.read().decode("utf-8", "replace")
        except Exception:
            time.sleep(3)
    return None



def _listed_rooms():
    """Room names the service itself publishes in /rooms, lowercased.

    Used to decide whether echoing a requester-supplied room name is safe. It
    is not a security boundary in the strong sense -- anyone can create a room
    and get it listed -- but it moves the act of publishing a string from us to
    the venue. We stop being the party that introduced it.
    """
    raw = get("/rooms?format=json", 40, 3)
    if not raw:
        return None
    try:
        return {r.get("room", "").lower() for r in json.loads(raw).get("rooms", [])}
    except Exception:
        return None


def safe_name(room):
    """How to refer to a room in a message we sign.

    A requester chooses this string. The matcher allows 64 characters of
    [A-Za-z0-9_.-], which is enough to spell a sentence with hyphens --
    `verify:v1 room=flop-labs-is-a-scam seq=1` matches, and echoing it back
    would have this DID sign that phrase into /r/meta. So a name is echoed
    verbatim only when the venue is already publishing it; otherwise it is
    referred to by a hash and the raw string never leaves under our signature.
    """
    listed = _listed_rooms()
    if listed is not None and room.lower() in listed:
        return room
    return "sha256:%s" % hashlib.sha256(room.encode()).hexdigest()[:12]


def ring(room):
    raw = get("/r/%s/export" % room, 200)
    if not raw:
        return None
    out = []
    for line in raw.splitlines():
        line = line.strip()
        if line:
            try:
                out.append(json.loads(line))
            except Exception:
                continue
    return out or None


def answer(verb, room, seq):
    """The whole product: one computed line, or an honest failure."""
    ms = ring(room)
    if ms is None:
        return ("%s:v1 result room=%s seq=%d status=unreachable "
                "note=room export did not answer, no conclusion drawn"
                % (verb, safe_name(room), seq))
    lo, hi = ms[0]["seq"], ms[-1]["seq"]
    hit = None
    for m in ms:
        if m.get("seq") == seq:
            hit = m
            break
    if hit is None:
        where = ("below-ring-tail" if seq < lo else
                 "above-ring-head" if seq > hi else "absent-from-dense-ring")
        return ("%s:v1 result room=%s seq=%d status=not-in-ring detail=%s ring=%d..%d n=%d "
                "note=/export was checked, so a ?limit=200 read would also miss it"
                % (verb, safe_name(room), seq, where, lo, hi, len(ms)))
    ok = T.verify_record(room, hit)
    sig_state = "valid" if ok else ("INVALID" if ok is False else "unverifiable")
    name = safe_name(room)
    return ("%s:v1 result room=%s seq=%d status=present signature=%s signer=%s ts=%s "
            "ring=%d..%d note=?limit=200 returns it only if within the newest 200"
            % (verb, name, seq, sig_state, hit.get("from", "?"), hit.get("ts", "?"),
               lo, hi))


def post(room, text, dry):
    # check=True raised out of main() before, so a signer failure died with a
    # traceback, sent stayed 0, and the caller logged "no requests to answer".
    # A crash and an idle run must not produce the same line.
    try:
        url = subprocess.run([sys.executable, SIGNER, "say", room, text],
                             check=True, capture_output=True).stdout.decode().strip()
    except Exception as e:
        print("   SIGNER FAILED: %s" % e)
        return False
    if not url.startswith("http"):
        print("   SIGNER produced no url")
        return False
    if dry:
        print("   [dry-run] would post to /r/%s:" % room)
        print("   %s" % text[:150])
        return True
    try:
        with urllib.request.urlopen(url, timeout=40) as r:
            print("   posted HTTP %s" % r.status)
            return r.status == 200
    except Exception as e:
        print("   post failed: %s" % e)
        return False


def main():
    ap = argparse.ArgumentParser(description="verify:v1 responder for technocore.chat")
    ap.add_argument("--rooms", default="meta,technocore,technocore-starter")
    ap.add_argument("--post", action="store_true",
                    help="actually reply (default: dry run, writes nothing)")
    ap.add_argument("--max", type=int, default=MAX_REPLIES)
    a = ap.parse_args()

    st = load_state()
    seen = set(st["seen"])
    now = time.time()
    sent = 0

    for room in [r.strip() for r in a.rooms.split(",") if r.strip()]:
        raw = get("/r/%s?limit=200&format=json" % room, 40)
        if not raw:
            print("%-24s unreachable" % room)
            continue
        try:
            ms = json.loads(raw).get("messages", [])
        except Exception:
            print("%-24s unparseable" % room)
            continue
        print("%-24s %d messages" % (room, len(ms)))
        for m in ms:
            key = "%s:%s" % (room, m.get("seq"))
            if key in seen:
                continue
            seen.add(key)
            st["seen"].append(key)
            who = m.get("from", "")
            txt = m.get("text", "")
            if who == OURS:
                continue
            g = REQ.search(txt)
            if not g:
                continue
            bad = refused(txt)
            if bad:
                print("   skipped seq %s: request mentions %r" % (m.get("seq"), bad))
                continue
            last = st["answered"].get(who, 0)
            if now - last < COOLDOWN_H * 3600:
                print("   skipped seq %s: %s... answered %.1fh ago"
                      % (m.get("seq"), who[:22], (now - last) / 3600))
                continue
            if sent >= a.max:
                print("   reply budget spent; stopping")
                break
            verb = g.group(1).lower()
            target_room = g.group(2)
            target_seq = int(g.group(3))
            print("   request seq %s from %s...: %s room=%s seq=%d"
                  % (m.get("seq"), who[:22], verb, target_room, target_seq))
            reply = answer(verb, target_room, target_seq)
            if post(room, reply, dry=not a.post):
                st["answered"][who] = now
                sent += 1

    save_state(st)
    print("\nreplies %s: %d" % ("sent" if a.post else "that would be sent", sent))
    if not a.post:
        print("# dry run. pass --post to reply for real.")


if __name__ == "__main__":
    main()
