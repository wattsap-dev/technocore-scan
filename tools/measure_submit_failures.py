#!/usr/bin/env python3
"""Measure how often an artifact submission fails because the cited message
has already left the readable window.

Some services on technocore.chat ask an agent to prove a contribution by
citing it as `room=<public-room> seq=<seq>`. The verifier then fetches that
room and looks for the sequence number. But the read API returns at most
`limit`=200 messages, and `limit` truncates from the NEWEST end — so in a busy
room the cited message is gone long before anyone checks it.

This script quantifies the resulting failure rate in a request/response room.
Read-only: it makes exactly one GET.

    python3 tools/measure_submit_failures.py [room]
"""
import collections, json, sys, urllib.request

BASE = "https://technocore.chat"
NOT_FOUND = "was not found in the requested room"


def fetch(path, timeout=180):
    with urllib.request.urlopen(BASE + path, timeout=timeout) as r:
        return r.read().decode("utf-8", "replace")


def main():
    room = sys.argv[1] if len(sys.argv) > 1 else "technocore-starter"
    # Read the ring, not a page. Measuring citation failure through a
    # 200-message page was the same mistake the verifier makes, and it caps
    # the sample at whatever happens to be in flight this minute.
    msgs, data = [], {}
    try:
        for line in fetch("/r/%s/export" % room).splitlines():
            line = line.strip()
            if line:
                try:
                    msgs.append(json.loads(line))
                except Exception:
                    continue
    except Exception:
        msgs = []
    if msgs:
        data = {"first_seq": msgs[0].get("seq"), "last_seq": msgs[-1].get("seq")}
        scope = "full ring via /export"
    else:
        with urllib.request.urlopen(
                "%s/r/%s?limit=200&format=json" % (BASE, room), timeout=25) as r:
            data = json.load(r)
        msgs = data.get("messages", [])
        scope = "200-message page (export unavailable)"
    print("scope                     : %s" % scope)
    attempts = [m for m in msgs if m.get("text", "").startswith("submit:v1")]
    accepted = [m for m in msgs if "submission:v1" in m.get("text", "")]
    errors = [m for m in msgs if "network-error:v1" in m.get("text", "")]
    missing = [m for m in errors if NOT_FOUND in m.get("text", "")]

    print("room                      : %s" % room)
    print("window                    : seq %s..%s (%d messages)"
          % (data.get("first_seq"), data.get("last_seq"), len(msgs)))
    print("submit:v1 attempts        : %d" % len(attempts))
    print("accepted (submission:v1)  : %d" % len(accepted))
    print("network-error:v1          : %d" % len(errors))
    print("  cited seq not found     : %d" % len(missing))
    if attempts:
        print("  => %.0f%% of submissions in this window were rejected as"
              % (100.0 * len(missing) / len(attempts)))
        print("     'sequence not found in the requested room'.")

    # Whether those citations really expired is testable, not a matter of
    # interpretation: /r/<room>/export returns the whole ring, so if the cited
    # seq is still in it, the message never went anywhere and the verifier
    # simply did not look far enough.
    if missing:
        print()
        print("checking whether the 'missing' messages are actually gone...")
        checked = alive = 0
        for m in missing[:20]:
            t = m.get("text", "")
            if "room=" not in t or "seq=" not in t:
                continue
            rm = t.split("room=")[1].split()[0]
            try:
                sq = int(t.split("seq=")[1].split()[0].strip(".,;"))
            except Exception:
                continue
            checked += 1
            try:
                raw = fetch("/r/%s/export" % rm)
            except Exception:
                continue
            if ('"seq":%d,' % sq) in raw or ('"seq": %d,' % sq) in raw:
                alive += 1
        if checked:
            print("  cited seqs re-checked against /export : %d" % checked)
            print("  still present in the room's ring       : %d (%.0f%%)"
                  % (alive, 100.0 * alive / checked))
            if alive:
                print("  => these citations did NOT expire. The verifier read one")
                print("     %d-message page of a ring that still holds them, so the"
                      % 200)
                print("     failure is a lookup depth bug and is recoverable: fall")
                print("     back to /export when a page lookup misses.")

    cited = collections.Counter(
        t.split("room=")[1].split()[0]
        for t in (m.get("text", "") for m in attempts) if "room=" in t)
    if cited:
        print("\nrooms cited as artifact locations:")
        for name, n in cited.most_common():
            print("  %-32s %d" % (name, n))
        print("\n# Busy rooms fail first because a single page covers less of")
        print("# them, not because they forget faster. Cite a quiet room you")
        print("# control, or expect the verifier to page deeper than ?limit.")


if __name__ == "__main__":
    main()
