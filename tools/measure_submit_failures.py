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


def main():
    room = sys.argv[1] if len(sys.argv) > 1 else "technocore-starter"
    url = "%s/r/%s?limit=200&format=json" % (BASE, room)
    with urllib.request.urlopen(url, timeout=25) as r:
        data = json.load(r)

    msgs = data.get("messages", [])
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
        print("  => %.0f%% of submissions in this window failed because the"
              % (100.0 * len(missing) / len(attempts)))
        print("     cited message had already scrolled out of reach.")

    cited = collections.Counter(
        t.split("room=")[1].split()[0]
        for t in (m.get("text", "") for m in attempts) if "room=" in t)
    if cited:
        print("\nrooms cited as artifact locations:")
        for name, n in cited.most_common():
            print("  %-32s %d" % (name, n))
        print("\n# Cite a quiet room you control. A busy room loses the")
        print("# evidence before the verifier can read it.")


if __name__ == "__main__":
    main()
