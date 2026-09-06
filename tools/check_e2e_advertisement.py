#!/usr/bin/env python3
"""Prove that an x25519 token advertised in a DID note is actually usable.

    python3 tools/check_e2e_advertisement.py <note-url> [path-to-local-x25519-pem]

patterns.md §4 makes the recipient's static X25519 public key the entry point
for every encrypted delivery: a sender fetches the note, mints an ephemeral
pair, and derives a shared value against the advertised key. If the advertised
half does not correspond to the half the recipient holds, every delivery fails
silently and the advertisement is a claim with nothing behind it -- the same
shape as the `tclk1:` token this repo measured at zero uptake, and the same
shape as a room named after a faucet that does not exist.

So: run the sender's side against the PUBLISHED note, run the recipient's side
against the local file, and compare. With one argument it checks only that the
advertised token is well-formed, which is all an outside observer can do.

Prints byte counts and a verdict. Never reads out, stores or transmits private
key material.
"""
import base64
import os
import subprocess
import sys
import tempfile
import urllib.request

# X25519 SubjectPublicKeyInfo prefix, so a raw 32-byte key can be handed to openssl
SPKI = bytes.fromhex("302a300506032b656e032100")


def b64u_dec(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return 2
    note_url = sys.argv[1]
    local_pem = sys.argv[2] if len(sys.argv) > 2 else None

    with urllib.request.urlopen(note_url, timeout=30) as r:
        note = r.read().decode("utf-8", "replace")

    tokens = [t for t in note.split() if t.startswith("x25519:")]
    if not tokens:
        print("no x25519 token in the note -- nobody can send this identity an")
        print("encrypted message, whatever else the note says")
        return 1

    try:
        pub_raw = b64u_dec(tokens[0][len("x25519:"):])
    except Exception as e:
        print("x25519 token does not decode as base64url: %s" % e)
        return 1

    print("advertised key : %d bytes (32 expected)" % len(pub_raw))
    if len(pub_raw) != 32:
        print("VERDICT: malformed. An X25519 public key is 32 bytes; this cannot")
        print("         be used as one, so the advertisement is unusable.")
        return 1

    if not local_pem:
        print("VERDICT: well-formed. Whether the advertiser holds the matching")
        print("         private half cannot be checked from outside -- pass the")
        print("         local key file to check that.")
        return 0

    d = tempfile.mkdtemp()
    try:
        peer = os.path.join(d, "advertised.der")
        with open(peer, "wb") as f:
            f.write(SPKI + pub_raw)

        eph = os.path.join(d, "eph.pem")
        subprocess.run(["openssl", "genpkey", "-algorithm", "X25519", "-out", eph],
                       check=True, capture_output=True)
        eph_pub = os.path.join(d, "eph.pub.der")
        with open(eph_pub, "wb") as f:
            f.write(subprocess.run(
                ["openssl", "pkey", "-in", eph, "-pubout", "-outform", "DER"],
                check=True, capture_output=True).stdout)

        # sender: ephemeral private against the key taken from the live note
        a = subprocess.run(["openssl", "pkeyutl", "-derive", "-inkey", eph,
                            "-peerkey", peer, "-peerform", "DER"],
                           check=True, capture_output=True).stdout
        # recipient: local private against the sender's ephemeral public
        b = subprocess.run(["openssl", "pkeyutl", "-derive", "-inkey", local_pem,
                            "-peerkey", eph_pub, "-peerform", "DER"],
                           check=True, capture_output=True).stdout

        print("sender side    : %d bytes derived" % len(a))
        print("recipient side : %d bytes derived" % len(b))
        print()
        if len(a) == 32 and a == b:
            print("VERDICT: usable. A stranger can complete patterns.md §4 against")
            print("         this note and the advertiser can open the result.")
            return 0
        print("VERDICT: BROKEN. The note advertises a key whose deliveries the")
        print("         advertiser cannot open. Republish or remove the token.")
        return 1
    finally:
        for f in os.listdir(d):
            os.unlink(os.path.join(d, f))
        os.rmdir(d)


if __name__ == "__main__":
    sys.exit(main())
