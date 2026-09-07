#!/usr/bin/env python3
"""Check what Technocore tools do with the key they make you generate.

There are ~29 `awesome-technocore` lists and none of them says anything about
this. The list is the easy part; the useful part is that most of these repos
walk a newcomer through generating an Ed25519 private key, and a reader has no
way to tell from a README whether that key stays on their machine.

So this reads the source and reports three facts per repository:

  * does it generate or handle a private key at all
  * does it contact any host other than technocore.chat
  * does anything print, log or transmit the key material

None of those is an accusation on its own -- a tool that posts your DID to a
registry is contacting another host for a good reason, and a tool that prints a
seed once so you can back it up is doing what it says. The point is that the
reader can currently see none of it, and all three are mechanical to check.

Read-only: fetches public source over the GitHub API and greps it. Runs nothing.

    python3 tools/audit_ecosystem.py [--top N]
"""
import argparse
import base64
import json
import re
import subprocess
import sys
import time
import urllib.request

# Files worth reading. Whole repositories are too much; entry points are enough
# to see whether a key leaves the machine.
CODE = re.compile(r"\.(py|js|mjs|ts|sh|ps1|rb|go)$", re.I)

KEYGEN = re.compile(
    r"(ed25519|genpkey|generate_private_key|randomSecretKey|nacl\.signing|"
    r"SigningKey|from_seed|urandom\(32\)|randomBytes\(32\))", re.I)

# Any absolute URL, so the destinations can be listed rather than judged.
URLS = re.compile(r"https?://([A-Za-z0-9.\-]+)")

# Key material reaching an output stream or a request body.
LEAK = re.compile(
    r"(print\s*\(\s*[^)]*(?:seed|priv|secret)[^)]*\)|"
    r"console\.log\s*\(\s*[^)]*(?:seed|priv|secret)|"
    r"echo\s+[^|;]*\$(?:SEED|PRIV|SECRET|KEY)\b|"
    r"(?:requests\.(?:post|get)|fetch|urlopen|curl)[^\n]{0,120}"
    r"(?:seed|private_key|privkey|secret_key))", re.I)

BENIGN_HOSTS = {
    "technocore.chat", "mcp.technocore.chat", "flop.finance", "www.flop.finance",
    "github.com", "raw.githubusercontent.com", "api.github.com", "docs.github.com",
    "pypi.org", "files.pythonhosted.org", "registry.npmjs.org", "npmjs.com",
    "nodejs.org", "python.org", "www.python.org", "astral.sh", "x.com",
    "twitter.com", "opensource.org", "www.apache.org", "spdx.org",
    "creativecommons.org", "img.shields.io", "shields.io", "modelcontextprotocol.io",
    "w3c-ccg.github.io", "www.w3.org", "datatracker.ietf.org", "www.rfc-editor.org",
}


def gh(path, tries=4):
    for _ in range(tries):
        try:
            r = subprocess.run(["gh", "api", path], capture_output=True, timeout=60)
            if r.returncode == 0:
                return json.loads(r.stdout.decode())
        except Exception:
            pass
        time.sleep(2)
    return None


def files_of(full_name, default_branch):
    tree = gh("repos/%s/git/trees/%s?recursive=1" % (full_name, default_branch))
    if not tree:
        return []
    out = []
    for n in tree.get("tree", []):
        if n.get("type") != "blob" or not CODE.search(n.get("path", "")):
            continue
        if n.get("size", 0) > 200000:
            continue
        out.append(n["path"])
    # entry points first, then whatever else fits the budget
    out.sort(key=lambda p: (p.count("/"), len(p)))
    return out[:12]


def blob(full_name, path):
    d = gh("repos/%s/contents/%s" % (full_name, urllib.parse.quote(path)))
    if not d or d.get("encoding") != "base64":
        return ""
    try:
        return base64.b64decode(d["content"]).decode("utf-8", "replace")
    except Exception:
        return ""


import urllib.parse  # noqa: E402  (kept next to its only use)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--top", type=int, default=20)
    a = ap.parse_args()

    found = gh("search/repositories?q=technocore+in:name,description"
               "&sort=stars&order=desc&per_page=%d" % a.top)
    if not found:
        print("could not search GitHub (is `gh` authenticated?)")
        return 1
    repos = found.get("items", [])
    print("# Technocore ecosystem: what these tools do with your key")
    print("# %d repositories, by stars. Read-only source inspection.\n" % len(repos))

    rows = []
    for r in repos:
        name = r["full_name"]
        if name.startswith("flop-labs/"):
            continue
        paths = files_of(name, r.get("default_branch") or "main")
        if not paths:
            rows.append((name, r["stargazers_count"], "no readable source", set(), False, 0))
            continue
        hosts, keygen, leaks, read = set(), False, 0, 0
        for p in paths:
            src = blob(name, p)
            if not src:
                continue
            read += 1
            if KEYGEN.search(src):
                keygen = True
            leaks += len(LEAK.findall(src))
            for h in URLS.findall(src):
                hosts.add(h.lower())
        rows.append((name, r["stargazers_count"],
                     "ok" if read else "unreadable", hosts, keygen, leaks))

    print("%-46s %5s %8s %7s  %s" % ("repository", "stars", "keygen", "flags", "non-obvious hosts"))
    for name, stars, state, hosts, keygen, leaks in rows:
        odd = sorted(h for h in hosts if h not in BENIGN_HOSTS)
        print("%-46s %5d %8s %7s  %s"
              % (name[:46], stars, "yes" if keygen else "-",
                 leaks if leaks else "-", ", ".join(odd[:3]) or "-"))

    print()
    print("# keygen  : the source generates or loads an Ed25519 private key.")
    print("# flags   : lines where key material reaches print/log/a request.")
    print("#           A non-zero count is a REASON TO READ, not a verdict --")
    print("#           printing a seed once for the user to back up looks the same")
    print("#           as sending it somewhere, to a regex.")
    print("# hosts   : destinations other than the service, the project, GitHub and")
    print("#           the usual package registries. Empty is the expected case.")
    print("#")
    print("# Nothing here was executed. Read the source before running any of it,")
    print("# and never paste a seed into a web page or a form.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
