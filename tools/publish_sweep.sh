#!/bin/zsh
# Publish the collected sweep samples, at most once a day.
#
# The collector appends hourly, but a series that only exists on one laptop
# proves nothing to anyone — the point is a public record across the Q4
# testnet. This commits and pushes the data file and nothing else.
#
# Deliberately narrow:
#   - stages data/ only, so code edits in progress are never swept in
#   - no force, no branch changes, no history rewriting
#   - if the remote moved ahead, it rebases once; if that fails it stops and
#     leaves the situation for a human rather than guessing
#   - runs at most once per 20 h, however often the collector fires

set -u

REPO="${0:A:h:h}"
cd "$REPO" || exit 1

STAMP="$REPO/data/.last-publish"
MIN_GAP=$((20 * 3600))
LOG="$REPO/data/collect.log"

note() { print "$(date -u +%Y-%m-%dT%H:%M:%SZ) publish: $1" >> "$LOG" }

# --- rate limit -------------------------------------------------------------
if [[ -f "$STAMP" ]]; then
    last=$(cat "$STAMP" 2>/dev/null || print 0)
    now=$(date +%s)
    (( now - last < MIN_GAP )) && exit 0
fi

# --- nothing to publish? ----------------------------------------------------
if [[ -z "$(git status --porcelain -- data/ 2>/dev/null)" ]]; then
    date +%s > "$STAMP"
    exit 0
fi

N=$(wc -l < data/sweep.jsonl | tr -d ' ')
git add -- data/ || { note "git add failed"; exit 1 }
git commit -q -m "sweep: $N samples" -- data/ || { note "nothing committed"; exit 0 }

if git push -q 2>/dev/null; then
    note "pushed ($N samples)"
    date +%s > "$STAMP"
    exit 0
fi

# remote moved ahead — reconcile once, then try again
note "push rejected, rebasing onto origin"
if git pull --rebase --autostash -q 2>/dev/null && git push -q 2>/dev/null; then
    note "pushed after rebase ($N samples)"
    date +%s > "$STAMP"
else
    git rebase --abort 2>/dev/null
    note "STOPPED: could not publish - commit is local, needs a human"
fi
