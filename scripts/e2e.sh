#!/usr/bin/env bash
# End-to-end test of a running Secretli server, driven by the released
# command-line client: everything a client does with a secret goes through
# the real API, the real database and the real object store.
#
#   SECRETLI_SERVER  the server to test (default http://localhost:8080)
#   SECRETLI_CLI     the secretli binary (default: secretli on PATH)
#
# The browser's own flows, and the hand-off between the browser and the
# client, are covered by the web app's end-to-end tests.
set -euo pipefail

SERVER="${SECRETLI_SERVER:-http://localhost:8080}"
CLI="${SECRETLI_CLI:-secretli}"
work="$(mktemp -d)"
trap 'kill $(jobs -p) 2> /dev/null || true; rm -rf "$work"' EXIT

pass() { printf 'ok    %s\n' "$1"; }
fail() { printf 'FAIL  %s\n' "$1" >&2; exit 1; }

# expect_exit CODE DESCRIPTION -- COMMAND...: runs the command and checks its exit code.
expect_exit() {
  local want="$1" what="$2"
  shift 3
  local got=0
  "$@" > "$work/out" 2> "$work/err" || got=$?
  if [ "$got" != "$want" ]; then
    cat "$work/out" "$work/err" >&2
    fail "$what: exit $got, want $want"
  fi
  pass "$what"
}

"$CLI" --version > /dev/null || fail "no secretli client at '$CLI'"
curl -fsS "$SERVER/api/v1/health/ready" > /dev/null || fail "$SERVER is not ready"

# --- a one-time text secret: share, look, open, and it is gone ---
text="e2e $(date +%s) the launch code is 0000"
"$CLI" share --server "$SERVER" -e 5m -t "$text" --json > "$work/shared.json"
link="$(jq -r .link "$work/shared.json")"
owner="$(jq -r .owner_link "$work/shared.json")"
[ "$(jq -r .opens "$work/shared.json")" = once ] || fail "a new secret should open once"
pass "share a one-time text secret"

expect_exit 0 "status before opening" -- "$CLI" status "$owner" --json
[ "$(jq -r .state "$work/out")" = live ] || fail "status should say live"

# Opening uses it up, so the client asks first; where it cannot ask, as in
# CI, it refuses without --yes and leaves the secret alone.
if ( : < /dev/tty ) 2> /dev/null; then
  pass "a one-time secret is not opened without --yes (skipped: a terminal would be asked)"
else
  expect_exit 1 "a one-time secret is not opened without --yes" -- "$CLI" open "$link"
fi

expect_exit 0 "open it" -- "$CLI" open "$link" --yes
[ "$(cat "$work/out")" = "$text" ] || fail "opened text differs: $(cat "$work/out")"

expect_exit 4 "the owner link says it was opened" -- "$CLI" status "$owner" --json
[ "$(jq -r .outcome "$work/out")" = opened ] || fail "outcome should be opened, got $(cat "$work/out")"
[ "$(jq -r .opened_by_owner "$work/out")" = false ] || fail "a recipient opened it, not the owner"

expect_exit 4 "a second open finds it gone" -- "$CLI" open "$link"

# --- reusable files with a password, large enough for several upload parts ---
head -c $((40 * 1024 * 1024)) /dev/urandom > "$work/big.bin"
printf 'notes\n' > "$work/notes.txt"
SECRETLI_PASSWORD=hunter2 "$CLI" share --server "$SERVER" -e 15m --reusable -p --json \
  "$work/big.bin" "$work/notes.txt" > "$work/files.json"
link="$(jq -r .link "$work/files.json")"
owner="$(jq -r .owner_link "$work/files.json")"
pass "share two files, 40 MiB in all, with a password"

# Without a password the client would ask on the terminal, so this check
# only runs where there is none to ask on, as in CI.
if ( : < /dev/tty ) 2> /dev/null; then
  pass "no password is refused (skipped: a terminal would be asked)"
else
  expect_exit 3 "no password is refused" -- "$CLI" open "$link" --out "$work/none"
fi
SECRETLI_PASSWORD=wrong expect_exit 3 "a wrong password is refused" -- "$CLI" open "$link" --out "$work/wrong"

SECRETLI_PASSWORD=hunter2 expect_exit 0 "open with the password" -- "$CLI" open "$link" --out "$work/received"
cmp -s "$work/big.bin" "$work/received/big.bin" || fail "big.bin differs after the round trip"
cmp -s "$work/notes.txt" "$work/received/notes.txt" || fail "notes.txt differs after the round trip"
pass "both files come back byte for byte"

expect_exit 0 "a reusable secret stays and remembers its first opening" -- "$CLI" status "$owner" --json
[ "$(jq -r .opened_at "$work/out")" != null ] || fail "opened_at should be set"

# --- deleting ---
expect_exit 1 "the recipient's link cannot delete" -- "$CLI" delete "$link" --yes
expect_exit 0 "the owner link deletes" -- "$CLI" delete "$owner" --yes
expect_exit 4 "and the owner link says so" -- "$CLI" status "$owner" --json
[ "$(jq -r .outcome "$work/out")" = deleted ] || fail "outcome should be deleted"

# --- handing a link over with a code, through the relay ---
# send_in_background LINK NAME: starts `send`, waits for the code it prints,
# and leaves the code in $code and the process in $sender.
send_in_background() {
  "$CLI" send "$1" > "$work/$2.code" 2> "$work/$2.err" &
  sender=$!
  for _ in $(seq 1 100); do
    [ -s "$work/$2.code" ] && break
    sleep 0.1
  done
  code="$(head -n 1 "$work/$2.code")"
  [ -n "$code" ] || fail "send printed no code: $(cat "$work/$2.err")"
}

text="e2e $(date +%s) handed over with a code"
"$CLI" share --server "$SERVER" -e 5m -t "$text" -q > "$work/handover.link"
send_in_background "$(cat "$work/handover.link")" handover
pass "send prints a code"
expect_exit 0 "receive opens what the code hands over" -- "$CLI" receive "$code" --server "$SERVER" --yes
[ "$(cat "$work/out")" = "$text" ] || fail "received text differs: $(cat "$work/out")"
got=0
wait "$sender" || got=$?
[ "$got" = 0 ] || fail "send exited $got after handing over: $(cat "$work/handover.err")"
pass "and send ends once the link is handed over"

# A wrong code ends the transfer on both sides, and nothing is handed over.
text="e2e $(date +%s) never handed over"
"$CLI" share --server "$SERVER" -e 5m -t "$text" -q > "$work/mismatch.link"
send_in_background "$(cat "$work/mismatch.link")" mismatch
wrong="${code%%-*}-yoyo-zucchini"
[ "$wrong" != "$code" ] || wrong="${code%%-*}-acid-rocket"
expect_exit 3 "a wrong code is refused" -- "$CLI" receive "$wrong" --server "$SERVER" --yes
got=0
wait "$sender" || got=$?
[ "$got" = 3 ] || fail "send should exit 3 on a wrong code, exited $got"
pass "and the sender hears it too"
expect_exit 0 "the secret was not handed over and still opens" -- "$CLI" open "$(cat "$work/mismatch.link")" --yes
[ "$(cat "$work/out")" = "$text" ] || fail "opened text differs: $(cat "$work/out")"

echo "all end-to-end checks passed against $SERVER"
