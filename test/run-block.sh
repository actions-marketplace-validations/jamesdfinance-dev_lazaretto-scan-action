#!/usr/bin/env bash
# Runs the step's run: block from action.yml the way a GitHub runner does
# (bash --noprofile --norc -eo pipefail), with curl swapped for test/stub/curl,
# and checks the ::warning lines, GITHUB_OUTPUT, the step summary and the exit
# code for each scenario.
#
#   bash test/run-block.sh
#
# Needs bash and jq. Nothing here reaches the network.
set -uo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/.." && pwd)"
work="$(mktemp -d "${TMPDIR:-/tmp}/lazaretto-run-block.XXXXXX")"
trap 'rm -rf "$work"' EXIT

command -v jq >/dev/null || { echo "jq is required"; exit 2; }

# ----------------------------------------------------------------------------
# Pull the run: block out of action.yml. It is the only one, indented 8 spaces
# under "      run: |", and it ends at the first line indented less than that.
# ----------------------------------------------------------------------------
awk '
  /^      run: \|[ \t]*$/       { inblock = 1; next }
  inblock && /^[ \t]*$/         { print ""; next }
  inblock && /^        /        { print substr($0, 9); next }
  inblock                       { exit }
' "$root/action.yml" > "$work/run.sh"

grep -q '^set -uo pipefail' "$work/run.sh" || { echo "could not extract the run: block from action.yml"; exit 2; }
if grep -q '\${{' "$work/run.sh"; then
  echo "the run: block uses a \${{ }} expression; pass it through env: so this harness sees what the runner sees"
  exit 2
fi

BASE=https://lazaretto.test
TOPUP="Top up: ${BASE}/buy"

fails=0; total=0; name=""; S=""; code=0; bad=0

# scenario <name>: a fresh workspace, stub directory and default fixtures.
scenario() {
  name="$1"; total=$(( total + 1 )); bad=0
  S="$work/$total"
  mkdir -p "$S/stub" "$S/ws" "$S/tmp"
  : > "$S/output"; : > "$S/summary"
  fixture lockfile 200 '{"checked":3,"malicious":[],"unverified":[],"skipped":{"count":0}}'
  fixture base 200 '{"lockfileVersion":3,"packages":{}}'
  fixture comments 200 '[]'
  fixture comment_create 201 '{"id":1}'
  fixture comment_update 200 '{"id":1}'
  echo '{"lockfileVersion":3,"packages":{}}' > "$S/ws/package-lock.json"
  jq -n '{pull_request: {number: 7, base: {sha: "basesha"}}}' > "$S/event.json"
  EVENT_NAME=pull_request; DEEP_SCAN=auto; MAX_PKGS=250; FAIL_ON=flagged; COMMENT=true; LAZ_KEY=laz_test_key
}

# fixture <key> <http code> <body>
fixture() { printf '%s' "$2" > "$S/stub/$1.code"; printf '%s\n' "$3" > "$S/stub/$1.body"; }

# added <n>: a /v1/lockfile/diff answer that adds n versions, pkg-1@1.0.1 ...
added() {
  fixture diff 200 "$(jq -n --argjson n "$1" \
    '{added: [range(1; $n + 1) | {name: "pkg-\(.)", version: "1.0.\(.)"}], upgraded: []}')"
}

# batch_ok <scanned> <billed> <remaining_credits> <not_scanned json or null> [worst verdict]
# A /v1/scan/batch 200 body shaped like the server's.
batch_ok() {
  jq -n --argjson s "$1" --argjson b "$2" --argjson r "$3" --argjson ns "$4" --arg v "${5:-clear}" '{
    requested: ($s + (($ns // {count: 0}).count)),
    scanned: $s, billed_credits: $b, refunded_credits: 0, remaining_credits: $r,
    complete_coverage: ($ns == null), not_scanned: $ns,
    partly_readable: 0,
    worst_verdict: (if $s > 0 then {name: "pkg-1", version: "1.0.1", verdict: $v, risk: (if $v == "clear" then "none" else "high" end)} else null end),
    results: [range(1; $s + 1) | {name: "pkg-\(.)", version: "1.0.\(.)", verdict: (if . == 1 then $v else "clear" end), risk: (if . == 1 and $v != "clear" then "high" else "none" end), rule_ids: []}],
    errored: []
  }'
}

# not_scanned <credits> <time> <cap> <first package number>: the object, with by_reason.
not_scanned() {
  jq -n --argjson c "$1" --argjson t "$2" --argjson k "$3" --argjson from "$4" '
    ($c + $t + $k) as $n | {
      count: $n,
      reasons: ([if $t > 0 then "ran out of time after 240s; send the remainder in another call" else empty end,
                 if $k > 0 then "capped at 25 packages per call; send the rest in another call" else empty end,
                 if $c > 0 then "not enough credits on this key to scan the rest" else empty end]),
      by_reason: {credits: $c, time: $t, cap: $k},
      packages: [range($from; $from + $n) | "pkg-\(.)@1.0.\(.)"]
    }'
}

run() {
  ( cd "$S/ws" && env -i \
      PATH="$root/test/stub:$PATH" HOME="$S" TMPDIR="$S/tmp" STUB_DIR="$S/stub" \
      GITHUB_EVENT_NAME="$EVENT_NAME" GITHUB_EVENT_PATH="$S/event.json" \
      GITHUB_REPOSITORY=acme/app GITHUB_API_URL=https://api.github.test \
      GITHUB_OUTPUT="$S/output" GITHUB_STEP_SUMMARY="$S/summary" \
      LOCKFILE_IN=auto LAZ_KEY="$LAZ_KEY" DEEP_SCAN="$DEEP_SCAN" MAX_PKGS="$MAX_PKGS" \
      FAIL_ON="$FAIL_ON" COMMENT="$COMMENT" GH_TOKEN=gh_test_token BASE_URL="$BASE" \
      bash --noprofile --norc -eo pipefail "$work/run.sh" ) > "$S/log" 2>&1
  code=$?
}

no() { echo "  FAIL: $*"; bad=1; }
exit_is()      { [ "$code" -eq "$1" ] || no "exit code ${code}, wanted $1"; }
log_line()     { grep -Fxq -- "$1" "$S/log" || no "log has no line: $1"; }
log_lacks()    { if grep -Fq -- "$1" "$S/log"; then no "log should not mention: $1"; fi; }
output_is()    { grep -Fxq -- "$1=$2" "$S/output" || no "GITHUB_OUTPUT has no $1=$2 (has: $(grep "^$1=" "$S/output" | tr '\n' ' '))"; }
summary_has()  { grep -Fq -- "$1" "$S/summary" || no "summary is missing: $1"; }
summary_lacks(){ if grep -Fq -- "$1" "$S/summary"; then no "summary should not contain: $1"; fi; }
batch_calls()  { local n; n="$(cat "$S/stub/batch.count" 2>/dev/null || echo 0)"; [ "$n" -eq "$1" ] || no "${n} batch call(s), wanted $1"; }
topup_warnings(){ local n; n="$(grep -c "^::warning title=Lazaretto::.*out of credits" "$S/log")"; [ "$n" -eq "$1" ] || no "${n} out-of-credits warning(s), wanted $1"; }

done_() {
  if [ "$bad" -eq 0 ]; then
    echo "ok   ${total} ${name}"
  else
    fails=$(( fails + 1 ))
    echo "FAIL ${total} ${name}"
    echo "  --- log";     sed 's/^/  | /' "$S/log"
    echo "  --- output";  sed 's/^/  | /' "$S/output"
    echo "  --- summary"; sed 's/^/  | /' "$S/summary"
    echo "  --- calls";   sed 's/^/  | /' "$S/stub/calls.log" 2>/dev/null
  fi
}

# ============================================================================
# Billing. Running out of credits only ever warns: every case below runs with
# fail-on: flagged and must still exit 0.
# ============================================================================

scenario "a short 200 then a 402 counts the short part and every batch after"
added 60   # three batches: 25, 25, 10
fixture batch.1 200 "$(batch_ok 20 20 0 "$(not_scanned 5 0 0 21)")"
fixture batch.2 402 '{"error":"insufficient_credits","detail":"this key has none available"}'
fixture batch.3 200 "$(batch_ok 10 10 0 null)"
run
exit_is 0
batch_calls 2
log_line "::warning title=Lazaretto::40 new versions not scanned: out of credits. ${TOPUP}"
topup_warnings 1
output_is not-scanned-count 40
output_is credits-remaining 0
output_is credits-spent 20
output_is worst-verdict clear
summary_has "**Behavioral scan stopped: out of credits.** **40** new versions not scanned."
summary_has "$TOPUP"
summary_lacks "Coverage was incomplete"
grep -q 'out of credits' "$S/stub/comment_create.request" 2>/dev/null || no "the PR comment does not say it ran out of credits"
done_

scenario "a 402 on the first batch warns, scans nothing, and does not fail"
added 1
fixture batch.1 402 '{"error":"insufficient_credits"}'
run
exit_is 0
batch_calls 1
log_line "::warning title=Lazaretto::1 new version not scanned: out of credits. ${TOPUP}"
output_is not-scanned-count 1
output_is credits-remaining ""
output_is credits-spent 0
output_is worst-verdict unscanned
summary_has "**1** new version not scanned."
done_

scenario "a whole-tree run that hits a 402 says pinned versions"
EVENT_NAME=schedule
added 30
fixture batch.1 402 '{"error":"insufficient_credits"}'
run
exit_is 0
batch_calls 1
log_line "::warning title=Lazaretto::30 pinned versions not scanned: out of credits. ${TOPUP}"
output_is not-scanned-count 30
done_

scenario "a 401 says the key was not accepted, not out of credits"
added 3
fixture batch.1 401 '{"error":"invalid_api_key"}'
run
exit_is 0
batch_calls 1
log_line "::warning title=Lazaretto::the api-key was not accepted (HTTP 401), so 3 version(s) were not behaviorally scanned. This is NOT an all-clear."
log_lacks "out of credits"
output_is not-scanned-count 3
output_is worst-verdict unscanned
summary_has 'The `api-key` was not accepted, so **3** version(s) were not behaviorally scanned.'
summary_lacks "out of credits"
done_

scenario "a 200 that is not JSON is an outage, not a pass"
added 3
fixture batch.1 200 '<html><body>502 Bad Gateway</body></html>'
run
exit_is 0
log_line "::warning title=Lazaretto::behavioral scan unavailable (HTTP 200, unreadable body). This is NOT an all-clear."
log_lacks "out of credits"
output_is not-scanned-count 3
output_is worst-verdict unscanned
output_is credits-spent 0
summary_has "unavailable (HTTP 200, unreadable body), so **3** version(s) were not scanned."
done_

scenario "a batch that only ran out of time gets no top-up warning"
added 5
fixture batch.1 200 "$(batch_ok 3 3 97 "$(not_scanned 0 2 0 4)")"
run
exit_is 0
topup_warnings 0
log_lacks "$TOPUP"
output_is not-scanned-count 2
output_is credits-remaining 97
output_is credits-spent 3
output_is worst-verdict clear
summary_has "Coverage was incomplete: **2** not scanned because the scan ran out of time (not billed)."
summary_lacks "out of credits"
done_

scenario "a time-only skip on a key that happens to be at 0 is still not a credit problem"
added 5
fixture batch.1 200 "$(batch_ok 3 3 0 "$(not_scanned 0 2 0 4)")"
run
exit_is 0
topup_warnings 0
output_is credits-remaining 0
summary_has "**2** not scanned because the scan ran out of time (not billed)"
summary_lacks "out of credits"
done_

scenario "a batch that ran out of time AND short of credits warns only for the credit part"
added 25
fixture batch.1 200 "$(batch_ok 17 17 3 "$(not_scanned 5 3 0 18)")"
run
exit_is 0
batch_calls 1
log_line "::warning title=Lazaretto::5 new versions not scanned: out of credits. ${TOPUP}"
topup_warnings 1
log_lacks "8 new versions"
output_is not-scanned-count 8
output_is credits-remaining 3
output_is credits-spent 17
summary_has "Coverage was incomplete: **3** not scanned because the scan ran out of time (not billed)."
summary_has "**Behavioral scan stopped: out of credits.** **5** new versions not scanned."
done_

scenario "a per-call cap skip goes in the coverage block, not the top-up warning"
added 25
fixture batch.1 200 "$(batch_ok 23 23 50 "$(not_scanned 0 0 2 24)")"
run
exit_is 0
topup_warnings 0
output_is not-scanned-count 2
summary_has "**2** not scanned because of the per-call package cap (not billed)"
done_

scenario "an older server with no by_reason: a credit reason still counts as out of credits"
added 10
fixture batch.1 200 "$(batch_ok 6 6 0 '{"count":4,"reasons":["not enough credits on this key to scan the rest"]}')"
run
exit_is 0
log_line "::warning title=Lazaretto::4 new versions not scanned: out of credits. ${TOPUP}"
output_is not-scanned-count 4
output_is credits-remaining 0
summary_has "**4** new versions not scanned."
done_

scenario "an older server with no by_reason: a time reason is incomplete coverage"
added 5
fixture batch.1 200 "$(batch_ok 3 3 50 '{"count":2,"reasons":["ran out of time after 240s; send the remainder in another call"]}')"
run
exit_is 0
topup_warnings 0
output_is not-scanned-count 2
output_is credits-remaining 50
summary_has "Coverage was incomplete: **2** not scanned."
summary_lacks "out of credits"
done_

# ============================================================================
# Not billing. Proves the harness can see a failing step, and pins the other
# ways the step must not go red.
# ============================================================================

scenario "a malicious verdict still fails the build"
FAIL_ON=malicious
added 2
fixture batch.1 200 "$(batch_ok 2 2 98 null malicious)"
run
exit_is 1
log_line "::error title=Lazaretto::pkg-1@1.0.1 is malicious (risk high)."
output_is worst-verdict malicious
done_

scenario "a malicious result behind a flagged worst_verdict still fails fail-on: malicious"
# The server orders worst_verdict by risk alone, so a flagged/critical package
# ahead of a malicious/critical one makes it say flagged. The gate reads the
# results.
FAIL_ON=malicious
added 2
fixture batch.1 200 '{"requested":2,"scanned":2,"billed_credits":2,"refunded_credits":0,"refund_failed":false,"remaining_credits":8,"complete_coverage":true,"not_scanned":null,"partly_readable":0,
  "worst_verdict":{"name":"pkg-1","version":"1.0.1","verdict":"flagged","risk":"critical"},
  "results":[{"name":"pkg-1","version":"1.0.1","verdict":"flagged","risk":"critical","rule_ids":["r1"]},
             {"name":"pkg-2","version":"1.0.2","verdict":"malicious","risk":"critical","rule_ids":["r2"]}],
  "errored":[]}'
run
exit_is 1
log_line "::error title=Lazaretto::pkg-2@1.0.2 is malicious (risk critical)."
log_line "::error title=Lazaretto::Worst verdict 'malicious' meets the fail-on threshold 'malicious'. Failing the build."
output_is worst-verdict malicious
summary_has "Worst verdict: **malicious**."
done_

scenario "the gate reads the results of every batch, not only the first"
FAIL_ON=malicious
added 30   # two batches: 25, 5
fixture batch.1 200 "$(batch_ok 25 25 5 null flagged)"
fixture batch.2 200 "$(batch_ok 5 5 0 null clear | jq -c '.results[4].verdict = "malicious" | .results[4].risk = "critical" | .worst_verdict.verdict = "clear"')"
run
exit_is 1
batch_calls 2
output_is worst-verdict malicious
done_

scenario "results that are all clear read clear, whatever worst_verdict says"
FAIL_ON=flagged
added 2
fixture batch.1 200 "$(batch_ok 2 2 8 null clear | jq -c '.worst_verdict = null')"
run
exit_is 0
output_is worst-verdict clear
done_

scenario "fail-on: never passes even on a malicious verdict"
FAIL_ON=never
added 2
fixture batch.1 200 "$(batch_ok 2 2 98 null malicious)"
run
exit_is 0
output_is worst-verdict malicious
done_

scenario "a PR comment the token may not list does not fail the step"
added 1
fixture batch.1 200 "$(batch_ok 1 1 9 null)"
fixture comments 403 '{"message":"Resource not accessible by integration"}'
fixture comment_create 403 '{"message":"Resource not accessible by integration"}'
run
exit_is 0
log_line "::warning title=Lazaretto::could not post the PR comment (grant 'pull-requests: write')"
output_is worst-verdict clear
done_

echo
echo "${total} scenarios, $(( total - fails )) passed, ${fails} failed."
[ "$fails" -eq 0 ]
