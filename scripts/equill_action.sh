#!/usr/bin/env bash
# The body of the equill GitHub Action (action.yml).
#
# Scans a checkout, maps every finding to ISO/IEC 25010, writes report.json,
# report.sarif, scores.json and summary.md, appends the summary to the job
# summary page, writes the counts to the step outputs, and exits 1 when the
# quality gate fails -- after everything is written, so the reason is on the
# page. Kept as a script so tests/test_action.py can run it without GitHub.
#
# Inputs, as environment variables:
#
#   EQUILL_PATH            directory to scan, relative to the working directory (.)
#   EQUILL_SCANNER         opengrep | semgrep | cppcheck (opengrep)
#   EQUILL_CONFIG          --config: auto, or registry packs / rule paths (auto)
#   EQUILL_SCANNER_OUTPUT  recorded Semgrep JSON or Cppcheck XML to map instead
#                          of running the scanner (empty: run it)
#   EQUILL_OUTPUT_DIR      where the artifacts go (equill-report)
#   EQUILL_FAIL_ON         characteristics whose actionable findings fail the gate
#   EQUILL_MAX_ACTIONABLE  fail the gate above this many actionable findings
#   EQUILL_NAME            name recorded in report.json (the directory's name)
#   EQUILL_BIN             the equill executable (equill)
#   EQUILL_PYTHON          a Python 3 for reading scores.json (python3)
#
# Run from the root of the checkout being scanned, so finding paths -- and the
# SARIF locations code scanning resolves -- are relative to it.
set -euo pipefail

target="${EQUILL_PATH:-.}"
out="${EQUILL_OUTPUT_DIR:-equill-report}"
equill="${EQUILL_BIN:-equill}"
python="${EQUILL_PYTHON:-python3}"

args=(scan "$target"
  --scanner "${EQUILL_SCANNER:-opengrep}"
  --config "${EQUILL_CONFIG:-auto}"
  --output "$out")
if [ -n "${EQUILL_NAME:-}" ]; then
  args+=(--name "$EQUILL_NAME")
fi
if [ -n "${EQUILL_SCANNER_OUTPUT:-}" ]; then
  args+=(--scanner-output "$EQUILL_SCANNER_OUTPUT")
fi
"$equill" "${args[@]}"

# A summary.md left by an earlier run would make a crash below look like a
# rendered page, so it goes first.
rm -f "$out/summary.md"
summary_args=(summary "$out/report.json" --output "$out/summary.md")
if [ -n "${EQUILL_FAIL_ON:-}" ]; then
  summary_args+=(--fail-on "$EQUILL_FAIL_ON")
fi
if [ -n "${EQUILL_MAX_ACTIONABLE:-}" ]; then
  summary_args+=(--max-actionable "$EQUILL_MAX_ACTIONABLE")
fi
set +e
"$equill" "${summary_args[@]}"
rc=$?
set -e
# The gate exits 1 only after writing the page; no page means equill itself
# failed (a bad --fail-on, an unreadable report), which is not a gate verdict.
if [ "$rc" -ne 0 ] && [ ! -s "$out/summary.md" ]; then
  exit "$rc"
fi
gate=passed
if [ "$rc" -ne 0 ]; then
  gate=failed
fi

if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
  cat "$out/summary.md" >> "$GITHUB_STEP_SUMMARY"
fi

counts="$("$python" - "$out/scores.json" <<'PY'
import json, sys
s = json.load(open(sys.argv[1], encoding="utf-8"))
print(s["total_findings"], s["mapped_findings"], s["actionable_findings"], s["actionable_sites"])
PY
)"
read -r total mapped actionable sites <<< "$counts"

if [ -n "${GITHUB_OUTPUT:-}" ]; then
  {
    echo "report=$out/report.json"
    echo "sarif=$out/report.sarif"
    echo "scores=$out/scores.json"
    echo "summary=$out/summary.md"
    echo "findings=$total"
    echo "mapped=$mapped"
    echo "actionable=$actionable"
    echo "sites=$sites"
    echo "gate=$gate"
  } >> "$GITHUB_OUTPUT"
fi

echo "equill: $total findings, $mapped mapped, $actionable actionable at $sites sites; gate $gate"
exit "$rc"
