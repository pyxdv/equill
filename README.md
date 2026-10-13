# equill

**ISO/IEC 25010 quality evidence from your SAST findings, in one CI step.**

equill runs Semgrep (or Opengrep, or Cppcheck), maps every finding to an
ISO/IEC 25010 characteristic and sub-characteristic through curated tables, and
gives you:

- `report.sarif`: SARIF 2.1.0 for GitHub code scanning, with each finding's ISO/IEC 25010 mapping in its message and property bag (`quillMapping`, the keys quill writes, so tools reading quill's SARIF read equill's);
- a **Markdown summary** on the job page, covering characteristics, file hotspots and the CWEs the table does not cover yet;
- a **quality gate**, for example "fail on any actionable security or reliability finding";
- `report.json` and `scores.json` for anything else you want to build.

The mapping is deterministic, so equill needs no LLM, no GPU and no vector store, and has two
runtime dependencies (pydantic, typer). It is the CI-sized distribution of
**quill**, a research artifact that maps SAST findings to ISO/IEC 25010 with
small local LLMs; equill ships quill's curated tables and its deterministic
mappers, scorer, SARIF export and summary, and leaves the LLM pipeline behind.

## GitHub Action

```yaml
# .github/workflows/equill.yml
name: equill
on: [pull_request, push]

jobs:
  quality:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write   # only for the SARIF upload
    steps:
      - uses: actions/checkout@v4

      - id: equill
        uses: pyxdv/equill@v1
        with:
          config: p/default        # or p/python, p/javascript, a rules dir, ...
          fail-on: security        # or: max-actionable: 0

      - if: ${{ !cancelled() && steps.equill.outputs.sarif != '' }}
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: ${{ steps.equill.outputs.sarif }}
          category: equill
```

| input | default | meaning |
|---|---|---|
| `path` | `.` | directory to scan, relative to the workspace |
| `scanner` | `semgrep` | `semgrep`, `opengrep` (must already be on `PATH`) or `cppcheck` |
| `config` | `p/default` | Semgrep/Opengrep `--config` |
| `scanner-output` | | a Semgrep JSON, or (with `scanner: cppcheck`) a Cppcheck XML, your workflow already produced; mapped instead of scanning |
| `fail-on` | | comma-separated characteristics, or `all`; fails on any actionable finding in them |
| `max-actionable` | | fails above this many actionable findings (`0` = none allowed) |
| `output-dir` | `equill-report` | where the artifacts go |
| `semgrep-version` | latest | pin Semgrep, e.g. `1.95.0` |
| `python-version` | `3.12` | Python used for equill and Semgrep |

Outputs: `report`, `sarif`, `scores`, `summary` (paths); `findings`, `mapped`,
`actionable`, `sites` (counts); `gate` (`passed` / `failed`). The step fails
when the gate does, after the summary is on the job page.

Already running Semgrep? Pass its JSON with `scanner-output: semgrep.json` and
equill skips the second scan. For C/C++, set `scanner: cppcheck`; to map a
report your workflow already produced, also pass `scanner-output: cppcheck.xml`
(from `cppcheck --xml`).

## Command line

```bash
pip install "equill @ git+https://github.com/pyxdv/equill@v1"
equill scan . --config p/python                 # equill-report/{report.json,report.sarif,scores.json}
equill summary equill-report/report.json        # Markdown to stdout
equill summary equill-report/report.json -o summary.md --fail-on security   # exit 1 if it trips
```

`equill scan --scanner-output semgrep.json` maps a scan you already have, and
`--reference` / `--checker-table` swap in your own tables.

## What gets counted

- **Mapped**: the finding's primary CWE (Semgrep/Opengrep) or checker id
  (Cppcheck) has a row in the table, which assigns one characteristic and one
  sub-characteristic with confidence 1.0 and a one-sentence rationale.
- **Unmapped**: no row. Such findings are listed by CWE (Semgrep/Opengrep) or
  checker id (Cppcheck) on the summary page and in SARIF, and **never trip the
  gate**: equill has no characteristic to attribute them to, and does not guess
  one.
- **Actionable**: mapped findings that count toward burden and the gate.
  Every mapped Semgrep finding is actionable. Cppcheck findings carry the
  checker table's prior class: BUG and QUALITY are actionable, while NOISE
  (true but stylistic) and GATE (known-false patterns) are reported beside
  them.
- **Sites**: findings from the same rule (for Cppcheck, the same checker
  family) on the same line, Cppcheck null-check reports sharing one anchor,
  and class-scoped Cppcheck reports naming the same class or member merge into
  one place to fix; different rules on one line stay separate sites.
- **Quality index**: `1 / (1 + burden)`, where burden sums severity weight
  (INFO 1, WARNING 2, ERROR 3) × confidence over actionable findings, per
  characteristic.

## What the numbers are not

The counts and the quality index are a **descriptive aggregate of mapped SAST
findings, not an ISO/IEC 25040 quality measurement**. They are comparable
across runs of the same repository, not across repositories, and a
characteristic with no evidence is *unmeasured*, not clean. Semgrep's security
packs map almost entirely to `security`; Cppcheck is the input on which the
other characteristics (reliability, maintainability, performance efficiency,
portability, functional suitability) show up.

The tables are quill's:

- **`data/cwe_to_iso25010.csv`**: 60 CWE rows labelled against ISO/IEC
  25010:2011. quill measured multi-LLM inter-annotator agreement of Fleiss'
  κ 0.81 at the characteristic level and 0.74 at the sub-characteristic level.
- **`data/cppcheck_checker_iso.csv`**: 44 checker ids. It was drafted by one
  reader and checked against the source, but no second annotator has labelled
  it yet. Treat Cppcheck mappings accordingly.

Module comments cite sections of quill's research notes
(`docs/PHASE2_IDEAS.md` §5.1x) and, in places, quill's LLM pipeline; neither is
part of this repository.

## Licence

MIT; see [`LICENSE`](./LICENSE). Semgrep, Opengrep and Cppcheck are separate
tools under their own licences, installed at run time and not redistributed.
Semgrep Registry rules (`p/default`, …) are fetched by Semgrep under the
Semgrep Rules License; no rule file is part of this repository.
