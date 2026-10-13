from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field, field_validator, model_validator

ISOCharacteristic = Literal[
    "functional_suitability",
    "performance_efficiency",
    "compatibility",
    "usability",
    "reliability",
    "security",
    "maintainability",
    "portability",
]

# ISO/IEC 25010:2011 — 31 sub-characteristics grouped by parent characteristic.
ISO_SUBCHARACTERISTICS: dict[str, frozenset[str]] = {
    "functional_suitability": frozenset(
        {"functional_completeness", "functional_correctness", "functional_appropriateness"}
    ),
    "performance_efficiency": frozenset(
        {"time_behaviour", "resource_utilization", "capacity"}
    ),
    "compatibility": frozenset({"co_existence", "interoperability"}),
    "usability": frozenset(
        {
            "appropriateness_recognizability",
            "learnability",
            "operability",
            "user_error_protection",
            "user_interface_aesthetics",
            "accessibility",
        }
    ),
    "reliability": frozenset(
        {"maturity", "availability", "fault_tolerance", "recoverability"}
    ),
    "security": frozenset(
        {
            "confidentiality",
            "integrity",
            "non_repudiation",
            "accountability",
            "authenticity",
        }
    ),
    "maintainability": frozenset(
        {"modularity", "reusability", "analysability", "modifiability", "testability"}
    ),
    "portability": frozenset({"adaptability", "installability", "replaceability"}),
}

ALL_SUBCHARACTERISTICS: frozenset[str] = frozenset().union(*ISO_SUBCHARACTERISTICS.values())

Severity = Literal["INFO", "WARNING", "ERROR"]

# The static-analysis CLI that produced a run's findings (equill.scan). Opengrep
# is the LGPL-2.1 fork of Semgrep CE 1.100.0: same rule syntax and JSON output,
# but it fills ``extra.lines`` with the matched source where an unauthenticated
# Semgrep writes ``requires login``.
# Cppcheck (equill.cppcheck) is the C/C++ quality scanner of the Phase 2 study:
# its findings carry a checker id and a quality CWE (398, 563, 476, ...) rather
# than an OWASP tag, and are mapped by checker id (equill.checker_table).
Scanner = Literal["semgrep", "opengrep", "cppcheck"]
SCANNERS: tuple[Scanner, ...] = ("semgrep", "opengrep", "cppcheck")
# The Semgrep-compatible CLIs: same subcommand, same JSON (equill.scan).
SEMGREP_FAMILY: tuple[Scanner, ...] = ("semgrep", "opengrep")

# A finding's prior class from the checker-id table (quill's docs/PHASE2_IDEAS.md 5.1d),
# a property of the checker that fired, not of the mapper: BUG and QUALITY are
# actionable evidence; NOISE is true but stylistic (scope narrowing, const,
# casts), which the 5.1b triage found to be about 78 % of true Cppcheck
# findings; GATE is a known-false pattern (e.g. uninitvar through uthash
# macros, 0/12 true). equill.score counts only BUG and QUALITY toward burden.
# None is what every Semgrep/Opengrep finding carries: no class, all counted.
EvidenceClass = Literal["BUG", "QUALITY", "NOISE", "GATE"]
EVIDENCE_CLASSES: tuple[EvidenceClass, ...] = ("BUG", "QUALITY", "NOISE", "GATE")
ACTIONABLE_CLASSES: frozenset[str] = frozenset({"BUG", "QUALITY"})

# Max length of a Mapping rationale. The prompt asks for a single sentence
# (≤ this many chars); an over-long answer is clipped rather than rejected so a
# mapping whose char/sub is correct but whose prose ran long is still a primary
# success instead of an avoidable fallback.
RATIONALE_MAX_LENGTH = 400


def _canonical_iso(value: str) -> str:
    """Lower-case and underscore-normalise an ISO label so minor formatting
    variants ("Security", "time behaviour") match the canonical enum values."""
    return value.strip().lower().replace(" ", "_").replace("-", "_")


def _coalesce_iso_sub(raw: str, iso_char: object) -> str:
    """Resolve a possibly ``/``-separated list of candidate subs to one value.

    Small models sometimes answer ``iso_sub`` with several candidates joined by
    slashes (e.g. ``"integrity/security/confidentiality"``) despite the prompt
    asking for exactly one. Rather than discard an otherwise-correct mapping and
    pay for a fallback call, pick the first listed candidate that is a recognised
    sub-characteristic *and* belongs to the declared ``iso_char``; failing that,
    the first recognised sub-characteristic; failing that, the canonicalised
    first token so the validator still reports the model's answer verbatim. A
    value with no slash is simply canonicalised. This parses the model's stated
    answer faithfully — it never invents a sub the model did not name.
    """
    parts = [p for p in (_canonical_iso(t) for t in raw.split("/")) if p]
    if len(parts) <= 1:
        return parts[0] if parts else _canonical_iso(raw)
    allowed = ISO_SUBCHARACTERISTICS.get(iso_char) if isinstance(iso_char, str) else None
    if allowed:
        for p in parts:
            if p in allowed:
                return p
    for p in parts:
        if p in ALL_SUBCHARACTERISTICS:
            return p
    return parts[0]


class Finding(BaseModel):
    rule_id: str
    file: str
    line: int = Field(ge=0)
    owasp: list[str] = Field(default_factory=list)
    cwe: list[str] = Field(default_factory=list)
    severity: Severity
    message: str
    snippet: str
    # Prior class of the checker that fired (EvidenceClass). Set by the Cppcheck
    # adapter from the checker-id table; None for every Semgrep/Opengrep
    # finding and every report written before this field existed, so an absent
    # key and None read the same: counted in full, as before.
    evidence_class: EvidenceClass | None = None
    # Secondary locations the scanner attached to the finding, as ``file:line``.
    # Cppcheck's null-pointer checks point every report at the one redundant
    # condition they share, which equill.rootcause uses to merge them into one
    # site. Empty for Semgrep/Opengrep findings and for older reports.
    related_locations: list[str] = Field(default_factory=list)


class Mapping(BaseModel):
    finding_id: str
    owasp: list[str]
    cwe: list[str]
    iso_char: ISOCharacteristic
    iso_sub: str
    confidence: float = Field(ge=0.0, le=1.0)
    rationale: str = Field(max_length=RATIONALE_MAX_LENGTH)
    model: str
    retrieved_ctx_ids: list[str] = Field(default_factory=list)

    @field_validator("rationale", mode="before")
    @classmethod
    def _clip_rationale(cls, v: object) -> object:
        """Clip an over-long rationale to the field limit instead of rejecting it.

        Small models occasionally exceed the single-sentence length cap while the
        mapping itself (char/sub/confidence) is correct. Truncating recovers it as
        a primary success rather than paying for a fallback call. Mirrors
        ``LookupMapper``'s ``rationale[:RATIONALE_MAX_LENGTH]``.
        """
        if isinstance(v, str) and len(v) > RATIONALE_MAX_LENGTH:
            return v[:RATIONALE_MAX_LENGTH]
        return v

    @model_validator(mode="before")
    @classmethod
    def _split_combined_iso(cls, data: object) -> object:
        """Accept the ``characteristic/subcharacteristic`` shorthand that the
        prompt uses (e.g. ``security/integrity``) when a model echoes it whole
        into ``iso_char``. Split it into the two fields and underscore-normalise
        both, backfilling ``iso_sub`` only when the model did not supply a
        recognised one. This parses the model's stated answer faithfully; it
        does not invent a characteristic the model did not name.
        """
        if not isinstance(data, dict):
            return data
        out = dict(data)
        char = out.get("iso_char")
        if isinstance(char, str):
            canon = _canonical_iso(char)
            if "/" in canon:
                char_part, _, sub_part = canon.partition("/")
                canon = char_part
                sub = out.get("iso_sub")
                sub_canon = _canonical_iso(sub) if isinstance(sub, str) else None
                if sub_canon not in ALL_SUBCHARACTERISTICS:
                    out["iso_sub"] = sub_part
            out["iso_char"] = canon
        sub = out.get("iso_sub")
        if isinstance(sub, str):
            out["iso_sub"] = _coalesce_iso_sub(sub, out.get("iso_char"))
        return out

    @field_validator("iso_sub")
    @classmethod
    def _sub_in_allowed(cls, v: str) -> str:
        if v not in ALL_SUBCHARACTERISTICS:
            raise ValueError(f"iso_sub {v!r} is not a recognised ISO/IEC 25010 sub-characteristic")
        return v

    def model_post_init(self, __context: object) -> None:
        allowed = ISO_SUBCHARACTERISTICS[self.iso_char]
        if self.iso_sub not in allowed:
            raise ValueError(
                f"iso_sub {self.iso_sub!r} does not belong to iso_char {self.iso_char!r}"
            )


class Report(BaseModel):
    benchmark: str
    commit_sha: str
    # Optional so existing report.json artifacts still load. Required by SARIF's
    # versionControlDetails, which cannot carry a revisionId without it. When
    # absent, the SARIF export omits the whole block rather than emitting an
    # invalid one, and commit_sha rides in run properties.
    repository_uri: str | None = None
    findings: list[Finding]
    mappings: list[Mapping]
    coverage: float = Field(ge=0.0, le=1.0)
    mean_confidence: float = Field(ge=0.0, le=1.0)
    # The ISO category order the mapping prompt used. None
    # is the canonical order, which is what every report written before this
    # field existed used: no production path passed a seed until this field
    # was added, so an absent key and None read the same.
    prompt_order_seed: int | None = None
    # Whether a ``requires login`` scanner placeholder was replaced by the flagged
    # source lines (PipelineConfig.snippet_fallback). False is what every report
    # written before this field existed used -- the scanner's text, placeholder
    # included -- so an absent key and False read the same.
    snippet_fallback: bool = False
    # Which CLI produced ``findings`` (PipelineConfig.scanner). Every report
    # written before this field existed came from Semgrep, so an absent key and
    # "semgrep" read the same. An "opengrep" report's snippets carry source code
    # even with snippet_fallback False, so it is not the published condition.
    # A "cppcheck" report is the Phase 2 input: C/C++ quality findings keyed by
    # checker id.
    scanner: Scanner = "semgrep"
    # The path-exclusion pattern applied to the scanner's findings (test, fuzz
    # and example directories; equill.cppcheck.DEFAULT_PATH_EXCLUDE), or None
    # when none was: the published Semgrep runs excluded nothing.
    path_exclude: str | None = None
    # The rules the scan ran with, as a short provenance string: for the default
    # open rules "opengrep/opengrep-rules@<commit> (<folders>)", otherwise the
    # --config values. None for a recorded scanner output or a Cppcheck run.
    rules: str | None = None
