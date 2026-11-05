"""The standard build review loop's decision (Droidtop/tracker#550).

Owner, 2026-10-15, verbatim: "No. We check the build itself for issues. If
we find some, then we attempt a rebuild. if that rebuild has the same
issues, then the issue is in the code (whether the code was tampered with or
not was irrelevant, we may find unknown legitimate vulnerabilities during
this process). We patch the code, rebuild, and retest. this should be our
standard build review system"

Outcomes, per release:
- approved: the build is clean. Eligible for (re-)signing.
- rebuilt: the build had findings and a rebuild from the same commit is
  clean, so the published build was the problem. The rebuild's artefacts
  are what gets signed.
- refused: everything else, listed for the owner with a reason:
  - code: the rebuild has the same findings; the issue is in the code. An
    issue is filed and the fix goes through the owning lane; the fixed
    build passes this same loop.
  - unreviewable: an analyser could not run (or no profile), so the review
    is incomplete. ("Releases that fail, or can't be reviewed, aren't
    re-signed.")
  - not-rebuildable: no source at the commit, or the build would not run.
  - rebuild-differs: the rebuild has findings, but different ones: the
    build isn't reproducible enough to tell the build from the code.
"""
from __future__ import annotations

from .findings import Finding


def _blocking(rec: dict) -> dict[str, dict]:
    return {f["fingerprint"]: f for f in rec.get("findings", []) if f.get("blocking")}


def needs_rebuild(original: dict) -> bool:
    return not original.get("clean") and not original.get("unreviewable")


def decide(original: dict, rebuild: dict | None = None, rebuild_error: str = "") -> dict:
    base = {"repo": original["repo"], "release": original["release"], "commit": original.get("commit", ""),
            "artefacts": original.get("artefacts", [])}
    ob = _blocking(original)
    if original.get("unreviewable"):
        return {**base, "outcome": "refused", "reason": "unreviewable",
                "summary": "The review could not be completed: " +
                           "; ".join(f["title"] for f in original["findings"] if f["category"] == "harness"
                                     and f.get("blocking"))[:600]}
    if original.get("clean"):
        return {**base, "outcome": "approved", "reason": "clean",
                "summary": "No blocking findings." + _nonblocking(original)}
    if rebuild is None:
        return {**base, "outcome": "refused", "reason": "not-rebuildable",
                "summary": f"{len(ob)} blocking finding(s); the release could not be rebuilt from its commit"
                           + (f": {rebuild_error}" if rebuild_error else ".")}
    if rebuild.get("unreviewable"):
        return {**base, "outcome": "refused", "reason": "unreviewable",
                "summary": "The rebuild's review could not be completed."}
    rb = _blocking(rebuild)
    if not rb:
        return {**base, "outcome": "rebuilt", "reason": "build",
                "rebuiltArtefacts": rebuild.get("artefacts", []),
                "summary": f"The published build had {len(ob)} blocking finding(s) that a rebuild from the same "
                           "commit does not: the published build was the problem. Sign the rebuild."}
    same = sorted(set(ob) & set(rb))
    if same:
        return {**base, "outcome": "refused", "reason": "code", "fingerprints": same,
                "findings": [ob[f] for f in same],
                "summary": f"The rebuild has the same {len(same)} blocking finding(s): the issue is in the code. "
                           "Fix in the owning lane; the fixed build goes through this loop."}
    return {**base, "outcome": "refused", "reason": "rebuild-differs",
            "summary": f"The published build has {len(ob)} blocking finding(s) and the rebuild has {len(rb)} "
                       "different ones: the build is not reproducible enough to tell build from code."}


def _nonblocking(rec: dict) -> str:
    c = rec.get("counts", {})
    n = c.get("medium", 0) + c.get("low", 0)
    return f" {n} non-blocking finding(s) recorded in the report." if n else ""


def gate_passes(decision: dict) -> bool:
    """The standing CI gate: only these may be signed."""
    return decision["outcome"] in ("approved", "rebuilt")


__all__ = ["decide", "needs_rebuild", "gate_passes", "Finding"]
