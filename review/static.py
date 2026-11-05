"""Review one release: every artefact through every analyser that applies.

Static analysis runs on every artefact. It also says whether the dynamic run
is needed: always for APKs and plugin bundles (their payload is an APK), and
for anything else when a static finding concerns behaviour that only a run
can confirm (owner, 2026-11-04: static on everything, dynamic gated, as the
standard).
"""
from __future__ import annotations

import datetime as dt
import json
import shutil
import tempfile
from pathlib import Path

from . import __version__
from .analysers import apk, behaviour, content, manifests, native
from .extract import extract, kind_of, sha256
from .findings import Finding, apply_explained, blocking_set, raise_severity
from .profile import Profile

RULES = Path(__file__).resolve().parent.parent / "rules"
SCHEMA = "droidtop.build-review/1"
DYNAMIC_KINDS = {"apk", "plugin-bundle"}
DYNAMIC_CATEGORIES = {"malicious", "obfuscation", "process", "network"}


def review_release(artefacts: list[Path], profile: Profile, *, repo: str, release: str, commit: str = "",
                   stage: str = "original", source: Path | None = None, previous: dict | None = None,
                   kinds: dict[str, str] | None = None, facts_only: bool = False) -> dict:
    """facts_only: just what the diff compares (permissions, components, API
    categories, hosts, native files and their imports), for the previous
    release. Its findings are not judged."""
    findings: list[Finding] = []
    facts: dict = {"hosts": {}}
    listed = []
    for art in artefacts:
        kind = (kinds or {}).get(art.name) or profile.kind_for(art.name) or kind_of(art)
        listed.append({"name": art.name, "kind": kind, "sha256": sha256(art), "size": art.stat().st_size})
        findings += review_artefact(art, kind, profile, facts, facts_only, stage)
    if source is not None:
        findings += content.deps_source(source, profile)
    if not profile.known:
        findings.append(Finding("profile", "profile.missing", "high",
                                f"{repo} has no review profile, so its stated purpose is unknown and nothing "
                                "it does can be judged against it.", location=repo, category="harness"))
    findings += behaviour.endpoints(facts, profile)

    facts["hostList"] = sorted(facts.get("hosts", {}))
    facts["nativeList"] = sorted(facts.get("native", {}))
    changes, diff_findings = behaviour.diff(facts, previous, profile)
    findings += diff_findings
    findings = raise_severity(findings, profile.block)
    findings = apply_explained(findings, profile)
    findings = _dedupe(findings)

    needs_dynamic = any(a["kind"] in DYNAMIC_KINDS for a in listed) or any(
        f.blocking and f.category in DYNAMIC_CATEGORIES for f in findings)
    if profile.dynamic.get("skip_reason"):
        needs_dynamic = False
    return _record(repo, release, commit, stage, listed, findings, facts, changes, needs_dynamic)


def review_artefact(art: Path, kind: str, profile: Profile, facts: dict, facts_only: bool = False,
                    stage: str = "original") -> list[Finding]:
    out: list[Finding] = []
    work = Path(tempfile.mkdtemp(prefix="review-"))
    try:
        if kind == "catalog":
            out += manifests.catalog(art, profile, facts)
            shutil.copy(art, work / art.name)
        elif kind == "apk":
            out += extract(art, work / art.name, nested=False)
            found = apk.analyse(str(art), profile, facts, facts_only)
            if profile.entry_for(art.name).get("debug"):
                # The published debug variant (SPEC 10b) is debuggable on
                # purpose; everything else about it is held to the profile.
                found = [f for f in found if f.rule not in ("manifest.debuggable", "manifest.test-only")]
            out += found
        elif kind in ("plugin-bundle", "engine-bundle", "archive"):
            out += extract(art, work / art.name)
            # A rebuild is the unsigned payload: the manifest and signature
            # are made at signing, so a rebuild has none to check. Its
            # payload gets every other analyser, at the same paths.
            unsigned = stage == "rebuild" and not any(
                (work / art.name / n).is_file() for n in manifests.MANIFEST_NAMES.get(kind, ()))
            if kind != "archive" and not unsigned:
                out += manifests.bundle(work / art.name, profile, facts, kind)
            dexes = sorted(str(p) for p in (work / art.name).rglob("*.dex") if ".apk.d" not in str(p))
            if dexes:
                out += apk.analyse_dex(dexes, profile, facts, art.name)
            for inner in sorted((work / art.name).rglob("*.apk")):
                out += apk.analyse(str(inner), profile, facts, facts_only)
        elif kind == "elf" or kind == "native":
            shutil.copy(art, work / art.name)
        else:
            shutil.copy(art, work / art.name)
            out.append(Finding("harness", "harness.unknown-kind", "medium",
                               f"{art.name} is of a kind the harness has no specific analyser for; it gets the "
                               "generic ones only.", location=art.name, category="harness"))
        out += native.analyse(work, profile, facts, capa=not facts_only)
        if facts_only:
            return out
        out += native.yara_scan(work, RULES / "yara")
        out += content.secrets(work, profile)
        out += content.deps_artefact(work, profile, facts)
        out += content.scripts(work, RULES / "semgrep")
    finally:
        shutil.rmtree(work, ignore_errors=True)
    return out


def _dedupe(findings: list[Finding]) -> list[Finding]:
    seen, out = set(), []
    for f in findings:
        if f.fingerprint in seen:
            continue
        seen.add(f.fingerprint)
        out.append(f)
    return sorted(out, key=lambda f: (-("info low medium high critical".split().index(f.severity)), f.rule))


def _record(repo, release, commit, stage, listed, findings, facts, changes, needs_dynamic) -> dict:
    unreviewable = [f for f in findings if f.category == "harness" and f.blocking]
    return {
        "schema": SCHEMA,
        "repo": repo,
        "release": release,
        "commit": commit,
        "stage": stage,
        "artefacts": listed,
        "generatedAt": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
        "harness": __version__,
        "clean": not blocking_set(findings),
        "unreviewable": bool(unreviewable),
        "needsDynamic": needs_dynamic,
        "counts": {s: sum(1 for f in findings if f.severity == s) for s in ("critical", "high", "medium", "low", "info")},
        "findings": [f.to_dict() for f in findings],
        "facts": _jsonable(facts),
        "diff": changes,
    }


def merge_dynamic(record: dict, dyn: list[Finding], dyn_facts: dict) -> dict:
    """Fold the dynamic run's findings into the static record."""
    findings = [Finding.from_dict(d) for d in record["findings"]] + dyn
    findings = _dedupe(findings)
    out = dict(record)
    out["findings"] = [f.to_dict() for f in findings]
    out["clean"] = not blocking_set(findings)
    out["unreviewable"] = any(f.category == "harness" and f.blocking for f in findings)
    out["counts"] = {s: sum(1 for f in findings if f.severity == s) for s in ("critical", "high", "medium", "low", "info")}
    out.setdefault("facts", {}).update(_jsonable(dyn_facts))
    out["dynamicRan"] = True
    return out


def _jsonable(o):
    return json.loads(json.dumps(o, default=str))
