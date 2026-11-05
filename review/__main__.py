"""Command line: `python -m review <command>`. The workflows call these; so
can a person, against a local file, with the same result.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from . import batch, decide as dec, profile as prof, report, static
from .analysers import behaviour


def _w(path: str, data) -> None:
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text(json.dumps(data, indent=2, sort_keys=False) + "\n")


def _r(path: str):
    return json.loads(Path(path).read_text())


def _out(name: str, value: str) -> None:
    """A step output for the workflow, and a line on stdout."""
    print(f"{name}={value}")
    gh_out = os.environ.get("GITHUB_OUTPUT")
    if gh_out:
        with open(gh_out, "a") as fh:
            if "\n" in value:
                fh.write(f"{name}<<__EOF__\n{value}\n__EOF__\n")
            else:
                fh.write(f"{name}={value}\n")


def cmd_profile(a):
    p = prof.load(a.repo)
    if a.field:
        cur = p.__dict__
        for part in a.field.split("."):
            cur = cur.get(part, "") if isinstance(cur, dict) else ""
        if isinstance(cur, bool):
            print(str(cur).lower())
        else:
            print(json.dumps(cur) if isinstance(cur, (list, dict)) else cur)
    else:
        print(json.dumps(p.__dict__, indent=2))


def cmd_fetch(a):
    """Download a release's reviewable assets, and say which release came before it."""
    from .gh import GitHub

    gh = GitHub()
    p = prof.load(a.repo)
    rels = sorted(gh.releases(a.repo), key=lambda r: r.get("published_at") or r.get("created_at") or "")
    cur = next((r for r in rels if r["tag_name"] == a.tag), None)
    if cur is None:
        sys.exit(f"{a.repo} has no release {a.tag}")

    def wanted(asset):
        if p.artefacts:
            return p.kind_for(asset["name"]) is not None
        return not asset["name"].endswith((".sha256", ".txt", ".md", ".sig", ".asc"))

    got = [gh.download_asset(a.repo, x, Path(a.out)) for x in cur.get("assets", []) if wanted(x)]
    try:
        commit = gh.tag_commit(a.repo, a.tag)
    except Exception:  # noqa: BLE001 - a deleted tag: the release's target is all there is
        commit = cur.get("target_commitish", "")
    idx = rels.index(cur)
    prev = next((r for r in reversed(rels[:idx]) if any(wanted(x) for x in r.get("assets", []))), None)
    if prev and a.previous_out:
        for x in prev.get("assets", []):
            if wanted(x):
                gh.download_asset(a.repo, x, Path(a.previous_out))
    _out("commit", commit)
    _out("assets", str(len(got)))
    _out("previous", prev["tag_name"] if prev else "")
    if not got:
        sys.exit(f"{a.repo}@{a.tag} has no reviewable assets")


def _kinds(pairs):
    return dict(x.split("=", 1) for x in (pairs or []))


def cmd_review(a):
    p = prof.load(a.repo)
    arts = []
    for x in a.artefacts:
        x = Path(x)
        arts += sorted(q for q in x.rglob("*") if q.is_file()) if x.is_dir() else [x]
    if p.artefacts:
        arts = [q for q in arts if p.kind_for(q.name)] or arts
    prev = None
    if a.previous and Path(a.previous).exists():
        pr = _r(a.previous)
        prev = dict(pr.get("facts", {}), release=pr.get("release"))
    rec = static.review_release(arts, p, repo=a.repo, release=a.release, commit=a.commit or "",
                                stage=a.stage, source=Path(a.source) if a.source else None, previous=prev,
                                kinds=_kinds(a.kind))
    _w(a.out, rec)
    _out("clean", str(rec["clean"]).lower())
    _out("unreviewable", str(rec["unreviewable"]).lower())
    _out("needs_dynamic", str(rec["needsDynamic"]).lower())
    _out("apks", " ".join(str(q) for q in arts if q.suffix == ".apk"))


def cmd_judge_dynamic(a):
    rec = _r(a.record)
    facts: dict = {}
    found = behaviour.dynamic(Path(a.trace), prof.load(rec["repo"]), facts)
    rec = static.merge_dynamic(rec, found, facts)
    _w(a.out or a.record, rec)
    _out("clean", str(rec["clean"]).lower())


def cmd_decide(a):
    original = _r(a.original)
    rebuild = _r(a.rebuild) if a.rebuild and Path(a.rebuild).exists() else None
    d = dec.decide(original, rebuild, a.rebuild_error or "")
    d["reportUrl"] = a.report_url or ""
    d["runUrl"] = a.run_url or ""
    d["reviewedAt"] = (rebuild or original).get("generatedAt", "")
    if d["reason"] == "code":
        # The harness never writes to the tracker (owner, 2026-11-05: "Drop
        # the token, file the issues yourself"); the coordinator files the
        # build-review issue from this draft in the results.
        d["issueDraft"] = report.issue_draft(d)
    _w(a.out, d)
    Path(a.markdown).write_text(report.markdown(original, d, a.run_url or "") +
                                ("\n---\n\n" + report.markdown(rebuild, None) if rebuild else ""))
    _out("outcome", d["outcome"])
    _out("reason", d["reason"])

    print(d["summary"])
    if a.gate and not dec.gate_passes(d):
        sys.exit(f"build review gate: {d['outcome']} ({d['reason']})")


def cmd_needs_rebuild(a):
    _out("rebuild", str(dec.needs_rebuild(_r(a.record))).lower())


def cmd_batch_plan(a):
    text = Path(a.releases_file).read_text() if a.releases_file and Path(a.releases_file).exists() else ""
    if text.strip():
        items = batch.parse(text, "pasted")
    else:
        from .gh import GitHub
        items = batch.from_releases(GitHub(), a.repos)
    items = batch.plan(items, a.repos, a.tags, a.limit, a.redo)
    matrix = [{"repo": i.repo, "tag": i.tag} for i in items]
    if len(matrix) > 256:
        sys.exit(f"{len(matrix)} releases selected; a run takes at most 256 (GitHub's matrix limit). "
                 "Narrow with repos/tags/limit.")
    print(f"{len(matrix)} release(s) planned: " + ", ".join(f"{m['repo']}@{m['tag']}" for m in matrix))
    _out("matrix", json.dumps({"include": matrix}))
    _out("count", str(len(matrix)))


def cmd_publish(a):
    """The audit results, published with the catalog beside the revocation list."""
    entries = []
    for f in sorted(Path(a.results).rglob("decision.json")):
        d = _r(f)
        entries.append({k: d.get(k) for k in ("repo", "release", "commit", "outcome", "reason", "summary",
                                              "reportUrl", "artefacts", "rebuiltArtefacts", "fingerprints",
                                              "findings", "issueDraft", "reviewedAt") if d.get(k)})
    prev = _r(a.merge) if a.merge and Path(a.merge).exists() else {"entries": []}
    keyed = {f"{e['repo']}@{e['release']}": e for e in prev.get("entries", [])}
    keyed.update({f"{e['repo']}@{e['release']}": e for e in entries})
    out = {"schema": "droidtop.build-review-results/1", "event": a.event, "policy": "Droidtop/tracker#550",
           "entries": sorted(keyed.values(), key=lambda e: (e["repo"], e["release"]))}
    out["counts"] = {o: sum(1 for e in out["entries"] if e["outcome"] == o) for o in batch.OUTCOMES}
    out["toFile"] = [f"{e['repo']}@{e['release']}" for e in out["entries"] if e.get("issueDraft")]
    _w(a.out, out)
    print(json.dumps(out["counts"]))


def main(argv=None):
    ap = argparse.ArgumentParser(prog="review")
    sub = ap.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("profile"); s.add_argument("repo"); s.add_argument("--field"); s.set_defaults(f=cmd_profile)

    s = sub.add_parser("fetch")
    s.add_argument("--repo", required=True); s.add_argument("--tag", required=True)
    s.add_argument("--out", required=True); s.add_argument("--previous-out")
    s.set_defaults(f=cmd_fetch)

    s = sub.add_parser("review")
    s.add_argument("--repo", required=True); s.add_argument("--release", required=True)
    s.add_argument("--commit"); s.add_argument("--stage", default="original", choices=["original", "rebuild"])
    s.add_argument("--source"); s.add_argument("--previous", help="the earlier release's record.json")
    s.add_argument("--kind", action="append", help="name=kind, overriding detection")
    s.add_argument("--out", required=True); s.add_argument("artefacts", nargs="+")
    s.set_defaults(f=cmd_review)

    s = sub.add_parser("judge-dynamic")
    s.add_argument("--record", required=True); s.add_argument("--trace", required=True); s.add_argument("--out")
    s.set_defaults(f=cmd_judge_dynamic)

    s = sub.add_parser("needs-rebuild"); s.add_argument("--record", required=True); s.set_defaults(f=cmd_needs_rebuild)

    s = sub.add_parser("decide")
    s.add_argument("--original", required=True); s.add_argument("--rebuild"); s.add_argument("--rebuild-error")
    s.add_argument("--out", required=True); s.add_argument("--markdown", required=True)
    s.add_argument("--report-url"); s.add_argument("--run-url"); s.add_argument("--gate", action="store_true")
    s.set_defaults(f=cmd_decide)

    s = sub.add_parser("batch-plan")
    s.add_argument("--releases-file", help="pasted inventory lines or owner/repo@tag lines; empty: list releases")
    s.add_argument("--repos", default="*"); s.add_argument("--tags", default="*")
    s.add_argument("--limit", type=int, default=0); s.add_argument("--redo", action="store_true")
    s.set_defaults(f=cmd_batch_plan)

    s = sub.add_parser("publish")
    s.add_argument("--results", required=True); s.add_argument("--out", required=True)
    s.add_argument("--event", default=""); s.add_argument("--merge")
    s.set_defaults(f=cmd_publish)

    a = ap.parse_args(argv)
    a.f(a)


if __name__ == "__main__":
    main()
