"""The batch runner's planner: which releases a run reviews.

It never reads the tracker. The tracker is private and the harness has no
token (owner, 2026-11-05: "Drop the token, file the issues yourself"), so a
run's releases come either from text the coordinator pastes into the run,
or from the named repos' own public releases.

Pasted text can be lines copied from an inventory issue (Droidtop/tracker#876
style, a checklist under `### <owner>/<repo>` headings):

    ### Droidtop/droidtop (396)
    - [ ] `<tag>` <date>[ pre] | <signer evidence>

or one `<owner>/<repo>@<tag>` per line. Ticked lines are skipped unless
`redo` is set. Outcomes go into build-review-results.json, never back into
any issue.
"""
from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass

PAIR_RE = re.compile(r"^\s*(?:-\s*)?(?P<repo>[\w.-]+/[\w.-]+)@(?P<tag>\S+)\s*$")
HEAD_RE = re.compile(r"^###\s+([\w.-]+/[\w.-]+)\b")
LINE_RE = re.compile(r"^\s*-\s\[(?P<box>[ xX])\]\s+`(?P<tag>[^`]+)`(?P<rest>.*)$")
OUTCOMES = ("approved", "rebuilt", "refused")


@dataclass
class Item:
    repo: str
    tag: str
    done: bool
    source: str      # "pasted" or "releases"
    line_no: int
    evidence: str

    @property
    def key(self) -> str:
        return f"{self.repo}@{self.tag}"


def parse(text: str, source: str, repo: str | None = None) -> list[Item]:
    """`repo`: the heading in force where this part starts (a comment that
    continues the body's last section has no heading of its own)."""
    items = []
    for i, line in enumerate(text.splitlines()):
        h = HEAD_RE.match(line)
        if h:
            repo = h.group(1)
            continue
        pair = PAIR_RE.match(line)
        if pair:
            items.append(Item(pair.group("repo"), pair.group("tag"), False, source, i, ""))
            continue
        m = LINE_RE.match(line)
        if m and repo:
            items.append(Item(repo, m.group("tag"), m.group("box") != " ", source, i,
                              m.group("rest").strip(" |")))
    return items


def plan(items: list[Item], repos: str = "*", tags: str = "*", limit: int = 0, redo: bool = False) -> list[Item]:
    globs = [g.strip() for g in repos.split(",") if g.strip()] or ["*"]
    tglobs = [g.strip() for g in tags.split(",") if g.strip()] or ["*"]
    out = [it for it in items
           if (redo or not it.done)
           and any(fnmatch.fnmatch(it.repo, g) for g in globs)
           and any(fnmatch.fnmatch(it.tag, g) for g in tglobs)]
    return out[:limit] if limit else out


def from_releases(gh, repos: str, limit: int = 0) -> list[Item]:
    """The named repos' published releases, newest first (exact names: a
    run that lists releases names its repos)."""
    items = []
    for repo in [r.strip() for r in repos.split(",") if r.strip()]:
        if any(c in repo for c in "*?["):
            raise SystemExit(f"{repo}: name repos exactly when no releases are pasted")
        rels = sorted((r for r in gh.releases(repo) if not r.get("draft")),
                      key=lambda r: r.get("published_at") or r.get("created_at") or "", reverse=True)
        for n, r in enumerate(rels):
            items.append(Item(repo, r["tag_name"], False, "releases", n, ""))
    return items
