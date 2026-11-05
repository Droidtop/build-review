"""The batch runner: works through an inventory issue's checklist.

The inventory (Droidtop/tracker#876) is one issue whose checklist runs on
through its first comments past GitHub's body limit. Each line is

    - [ ] `<tag>` <date>[ pre] | <signer evidence>

under a `### <owner>/<repo> (<count>)` heading. The runner only reads it: it
plans which lines to review (unticked, filtered), and the outcomes go into
build-review-results.json, never back into the issue (owner, 2026-11-05:
"Drop the token, file the issues yourself").
"""
from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass

HEAD_RE = re.compile(r"^###\s+([\w.-]+/[\w.-]+)\b")
LINE_RE = re.compile(r"^\s*-\s\[(?P<box>[ xX])\]\s+`(?P<tag>[^`]+)`(?P<rest>.*)$")
OUTCOMES = ("approved", "rebuilt", "refused")


@dataclass
class Item:
    repo: str
    tag: str
    done: bool
    source: str      # "body" or a comment id
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


def last_repo(text: str, repo: str | None = None) -> str | None:
    for line in text.splitlines():
        h = HEAD_RE.match(line)
        if h:
            repo = h.group(1)
    return repo


def load_inventory(gh, repo: str, number: int, comment_limit: int = 2):
    """[(source, text, comment_id|None, repo_in_force)] for the body and the
    first comments by the issue's author that carry checklist lines: the
    inventory's own continuation past the body limit."""
    issue = gh.issue(repo, number)
    author = (issue.get("user") or {}).get("login")
    body = issue.get("body") or ""
    parts = [("body", body, None, None)]
    current = last_repo(body)
    taken = 0
    for c in gh.comments(repo, number):
        if taken >= comment_limit:
            break
        text = c.get("body") or ""
        if (c.get("user") or {}).get("login") != author or not any(LINE_RE.match(l) for l in text.splitlines()):
            continue
        parts.append((str(c["id"]), text, c["id"], current))
        current = last_repo(text, current)
        taken += 1
    return parts


def items_of(parts) -> list[Item]:
    out = []
    for source, text, _cid, repo in parts:
        out += parse(text, source, repo)
    return out
