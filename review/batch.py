"""The batch runner: works through an inventory issue's checklist.

The inventory (Droidtop/tracker#876) is one issue whose checklist runs on
through its first comments past GitHub's body limit. Each line is

    - [ ] `<tag>` <date>[ pre] | <signer evidence>

under a `### <owner>/<repo> (<count>)` heading. The runner plans which lines
to review (unticked, filtered), and afterwards ticks each reviewed line with
its outcome and a link to its report, leaving the evidence text as it was:

    - [x] `<tag>` <date> | <evidence> — **approved**, [report](<url>)

A line is only ticked for a final outcome (approved, rebuilt, refused); a
review that fails to run leaves it unticked for the next pass.
"""
from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass

HEAD_RE = re.compile(r"^###\s+([\w.-]+/[\w.-]+)\b")
LINE_RE = re.compile(r"^(?P<pre>\s*-\s\[)(?P<box>[ xX])(?P<mid>\]\s+`(?P<tag>[^`]+)`(?P<rest>.*?))"
                     r"(?P<result>\s+—\s+\*\*(?:approved|rebuilt|refused)\*\*.*)?$")
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


BODY_LIMIT = 65_000  # GitHub refuses issue bodies and comments over 65,536 characters


def tick(text: str, results: dict[str, dict], repo: str | None = None,
         limit: int = BODY_LIMIT) -> tuple[str, int, list[str]]:
    """results: {"repo@tag": {"outcome", "reason", "report"}}.

    Returns (new text, lines changed, keys ticked without their link). The
    inventory sits near GitHub's size limit, so each tick carries its report
    link only while the part has room; past that the tick carries the
    outcome alone and the link is in the runner's results comment (one per
    repo, `results_comment`), which the inventory links to.
    """
    lines, changed, linkless = text.splitlines(), 0, []
    size = len(text)
    for i, line in enumerate(lines):
        h = HEAD_RE.match(line)
        if h:
            repo = h.group(1)
            continue
        m = LINE_RE.match(line)
        if not (m and repo):
            continue
        key = f"{repo}@{m.group('tag')}"
        r = results.get(key)
        if not r or r.get("outcome") not in OUTCOMES:
            continue
        reason = f" ({r['reason']})" if r.get("reason") and r["outcome"] == "refused" else ""
        head = f"{m.group('pre')}x{m.group('mid')} — **{r['outcome']}**{reason}"
        new = head + (f", [report]({r['report']})" if r.get("report") else "")
        if size - len(line) + len(new) > limit:
            new = head
            linkless.append(key)
            if size - len(line) + len(new) > limit:
                new = f"{m.group('pre')}x{m.group('mid')} — {r['outcome']}"
        if new != line:
            size += len(new) - len(line)
            lines[i] = new
            changed += 1
    tail = "\n" if text.endswith("\n") else ""
    return "\n".join(lines) + tail, changed, linkless


RESULTS_MARK = "<!-- build-review:results repo={repo} -->"


def results_comment(repo: str, rows: dict[str, dict]) -> str:
    """The runner's own per-repo results comment: every reviewed release of
    `repo`, its outcome and its report. Edited in place on each pass."""
    lines = [RESULTS_MARK.format(repo=repo), f"### Build review results: {repo}", "",
             "| Release | Outcome | Report |", "|---|---|---|"]
    for key in sorted(rows, key=lambda k: rows[k].get("reviewedAt", ""), reverse=True):
        r = rows[key]
        out = r["outcome"] + (f" ({r['reason']})" if r.get("reason") and r["outcome"] == "refused" else "")
        rep = f"[report]({r['report']})" if r.get("report") else ""
        lines.append(f"| `{key.split('@', 1)[1]}` | **{out}** | {rep} |")
    return "\n".join(lines) + "\n"


def parse_results_comment(text: str) -> dict[str, dict]:
    m = re.search(r"build-review:results repo=([\w./-]+)", text)
    if not m:
        return {}
    repo, out = m.group(1), {}
    for line in text.splitlines():
        r = re.match(r"^\| `([^`]+)` \| \*\*(approved|rebuilt|refused)(?: \(([\w-]+)\))?\*\* \|(?: \[report\]\(([^)]+)\))? \|", line)
        if r:
            out[f"{repo}@{r.group(1)}"] = {"outcome": r.group(2), "reason": r.group(3) or "",
                                          "report": r.group(4) or ""}
    return out


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
