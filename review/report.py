"""Human-readable report and filed-issue body, from a review record."""
from __future__ import annotations

ICON = {"critical": "CRITICAL", "high": "HIGH", "medium": "medium", "low": "low", "info": "info"}


def markdown(rec: dict, decision: dict | None = None, run_url: str = "") -> str:
    lines = [f"# Build review: {rec['repo']} `{rec['release']}`", ""]
    if decision:
        lines += [f"**Outcome: {decision['outcome']}** ({decision['reason']}). {decision['summary']}", ""]
    lines += [f"- Commit: `{rec.get('commit') or 'unknown'}`", f"- Stage: {rec['stage']}",
              f"- Harness: {rec['harness']}, {rec['generatedAt']}"]
    if run_url:
        lines.append(f"- Run: {run_url}")
    lines.append(f"- Dynamic run: {'yes' if rec.get('dynamicRan') else 'no'}"
                 f"{' (needed)' if rec.get('needsDynamic') and not rec.get('dynamicRan') else ''}")
    lines += ["", "| Artefact | Kind | SHA-256 |", "|---|---|---|"]
    for a in rec["artefacts"]:
        lines.append(f"| {a['name']} | {a['kind']} | `{a['sha256']}` |")
    c = rec["counts"]
    lines += ["", f"Findings: {c['critical']} critical, {c['high']} high, {c['medium']} medium, {c['low']} low, "
                  f"{c['info']} info. High and critical block.", ""]
    if rec["findings"]:
        lines += ["| Severity | Rule | Where | What |", "|---|---|---|---|"]
        for f in rec["findings"]:
            if f["severity"] == "info":
                continue
            lines.append(f"| {ICON[f['severity']]} | `{f['rule']}` | `{_cell(f['location'])}` | {_cell(f['title'])} |")
        ev = [f for f in rec["findings"] if f["blocking"] and f.get("evidence")]
        if ev:
            lines += ["", "## Evidence (blocking findings)", ""]
            for f in ev[:40]:
                lines += [f"**`{f['rule']}`** at `{_cell(f['location'])}` (fingerprint `{f['fingerprint']}`)",
                          "```", f["evidence"][:1500], "```", ""]
    d = rec.get("diff") or {}
    if d.get("previous"):
        lines += ["", f"## Changes since `{d['previous']}`", ""]
        for k, v in d.items():
            if k == "previous" or not isinstance(v, dict):
                continue
            if "added" in v:
                lines.append(f"- {k}: +{', '.join(v['added']) or 'none'}; -{', '.join(v['removed']) or 'none'}")
    return "\n".join(lines) + "\n"


def _cell(s: str) -> str:
    return str(s).replace("|", "\\|").replace("\n", " ")[:200]


def issue_draft(decision: dict) -> dict:
    """What the coordinator files on Droidtop/tracker (label build-review)
    for a refused (code) release: title, body and labels, with the evidence."""
    fps = ", ".join(f"`{f}`" for f in decision.get("fingerprints", []))
    repo = decision["repo"]
    lines = [
        f"The build review harness found blocking issues in {repo} `{decision['release']}` "
        f"(commit `{decision.get('commit') or 'unknown'}`), and a rebuild from the same commit has the same ones, "
        "so the issue is in the code (Droidtop/tracker#550, the standard build review loop, step 3).",
        "",
        f"Report: {decision.get('reportUrl') or '(in the run)'}",
        "",
        f"Owning repo: {repo}. Fix it in the code through its own lane. The fixed build goes through the same "
        "review before it is signed; this release stays refused.",
        "",
        "| Severity | Rule | Where | What |", "|---|---|---|---|",
    ]
    for f in decision.get("findings", []):
        lines.append(f"| {f['severity']} | `{f['rule']}` | `{_cell(f['location'])}` | {_cell(f['title'])} |")
    ev = [f for f in decision.get("findings", []) if f.get("evidence")]
    if ev:
        lines += ["", "Evidence:", ""]
        for f in ev[:20]:
            lines += [f"`{f['rule']}` at `{_cell(f['location'])}`:", "```", f["evidence"][:1200], "```"]
    lines += ["", f"<!-- build-review: repo={repo} fingerprints={fps} -->"]
    n = len(decision.get("fingerprints", []))
    return {"repo": "Droidtop/tracker", "labels": ["build-review"],
            "title": f"{repo.split('/')[-1]}: build review finds {n} issue(s) in the code ({decision['release']})",
            "body": "\n".join(lines)}
