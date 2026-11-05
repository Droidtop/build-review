"""Secrets, dependencies and CVEs, and script payloads.

Real analysers: gitleaks (secrets), Syft and Grype (SBOM and CVEs of what
the artefact ships), OSV-Scanner (CVEs of the source's lockfiles at the
release's commit), Semgrep (rules/semgrep, over script payloads).
"""
from __future__ import annotations

import fnmatch
import json
import tempfile
from pathlib import Path

from ..findings import Finding
from ..profile import Profile
from ..tools import harness_finding, run, run_json

# Public material that is supposed to ship: certificates and public keys.
PUBLIC_OK = ("enginehost-public-key.json", "droidtop-plugin-key.json", ".pem.pub", ".crt", ".cer")


def secrets(root: Path, profile: Profile) -> list[Finding]:
    out = []
    with tempfile.TemporaryDirectory() as tmp:
        report = Path(tmp) / "gitleaks.json"
        try:
            run(["gitleaks", "dir", str(root), "--no-banner", "--redact=80", "--report-format", "json",
                 "--config", str(Path(__file__).resolve().parent.parent.parent / "rules" / "gitleaks.toml"),
                 "--report-path", str(report), "--exit-code", "0", "--max-target-megabytes", "64"], timeout=1800)
            data = json.loads(report.read_text() or "[]")
        except Exception as e:  # noqa: BLE001
            return [harness_finding("gitleaks", e)]
    for leak in data:
        rel = leak.get("File", "")
        try:
            rel = str(Path(rel).relative_to(root))
        except ValueError:
            pass
        rule = leak.get("RuleID", "generic")
        # Profile entries are "<path glob>:<rule id>", each with its reason.
        if rel.endswith(PUBLIC_OK) or any(fnmatch.fnmatch(f"{rel}:{rule}", g) for g in profile.secrets_ignore):
            continue
        sev = "critical" if "private-key" in rule or rule in ("pkcs12-file",) else "high"
        out.append(Finding("secrets", f"secret.{rule}", sev,
                           f"gitleaks finds a {rule} secret embedded in the build.",
                           location=f"{rel}:{leak.get('StartLine', '')}", evidence=leak.get("Match", ""),
                           category="secret"))
    return out


SEV_MAP = {"Critical": "critical", "High": "high", "Medium": "medium", "Low": "low",
           "Negligible": "info", "Unknown": "low"}


def deps_artefact(root: Path, profile: Profile, facts: dict) -> list[Finding]:
    with tempfile.TemporaryDirectory() as tmp:
        sbom = Path(tmp) / "sbom.cdx.json"
        try:
            run(["syft", f"dir:{root}", "-q", "-o", f"cyclonedx-json={sbom}"], timeout=1800)
            facts["sbomComponents"] = len(json.loads(sbom.read_text()).get("components", []))
            data = run_json(["grype", f"sbom:{sbom}", "-q", "-o", "json"], timeout=1800)
        except Exception as e:  # noqa: BLE001
            return [harness_finding("syft/grype", e)]
    return _grype(data, profile, "artefact")


def _grype(data, profile: Profile, where: str) -> list[Finding]:
    out = []
    for m in (data or {}).get("matches", []):
        v, art = m.get("vulnerability", {}), m.get("artifact", {})
        vid = v.get("id", "")
        if vid in profile.cve_ignore:
            continue
        fixed = (v.get("fix") or {}).get("versions") or []
        sev = SEV_MAP.get(v.get("severity", "Unknown"), "low")
        out.append(Finding("deps", f"cve.{vid}", sev,
                           f"{art.get('name')} {art.get('version')} has {vid}"
                           + (f" (fixed in {', '.join(fixed)})." if fixed else " (no fix yet)."),
                           location=f"{where}:{art.get('name')}", evidence=v.get("description", "")[:500],
                           category="dependency"))
    return out


def deps_source(src: Path, profile: Profile) -> list[Finding]:
    if not src or not src.exists():
        return []
    try:
        data = run_json(["osv-scanner", "scan", "source", "-r", "--format", "json", str(src)],
                        timeout=1800, ok_codes=(0, 1, 128))
    except Exception as e:  # noqa: BLE001
        return [harness_finding("osv-scanner", e)]
    out = []
    for res in (data or {}).get("results", []):
        for pkg in res.get("packages", []):
            p = pkg.get("package", {})
            groups = {tuple(sorted(g.get("ids", []))): g.get("max_severity", "") for g in pkg.get("groups", [])}
            for ids, score in groups.items():
                if any(i in profile.cve_ignore for i in ids):
                    continue
                try:
                    s = float(score)
                    sev = "critical" if s >= 9 else "high" if s >= 7 else "medium" if s >= 4 else "low"
                except ValueError:
                    sev = "medium"
                out.append(Finding("deps", f"osv.{ids[0]}", sev,
                                   f"Source dependency {p.get('name')} {p.get('version')} has {', '.join(ids)}.",
                                   location=f"source:{p.get('name')}", evidence=score, category="dependency"))
    return out


SCRIPT_EXT = {".py", ".js", ".mjs", ".lua", ".gd", ".rb", ".sh", ".rpy", ".pyw", ".ps1", ".bat"}


def scripts(root: Path, rules_dir: Path) -> list[Finding]:
    if not any(p.suffix.lower() in SCRIPT_EXT for p in root.rglob("*") if p.is_file()):
        return []
    try:
        data = run_json(["semgrep", "scan", "--config", str(rules_dir), "--json", "--quiet", "--metrics=off",
                         "--disable-version-check", "--no-git-ignore", "--scan-unknown-extensions",
                         "--max-target-bytes", "5000000", str(root)], timeout=3600, ok_codes=(0, 1))
    except Exception as e:  # noqa: BLE001
        return [harness_finding("semgrep", e)]
    out = []
    for r in (data or {}).get("results", []):
        extra = r.get("extra", {})
        sev = (extra.get("metadata") or {}).get("severity") or \
            {"ERROR": "high", "WARNING": "medium", "INFO": "low"}.get(extra.get("severity"), "medium")
        rel = r.get("path", "")
        try:
            rel = str(Path(rel).relative_to(root))
        except ValueError:
            pass
        rid = r.get("check_id", "").split(".")[-1]
        out.append(Finding("scripts", f"semgrep.{rid}", sev, extra.get("message", rid).strip(),
                           location=f"{rel}:{rid}", evidence=(extra.get("lines") or "")[:500],
                           category=(extra.get("metadata") or {}).get("category", "malicious")))
    for err in (data or {}).get("errors", []):
        # A file semgrep can't parse (minified, a dialect) is not a failed
        # review; semgrep failing to run its rules is.
        etype = str(err.get("type", ""))
        if err.get("level") == "error" and not any(x in etype for x in ("Syntax", "Lexical", "Partial", "Timeout")):
            out.append(harness_finding("semgrep", RuntimeError(err.get("message", "")[:500])))
            break
    return out
