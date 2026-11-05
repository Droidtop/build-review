"""A repo's review profile: its stated purpose, written down so a machine can
hold the build to it.

Policy (Droidtop/tracker#550, 2026-10-15): "declared permissions and API use
against what the plugin's stated purpose needs". Each repo's profile lives in
`profiles/<owner>/<repo>.yml` here, not in the repo under review, so an old
release is judged by today's statement of purpose and a tampered repo can't
widen its own allowance. Anything a profile does not mention is unexpected.
"""
from __future__ import annotations

import fnmatch
import os
from dataclasses import dataclass, field
from pathlib import Path

import yaml

ROOT = Path(os.environ.get("BUILD_REVIEW_PROFILES") or Path(__file__).resolve().parent.parent / "profiles")


@dataclass
class Profile:
    repo: str
    purpose: str = ""
    artefacts: list[dict] = field(default_factory=list)   # [{pattern, kind}]
    build: dict = field(default_factory=dict)             # {setup, command, outputs, submodules}
    permissions: list[str] = field(default_factory=list)  # Android permissions the purpose needs
    plugin_permissions: list[str] = field(default_factory=list)  # droidtop host-API permissions
    api: list[str] = field(default_factory=list)          # sensitive API categories the purpose needs
    hosts: list[str] = field(default_factory=list)        # network endpoints, globs
    native_libs: list[str] = field(default_factory=list)  # globs of expected native libraries
    exported_ok: list[str] = field(default_factory=list)  # components exported on purpose
    obfuscation_ok: bool = False
    cve_ignore: dict = field(default_factory=dict)        # {CVE-id: reason}
    secrets_ignore: list[str] = field(default_factory=list)  # gitleaks fingerprints with reason in comment
    block: list[str] = field(default_factory=list)        # rules that block for this repo
    dynamic: dict = field(default_factory=dict)           # {package, monkey_events, skip_reason}
    api_callers_ok: dict = field(default_factory=dict)    # {category: {class prefix: reason}}
    explained: list[dict] = field(default_factory=list)   # [{rule, location, reason, source}]
    reasons: dict = field(default_factory=dict)           # every entry's stated reason, for the report
    known: bool = True                                    # False: no profile written yet

    def host_ok(self, host: str) -> bool:
        host = host.lower().rstrip(".")
        return any(fnmatch.fnmatch(host, g.lower()) for g in self.hosts)

    def lib_ok(self, name: str) -> bool:
        return any(fnmatch.fnmatch(name, g) for g in self.native_libs)

    def explanation(self, rule: str, location: str) -> dict | None:
        """A finding the owning lane has explained. Exact rule, and the
        location as a glob; it must cite where the explanation was given."""
        for e in self.explained:
            if e.get("rule") == rule and fnmatch.fnmatch(location, e.get("location", "")) and e.get("source"):
                return e
        return None

    def entry_for(self, asset: str) -> dict:
        for a in self.artefacts:
            if fnmatch.fnmatch(asset, a["pattern"]):
                return a
        return {}

    def kind_for(self, asset: str) -> str | None:
        return self.entry_for(asset).get("kind")


# Endpoints every Android build reaches through the platform or the schema
# namespaces in its own resources; never a finding.
COMMON_HOSTS = [
    "schemas.android.com", "www.w3.org", "ns.adobe.com", "xmlpull.org", "www.apache.org",
    "apache.org", "json-schema.org", "localhost", "127.0.0.1", "::1", "example.com", "*.example.com",
    "example.org", "www.example.com", "purl.org", "xml.org", "*.xml.org", "www.xml.org",
]


def load(repo: str, root: Path = ROOT) -> Profile:
    path = root / f"{repo}.yml"
    if not path.exists():
        # The defaults for an unknown repo deliberately allow nothing, so an
        # unprofiled repo's every permission and host is a finding.
        return Profile(repo=repo, hosts=list(COMMON_HOSTS), known=False)
    data = yaml.safe_load(path.read_text()) or {}
    base = {}
    if "extends" in data:
        base = yaml.safe_load((root / f"{data.pop('extends')}.yml").read_text()) or {}
    for k, v in base.items():
        if k == "repo":
            continue
        if isinstance(v, list) and isinstance(data.get(k), list):
            data[k] = v + data[k]
        else:
            data.setdefault(k, v)
    # Entries are either a list or a {name: reason} map (the lanes write
    # maps, so every line carries its reason). A reason starting "TO
    # IDENTIFY" is no reason: that entry stays a finding.
    reasons: dict = {}
    for key in ("permissions", "plugin_permissions", "api", "hosts", "native_libs", "exported_ok"):
        v = data.get(key)
        if isinstance(v, dict):
            reasons[key] = {k: str(r) for k, r in v.items()}
            data[key] = [k for k, r in v.items() if not str(r).upper().startswith("TO IDENTIFY")]
    for e in data.get("explained", []) or []:
        if not (e.get("rule") and e.get("location") and e.get("reason") and e.get("source")):
            raise ValueError(f"{repo}: an explained entry needs rule, location, reason and source: {e}")
    data["reasons"] = reasons
    data["hosts"] = list(COMMON_HOSTS) + list(data.get("hosts", []))
    data.setdefault("repo", repo)
    return Profile(**data)
