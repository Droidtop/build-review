"""Network endpoints, differences from earlier releases, and the dynamic
run's process, filesystem and network trace.
"""
from __future__ import annotations

import ipaddress
import json
from pathlib import Path

from ..findings import Finding
from ..profile import Profile

# Hosts no release of ours has a reason to reach.
BAD_HOST_HINTS = ("pastebin.", "ngrok", "duckdns.", "no-ip.", "trycloudflare.com", "transfer.sh",
                  "api.telegram.org", "webhook.site", "requestbin", "pipedream.net", ".onion", "pool.", "xmr", "stratum")


def _real_host(host: str) -> bool:
    """A placeholder in a URL template ("http://x", "default.url") is not
    an endpoint: a host needs a dot and a letters-only TLD, or to be an IP."""
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        pass
    labels = host.split(".")
    return len(labels) >= 2 and labels[-1].isalpha() and len(labels[-1]) >= 2 and labels[-1] not in ("url", "local", "invalid", "test")


def endpoints(facts: dict, profile: Profile) -> list[Finding]:
    out = []
    for host, where in sorted(facts.get("hosts", {}).items()):
        if profile.host_ok(host) or not _real_host(host):
            continue
        sev = "medium"
        if any(h in host for h in BAD_HOST_HINTS):
            sev = "critical"
        else:
            try:
                ipaddress.ip_address(host)
                sev = "high"  # a hard-coded public IP has no stated purpose
            except ValueError:
                pass
        out.append(Finding("network", "endpoint.not-in-purpose", sev,
                           f"The build refers to {host}, which the repo's profile does not list.",
                           location=host, evidence=where, category="network"))
    return out


# What a difference from the previous release means. A new permission, host,
# native library or API category is what a tampered build looks like; it's
# a finding unless the profile already lists it (then it's on purpose).
def diff(cur: dict, prev: dict | None, profile: Profile) -> tuple[dict, list[Finding]]:
    if not prev:
        return {"previous": None}, []
    changes: dict = {"previous": prev.get("release")}
    out: list[Finding] = []

    def setdiff(key, rule, sev, label, ok=lambda x: False):
        a, b = set(cur.get(key) or []), set(prev.get(key) or [])
        added, removed = sorted(a - b), sorted(b - a)
        if added or removed:
            changes[key] = {"added": added, "removed": removed}
        for x in added:
            out.append(Finding("diff", rule, "low" if ok(x) else sev,
                               f"New since {prev.get('release')}: {label} {x}.", location=x, category="diff"))

    setdiff("permissions", "diff.new-permission", "high", "permission", lambda x: x in profile.permissions)
    setdiff("pluginPermissions", "diff.new-plugin-permission", "high", "host permission",
            lambda x: x in profile.plugin_permissions)
    setdiff("apiCategories", "diff.new-api", "medium", "API category", lambda x: x in profile.api)
    setdiff("hostList", "diff.new-host", "medium", "endpoint", profile.host_ok)
    setdiff("nativeList", "diff.new-native", "medium", "native file", lambda x: profile.lib_ok(Path(x).name))
    for key in ("receivers", "services", "providers"):
        setdiff(key, f"diff.new-{key[:-1]}", "low", key[:-1])

    if cur.get("package") and prev.get("package") and cur["package"] != prev["package"]:
        out.append(Finding("diff", "diff.package-changed", "critical",
                           f"Package name changed from {prev['package']} to {cur['package']}.",
                           category="nonsense"))
    if cur.get("versionCode") and prev.get("versionCode"):
        try:
            if int(cur["versionCode"]) < int(prev["versionCode"]):
                out.append(Finding("diff", "diff.version-regressed", "high",
                                   "The version code is lower than the earlier release's.", category="nonsense"))
        except ValueError:
            pass
    # A catalog entry whose download changed without its version changing.
    ci, pi = cur.get("catalogIndex") or {}, prev.get("catalogIndex") or {}
    for eid, e in ci.items():
        p = pi.get(eid)
        if p and p.get("version") == e.get("version") and (p.get("urls") != e.get("urls") or
                                                           p.get("sha256") != e.get("sha256")):
            out.append(Finding("diff", "diff.catalog-silent-change", "high",
                               f"Catalog entry {eid} changed its download at the same version.", location=eid,
                               category="malicious"))
    # Native code that grew a lot with no version bump in its name.
    pn = prev.get("native") or {}
    for rel, info in (cur.get("native") or {}).items():
        if rel in pn and pn[rel].get("size") and info.get("size", 0) > 1.5 * pn[rel]["size"] + 65536:
            out.append(Finding("diff", "diff.native-grew", "medium",
                               f"{rel} grew from {pn[rel]['size']} to {info['size']} bytes.", location=rel,
                               category="diff"))
        if rel in pn and set(info.get("imports", [])) - set(pn[rel].get("imports", [])):
            new = sorted(set(info["imports"]) - set(pn[rel].get("imports", [])))
            changes.setdefault("nativeImports", {})[rel] = new
    return changes, out


def dynamic(trace_dir: Path, profile: Profile, facts: dict) -> list[Finding]:
    """Judge the sandbox run (scripts/dynamic-android.sh writes trace.json)."""
    tpath = trace_dir / "trace.json"
    if not tpath.exists():
        return [Finding("dynamic", "harness.dynamic-missing", "critical",
                        "The dynamic run produced no trace, so behaviour was not reviewed.", category="harness")]
    t = json.loads(tpath.read_text())
    out: list[Finding] = []
    facts["dynamic"] = {k: t.get(k) for k in ("package", "launched", "crashed", "events", "durationSeconds")}
    if not t.get("installed", True):
        out.append(Finding("dynamic", "dynamic.install-failed", "high", "The APK would not install in the sandbox.",
                            evidence=t.get("installError", ""), category="nonsense"))
    for host in sorted(set(t.get("dnsQueries", []) + t.get("tlsSni", []))):
        if profile.host_ok(host):
            continue
        sev = "critical" if any(h in host for h in BAD_HOST_HINTS) else "high"
        out.append(Finding("dynamic", "dynamic.contacted-host", sev,
                           f"At run time the app contacted {host}, which the profile does not list.",
                           location=host, category="network"))
    for ip in sorted(set(t.get("directIps", []))):
        out.append(Finding("dynamic", "dynamic.direct-ip", "high",
                           f"At run time the app connected to {ip} without a DNS lookup.", location=ip,
                           category="network"))
    for proc in sorted(set(t.get("childProcesses", []))):
        name = proc.split()[0].rsplit("/", 1)[-1] if proc else proc
        if name in ("su", "magisk", "busybox"):
            sev = "critical"
        elif "exec" in profile.api or "native-process" in profile.api:
            sev = "low"
        else:
            sev = "high"
        out.append(Finding("dynamic", "dynamic.child-process", sev, f"The app started a process: {proc}.",
                           location=name, category="process"))
    pkg = t.get("package", "")
    for path in sorted(set(t.get("filesWritten", []))):
        own = path.startswith((f"/data/data/{pkg}", f"/data/user/0/{pkg}", f"/sdcard/Android/data/{pkg}",
                               f"/storage/emulated/0/Android/data/{pkg}"))
        if own:
            continue
        sev = "high" if path.startswith(("/system", "/vendor", "/data/local/tmp", "/data/data/")) else "medium"
        out.append(Finding("dynamic", "dynamic.wrote-outside-own-storage", sev,
                           f"The app wrote {path}, outside its own storage.", location=path, category="filesystem"))
    for line in t.get("logFlags", []):
        out.append(Finding("dynamic", "dynamic.log-flag", "medium", "A suspicious log line at run time.",
                           location=line[:80], evidence=line, category="process"))
    return out
