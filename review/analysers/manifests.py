"""Plugin bundles, engine bundles and catalogs: what they declare, and
whether what they declare is what they carry.

The signature itself is not judged here: after a revocation the old
signatures are exactly what can no longer be trusted. What is judged is the
content: hashes against payload, declared host-API permissions against the
stated purpose, and catalog entries against where they may point.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import sys
from pathlib import Path
from urllib.parse import urlparse

from ..findings import Finding
from ..profile import Profile
from ..tools import ToolMissing, harness_finding


def _sha256(p: Path) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as fh:
        for c in iter(lambda: fh.read(1 << 20), b""):
            h.update(c)
    return h.hexdigest()


def _jws_payload(text: str) -> dict | None:
    parts = text.strip().split(".")
    if len(parts) != 3:
        return None
    try:
        pad = "=" * (-len(parts[1]) % 4)
        return json.loads(base64.urlsafe_b64decode(parts[1] + pad))
    except Exception:  # noqa: BLE001
        return None


def _iter_hashes(manifest: dict):
    """Yield (path, sha256) from the shapes our manifests use."""
    for key in ("payload", "files", "hashes", "assets"):
        v = manifest.get(key)
        if isinstance(v, dict):
            for path, h in v.items():
                if isinstance(h, str):
                    yield path, h
                elif isinstance(h, dict) and "sha256" in h:
                    yield path, h["sha256"]
        elif isinstance(v, list):
            for item in v:
                if isinstance(item, dict) and "sha256" in item and ("path" in item or "name" in item):
                    yield item.get("path") or item.get("name"), item["sha256"]


# A bundle's manifest: droidtop plugin bundles carry manifest.json
# (plugin-api.md, "Install"); Enginehost cores carry enginehost-bundle.json
# as their first member (Enginehost docs/engine-bundle-format.md).
MANIFEST_NAMES = {"plugin-bundle": ("manifest.json",), "engine-bundle": ("enginehost-bundle.json",),
                  "bundle": ("manifest.json", "enginehost-bundle.json")}
# Trust files, which are not payload: droidtop's PluginBundleInstaller.TRUST_FILES
# (manifest.json, manifest.jws, legacy manifest.sig and origin.cert) and
# Enginehost's first members.
SIGNATURE_FILES = ("manifest.json", "manifest.jws", "manifest.sig", "origin.cert", "enginehost-bundle.json",
                   "enginehost-bundle.sig", "enginehost-bundle.jws")


def payload_sha256(base: Path, files: list[dict]) -> str:
    """Enginehost's aggregate: UTF8(path) 0x00 ASCII(size) 0x00 bytes, per
    file in manifest order, with no separators (engine-bundle-format.md)."""
    h = hashlib.sha256()
    for item in files:
        p = base / item["path"]
        data = p.read_bytes() if p.is_file() else b""
        h.update(item["path"].encode("utf-8") + b"\0" + str(len(data)).encode("ascii") + b"\0" + data)
    return h.hexdigest()


def bundle(root: Path, profile: Profile, facts: dict, kind: str) -> list[Finding]:
    out: list[Finding] = []
    names = MANIFEST_NAMES.get(kind, MANIFEST_NAMES["bundle"])
    manifests = [p for n in names for p in root.rglob(n) if p.is_file()]
    if not manifests:
        out.append(Finding("manifest", "manifest.missing", "high",
                           f"The {kind} carries no {' or '.join(names)}.", location=root.name, category="nonsense"))
        return out
    mpath = min(manifests, key=lambda p: len(p.parts))
    try:
        manifest = json.loads(mpath.read_text(encoding="utf-8"))
    except Exception as e:  # noqa: BLE001
        return [Finding("manifest", "manifest.unparseable", "high", "manifest.json is not valid JSON.",
                        location=str(mpath.relative_to(root)), evidence=str(e), category="nonsense")]
    base = mpath.parent
    facts["manifest"] = {k: manifest.get(k) for k in ("id", "version", "versionCode", "contract", "abis",
                                                       "lockdown", "origin", "bundleId", "engine", "engines",
                                                       "pluginVersion", "apiVersion", "entrypoint",
                                                       "writesGameFolder", "gameWrites") if k in manifest}

    # Every payload hash matches the bytes, and nothing ships that the
    # manifest does not name.
    named = set()
    for rel, want in _iter_hashes(manifest):
        named.add(rel)
        p = base / rel
        if not p.is_file():
            out.append(Finding("manifest", "manifest.payload-missing", "high",
                               f"The manifest names {rel}, which is not in the bundle.", location=rel,
                               category="nonsense"))
        elif _sha256(p).lower() != want.lower():
            out.append(Finding("manifest", "manifest.hash-mismatch", "critical",
                               f"{rel} does not match the hash its manifest gives: the content was changed "
                               "after the manifest was made.", location=rel, evidence=want, category="malicious"))
    # Enginehost's signed sizes and modes, and the aggregate over the payload.
    signed = [f for f in manifest.get("files", []) or [] if isinstance(f, dict) and "path" in f]
    for item in signed:
        p = base / item["path"]
        if p.is_file() and "size" in item and int(item["size"]) != p.stat().st_size:
            out.append(Finding("manifest", "manifest.size-mismatch", "critical",
                               f"{item['path']} is not the size its manifest signs.", location=item["path"],
                               evidence=f"signed {item['size']}, found {p.stat().st_size}", category="malicious"))
        mode = item.get("mode")
        if isinstance(mode, (int, str)) and str(mode).strip():
            try:
                m = int(str(mode), 8) if isinstance(mode, str) else int(mode)
                if m & 0o6000:
                    out.append(Finding("manifest", "manifest.setid", "high", f"{item['path']} is signed setuid or setgid.",
                                       location=item["path"], category="nonsense"))
            except ValueError:
                pass
    if signed and manifest.get("payloadSha256"):
        got = payload_sha256(base, signed)
        if got.lower() != str(manifest["payloadSha256"]).lower():
            out.append(Finding("manifest", "manifest.payload-mismatch", "critical",
                               "The payload does not match the manifest's payloadSha256.", location=mpath.name,
                               evidence=f"signed {manifest['payloadSha256']}, found {got}", category="malicious"))
    if named:
        for p in base.rglob("*"):
            rel = str(p.relative_to(base))
            if p.is_file() and rel not in named and rel not in SIGNATURE_FILES and not rel.startswith("META-INF") \
                    and ".d/" not in rel + "/" and not rel.endswith(".d"):
                out.append(Finding("manifest", "manifest.unlisted-file", "high",
                                   f"{rel} ships in the bundle but its manifest does not list it.",
                                   location=rel, category="nonsense"))

    # Declared host-API permissions against stated purpose.
    perms = []
    for p in manifest.get("permissions", []) or []:
        perms.append(p.get("id") if isinstance(p, dict) else str(p))
    facts["pluginPermissions"] = sorted(x for x in perms if x)
    for pid in perms:
        if not pid or pid in profile.plugin_permissions:
            continue
        sev = "high" if pid.startswith("priv.") else "medium"
        out.append(Finding("manifest", "plugin-permission.not-in-purpose", sev,
                           f"Declares host permission {pid}, which the repo's stated purpose does not list.",
                           location=f"manifest.json:{pid}", category="purpose"))
    for req in manifest.get("requires", []) or []:
        if isinstance(req, dict) and str(req.get("id", "")).startswith("priv.") and not req.get("optional"):
            out.append(Finding("manifest", "plugin.priv-required", "high",
                               f"Requires {req.get('id')} without marking it optional (plugin API §2.7).",
                               location=f"manifest.json:{req.get('id')}", category="nonsense"))
    if kind == "engine-bundle":
        out += engine_conformance(base, mpath)
    if kind == "engine-bundle" and manifest.get("lockdown") is False:
        out.append(Finding("manifest", "engine.lockdown-off", "medium",
                           "The core turns process lockdown off.", location="manifest.json", category="process"))

    hosts = facts.setdefault("hosts", {})
    for v in _walk_strings(manifest):
        u = urlparse(v)
        if u.scheme in ("http", "https", "ws", "wss") and u.hostname:
            hosts.setdefault(u.hostname.lower(), mpath.name)
    return out


ENGINEHOST_TOOLING = Path(os.environ.get("ENGINEHOST_TOOLING", str(Path.home() / ".enginehost-tooling")))


def engine_conformance(base: Path, manifest_path: Path) -> list[Finding]:
    """Enginehost's own conformance layer 1a (scripts/check-bundle-conformance.py),
    which its signing workflow runs before signing, run again on the
    published bundle. Reused, not rewritten (owner, 2026-11-05: "reuse and
    repurpose existing code whenever possible"). Each problem it reports is
    one the signer refuses, so each blocks."""
    import shutil
    import subprocess
    import tempfile

    script = ENGINEHOST_TOOLING / "scripts" / "check-bundle-conformance.py"
    names = ENGINEHOST_TOOLING / "app/src/main/kotlin/dev/enginehost/EngineNames.kt"
    if not script.exists() or not names.exists():
        return [harness_finding("enginehost-conformance", ToolMissing(str(script)))]
    with tempfile.TemporaryDirectory() as tmp:
        payload = Path(tmp) / "payload"
        shutil.copytree(base, payload, ignore=shutil.ignore_patterns(*SIGNATURE_FILES), symlinks=False)
        r = subprocess.run([sys.executable, "-I", str(script), "--metadata", str(manifest_path), "--payload",
                            str(payload), "--engine-names", str(names)], capture_output=True, text=True, timeout=600)
    out = []
    for line in r.stderr.splitlines():
        if line.startswith("::error::"):
            problem = line[len("::error::"):].strip()
            out.append(Finding("manifest", "engine.conformance", "high", f"Enginehost conformance: {problem}",
                               location=problem[:120], category="nonsense"))
    if r.returncode and not out:
        out.append(harness_finding("enginehost-conformance", RuntimeError(r.stderr[-800:])))
    return out


def _walk_strings(o):
    if isinstance(o, str):
        yield o
    elif isinstance(o, dict):
        for v in o.values():
            yield from _walk_strings(v)
    elif isinstance(o, list):
        for v in o:
            yield from _walk_strings(v)


URL_VALUE = __import__("re").compile(r"[A-Za-z][A-Za-z0-9+.-]*://\S+")


def _catalog_entries(data: dict) -> list[dict]:
    """Every downloadable entry, whatever the catalog's shape: lists of
    entries (droidtop's plugin catalogs), or maps of lists and maps of
    objects (droidtop-components: items {type: [..]}, files {name: {..}})."""
    out: list[dict] = []
    for key in ("entries", "plugins", "components", "items", "files"):
        v = data.get(key)
        if isinstance(v, list):
            out += [e for e in v if isinstance(e, dict)]
        elif isinstance(v, dict):
            for k, e in v.items():
                if isinstance(e, dict):
                    out.append(dict(e, id=e.get("id") or f"{key}/{k}"))
                elif isinstance(e, list):
                    out += [dict(x, id=f"{k}/{x.get('id') or x.get('name') or i}") for i, x in enumerate(e)
                            if isinstance(x, dict)]
    return out


def catalog(path: Path, profile: Profile, facts: dict) -> list[Finding]:
    out: list[Finding] = []
    text = path.read_text(encoding="utf-8", errors="replace")
    data = _jws_payload(text) if path.suffix == ".jws" else None
    if data is None:
        try:
            data = json.loads(text)
        except Exception as e:  # noqa: BLE001
            return [Finding("catalog", "catalog.unparseable", "high", "The catalog is not valid JSON or JWS.",
                            location=path.name, evidence=str(e), category="nonsense")]
    entries = _catalog_entries(data)
    facts["catalogEntries"] = len(entries)
    seen: dict[str, int] = {}
    index = {}
    for i, e in enumerate(entries):
        if not isinstance(e, dict):
            continue
        eid = str(e.get("id") or e.get("name") or i)
        seen[eid] = seen.get(eid, 0) + 1
        # Values that are URLs from end to end. A sentence that mentions one
        # (a licence note's "https://.../LICENSE") is text, not a download.
        urls = [v for v in _walk_strings(e) if URL_VALUE.fullmatch(v.strip())]
        index[eid] = {"urls": sorted(urls), "sha256": e.get("sha256"), "version": e.get("version")}
        for u in urls:
            pu = urlparse(u)
            if pu.scheme != "https":
                out.append(Finding("catalog", "catalog.not-https", "high",
                                   f"Entry {eid} points at a non-HTTPS URL.", location=f"{eid}:{pu.hostname}",
                                   evidence=u, category="network"))
            if pu.hostname:
                facts.setdefault("hosts", {}).setdefault(pu.hostname.lower(), f"catalog:{eid}")
        if any(k in e for k in ("url", "download", "asset")) and not any(
                k in e for k in ("sha256", "hash", "digest", "archiveSha256")):
            out.append(Finding("catalog", "catalog.no-hash", "high",
                               f"Entry {eid} downloads something with no hash to check it against.",
                               location=eid, category="vulnerability"))
    for eid, n in seen.items():
        if n > 1:
            out.append(Finding("catalog", "catalog.duplicate-id", "high", f"Entry id {eid} appears {n} times.",
                               location=eid, category="nonsense"))
    facts["catalogIndex"] = index
    return out
