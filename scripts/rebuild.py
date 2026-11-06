#!/usr/bin/env python3
"""Rebuild a release from its commit, with no secrets, and name the outputs
as the release published them (step 2 of the standard build review loop).

  rebuild.py <repo> <source-dir> <original-record.json> <out-dir>

The build is the profile's `build:`. Either:
- `command`: run in the source folder; or
- `setup: act`: the repo's own `job` of its own `workflow`, replayed at that
  commit by nektos/act on this runner (host mode: the runner's own JDK and
  Android SDK, the job's own actions at their pinned commits). The job's
  uploaded artifacts are the outputs. act is reused rather than an emulator
  written here (owner, 2026-11-05: "reuse and repurpose existing code
  whenever possible"). The Enginehost cores pin their toolchain and their
  plugin-api commit in that job, and act honours both.

`outputs` maps a glob to the published name, or to "{<kind>}" for the
original's one artefact of that kind. The rebuilt files then sit at the
paths the original's findings name, so the two reviews' fingerprints can be
compared. `repack: payload` turns a core's unsigned.tar (payload/ and
bundle-metadata.json) into the bundle's own layout (payload at the root; the
manifest is made at signing). `repack: tree` packs an uploaded folder as it
stands (a droidtop plugin's unsigned build/: manifest.json and payload).

On failure it prints `error=<reason>` and exits 0, so the decision records
the release as not rebuildable instead of the job failing.
"""
from __future__ import annotations

import fnmatch
import glob
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from review import profile as prof  # noqa: E402


ORIGINALS: list[dict] = []   # the original review's artefacts: names and kinds


def fail(reason: str) -> None:
    print(f"error={reason}")
    out = os.environ.get("GITHUB_OUTPUT")
    if out:
        with open(out, "a") as fh:
            fh.write(f"error={reason}\n")
    sys.exit(0)


def clean_env() -> dict:
    """No credential of any kind reaches the build."""
    env = dict(os.environ)
    for k in list(env):
        if re.search(r"(TOKEN|SECRET|PASSWORD|PASSPHRASE|_KEY|KEYSTORE|PEM|SIGNING)", k):
            env.pop(k)
    return env


def run_command(src: Path, command: str, env: dict) -> Path:
    # Memory every 30 s into the build's log, so a build that loses its
    # runner leaves how close it came (pilot runs 42002552036, 42070954537).
    vmstat = subprocess.Popen(["vmstat", "-t", "-S", "M", "30"]) if shutil.which("vmstat") else None
    try:
        r = subprocess.run(["bash", "-euo", "pipefail", "-c", command], cwd=src, env=env)
    finally:
        if vmstat:
            vmstat.terminate()
            vmstat.wait()
    if r.returncode:
        fail(f"the build failed at that commit (exit {r.returncode}; log in the run)")
    return src


def run_act(src: Path, build: dict, env: dict) -> Path:
    act = shutil.which("act")
    if not act:
        fail("act is not installed (scripts/install-tools.sh)")
    wf, job = build.get("workflow"), build.get("job")
    # A repo that builds several bundles in one workflow, one job each (the
    # test fixtures): `jobs` maps an asset pattern to its job.
    for pattern, j in (build.get("jobs") or {}).items():
        if any(fnmatch.fnmatch(a["name"], pattern) for a in ORIGINALS):
            job = j
            break
    if not wf or not job or not (src / wf).is_file():
        fail(f"the profile's workflow {wf!r} (job {job!r}) is not in the source at that commit")
    art = Path(tempfile.mkdtemp(prefix="act-artifacts-"))
    cmd = [act, build.get("event", "workflow_dispatch"), "-j", job, "-W", wf,
           "-P", "ubuntu-latest=-self-hosted", "-P", "ubuntu-24.04=-self-hosted", "-P", "ubuntu-22.04=-self-hosted",
           "--artifact-server-path", str(art), "--no-cache-server"]
    # The one credential a rebuild gets: the rebuild job's own GITHUB_TOKEN
    # (contents: read, expiring with the job), as the replayed job's
    # github.token. A job that checks out another repository cannot start
    # without one (droidtop plugins check out droidtop: "Input required and
    # not supplied: token", build review batch 42120200445). Owner,
    # 2026-11-05, Droidtop/tracker#913: "Yes". It goes in through a secret
    # file, not the command line, and never into the build's environment,
    # which clean_env() has already stripped of it.
    secrets = None
    token = os.environ.get("REBUILD_READ_TOKEN", "")
    if token:
        secrets = Path(tempfile.mkdtemp(prefix="act-secrets-")) / "secrets"
        secrets.touch(mode=0o600)
        secrets.write_text(f"GITHUB_TOKEN={token}\n")
        cmd += ["--secret-file", str(secrets)]
    try:
        r = subprocess.run(cmd, cwd=src, env=env)
    finally:
        if secrets:
            shutil.rmtree(secrets.parent, ignore_errors=True)
    unpacked = art / "unpacked"
    for z in art.rglob("*.zip"):
        with zipfile.ZipFile(z) as zf:
            zf.extractall(unpacked / z.parent.name)
    if r.returncode:
        # A job that builds and then signs in a later job of its own (the
        # shared droidtop plugin workflow) fails at signing here, since no
        # key reaches a rebuild. With `signs_after_build: true` the uploads
        # made before that failure are the outputs.
        if not (build.get("signs_after_build") and unpacked.exists()):
            fail(f"the repo's own job {job} failed at that commit (exit {r.returncode}; log in the run)")
        print(f"act exited {r.returncode} after the build's uploads (the signing step has no key here, as intended)")
    return unpacked


def repack_payload(tar_path: Path, dest: Path) -> None:
    with tarfile.open(tar_path) as tf, tarfile.open(dest, "w:xz") as out:
        for ti in tf:
            if not ti.name.startswith("payload/") or not ti.isfile():
                continue
            data = tf.extractfile(ti).read()
            ni = tarfile.TarInfo(ti.name[len("payload/"):])
            ni.size, ni.mode, ni.mtime = len(data), ti.mode, 0
            out.addfile(ni, io.BytesIO(data))


def run_mirror(src: Path, build: dict) -> Path:
    """A re-hosted file's rebuild is its maker's own copy: the mirror's
    record at that commit (droidtop-components sources/mirror.json: `from`,
    `official`, `sha256`) says where the maker publishes it and what it must
    hash to. The maker's bytes, checked against that hash, are the rebuild."""
    import hashlib
    import urllib.request

    record = src / build.get("mirror", "sources/mirror.json")
    if not record.is_file():
        fail(f"{record.relative_to(src)} is not in the source at that commit")
    files = json.loads(record.read_text()).get("files", [])
    by_name = {}
    for f in files:
        for key in (f.get("name"), Path(f.get("path") or "").name):
            if key:
                by_name[key] = f
    root = Path(tempfile.mkdtemp(prefix="mirror-"))
    missing = []
    for a in ORIGINALS:
        f = by_name.get(a["name"])
        if not f:
            missing.append(a["name"])
            continue
        for url in [f.get("from"), *(f.get("official") or [])]:
            if not url:
                continue
            try:
                data = urllib.request.urlopen(url, timeout=600).read()
            except Exception as e:  # noqa: BLE001
                print(f"{url}: {e}")
                continue
            if hashlib.sha256(data).hexdigest() == str(f.get("sha256", "")).lower():
                (root / a["name"]).write_bytes(data)
                print(f"{a['name']}: the maker's copy at {url} matches the mirror's record")
                break
            print(f"{url}: does not match the mirror's recorded SHA-256")
        else:
            fail(f"no maker's copy of {a['name']} matches the mirror's record")
    if missing:
        fail("not re-hosted files, so there is no maker's copy to compare: " + ", ".join(missing[:5]))
    return root


def pack_tree(folder: Path, dest: Path) -> None:
    """A plugin bundle's layout: the unsigned build/ tree as it stands."""
    with tarfile.open(dest, "w:xz") as out:
        for p in sorted(folder.rglob("*")):
            if p.is_file():
                ti = out.gettarinfo(str(p), arcname=str(p.relative_to(folder)))
                ti.mtime, ti.uid, ti.gid, ti.uname, ti.gname = 0, 0, 0, "", ""
                with open(p, "rb") as fh:
                    out.addfile(ti, fh)


def main() -> None:
    repo, src, record, out = sys.argv[1], Path(sys.argv[2]), Path(sys.argv[3]), Path(sys.argv[4])
    p = prof.load(repo)
    build = p.build or {}
    if not src.is_dir():
        fail("the source at that commit could not be checked out")
    env = clean_env()
    ORIGINALS[:] = json.loads(record.read_text()).get("artefacts", [])
    if build.get("setup") == "mirror":
        root = run_mirror(src, build)
    elif build.get("setup") == "act":
        root = run_act(src, build, env)
    elif build.get("command"):
        root = run_command(src, build["command"], env)
    else:
        fail("the repo's profile gives no way to build it")
    originals = ORIGINALS
    outputs = build.get("outputs") or []
    if isinstance(outputs, list):
        outputs = {g: None for g in outputs}
    out.mkdir(parents=True, exist_ok=True)
    made = 0
    for pattern, name in outputs.items():
        hits = sorted(glob.glob(str(root / pattern), recursive=True))
        if not hits:
            continue
        if name and name.startswith("{") and name.endswith("}"):
            kind = name[1:-1]
            same = [a["name"] for a in originals if a.get("kind") == kind]
            name = same[0] if len(same) == 1 else None
        for hit in hits[:1] if name else hits:
            target = out / (name or Path(hit).name)
            if build.get("repack") == "tree" and Path(hit).is_dir():
                pack_tree(Path(hit), target)
            elif build.get("repack") == "payload" and tarfile.is_tarfile(hit):
                repack_payload(Path(hit), target)
            else:
                shutil.copy(hit, target)
            made += 1
            print(f"rebuilt {target.name} from {Path(hit).relative_to(root) if Path(hit).is_relative_to(root) else hit}")
    if not made:
        fail("the build made none of the profile's outputs")


if __name__ == "__main__":
    main()
