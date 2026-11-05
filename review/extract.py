"""Unpack an artefact into a work folder, safely.

Artefacts under review are untrusted by definition, so nothing is extracted
with the archive's own paths unchecked: absolute paths, `..` components,
links and device files are refused and reported as findings, and the total
size and member count are capped against archive bombs.
"""
from __future__ import annotations

import hashlib
import os
import stat
import tarfile
import zipfile
from pathlib import Path, PurePosixPath

from .findings import Finding

MAX_TOTAL = 8 * 1024 ** 3     # 8 GiB unpacked
MAX_MEMBERS = 200_000
MAX_RATIO = 200               # unpacked / packed, per member


def sha256(path: str | Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def kind_of(path: str | Path) -> str:
    """apk | plugin-bundle | engine-bundle | catalog | archive | elf | unknown"""
    p = str(path).lower()
    with open(path, "rb") as fh:
        head = fh.read(4)
    if p.endswith((".apk", ".aab")):
        return "apk"
    if p.endswith(".droidplugin.tar.xz") or p.endswith(".droidplugin"):
        return "plugin-bundle"
    if p.endswith(".enginehost.tar.xz"):
        return "engine-bundle"   # Enginehost docs/engine-bundle-format.md
    if p.endswith((".json", ".jws")) and "catalog" in os.path.basename(p):
        return "catalog"
    if head == b"\x7fELF":
        return "elf"
    if head == b"\x28\xb5\x2f\xfd":
        return "archive"   # zstd: a .tzst or .wcp component
    if head[:2] == b"PK" or p.endswith((".tar.xz", ".tar.gz", ".tgz", ".tar.zst", ".zip", ".tar")):
        # Enginehost core bundles ship as zips or tarballs beside
        # enginehost-public-key.json; the caller can say so explicitly.
        return "archive"
    return "unknown"


def _safe_name(name: str) -> str | None:
    pp = PurePosixPath(name.replace("\\", "/"))
    if pp.is_absolute() or ".." in pp.parts or not pp.parts:
        return None
    return str(pp)


def _unzstd(src: Path) -> Path | None:
    """A zstd-compressed tar (.tzst, droidtop-components' .wcp), through the
    zstd tool, since Python's tarfile can't read zstd before 3.14."""
    import shutil
    import subprocess
    import tempfile

    with open(src, "rb") as fh:
        if fh.read(4) != b"\x28\xb5\x2f\xfd" or not shutil.which("zstd"):
            return None
    out = Path(tempfile.mkdtemp(prefix="unzstd-")) / (src.name + ".tar")
    r = subprocess.run(["zstd", "-q", "-d", "--no-progress", "-o", str(out), str(src)], capture_output=True)
    return out if r.returncode == 0 else None


def extract(src: str | Path, dest: str | Path, nested: bool = True, _depth: int = 0) -> list[Finding]:
    """Extract src into dest. Returns findings about the archive itself."""
    src, dest = Path(src), Path(dest)
    plain = _unzstd(src)
    if plain is not None:
        import shutil
        try:
            return extract(plain, dest, nested, _depth)
        finally:
            shutil.rmtree(plain.parent, ignore_errors=True)
    dest.mkdir(parents=True, exist_ok=True)
    findings: list[Finding] = []
    total = 0

    def refuse(rule, member, why, sev="high"):
        findings.append(Finding("extract", rule, sev, why, location=f"{src.name}!{member}",
                                category="nonsense"))

    if zipfile.is_zipfile(src):
        with zipfile.ZipFile(src) as zf:
            infos = zf.infolist()
            if len(infos) > MAX_MEMBERS:
                refuse("archive.too-many-members", "", f"{len(infos)} members")
                return findings
            seen = set()
            for zi in infos:
                name = _safe_name(zi.filename)
                if name is None:
                    refuse("archive.path-escape", zi.filename, "A member's path leaves the archive (zip-slip).")
                    continue
                if name in seen:
                    # Duplicate names are how APK "master key" style parser
                    # confusion works: two readers see different files.
                    refuse("archive.duplicate-entry", name, "Two members share one name.")
                seen.add(name)
                mode = zi.external_attr >> 16
                if stat.S_ISLNK(mode):
                    refuse("archive.symlink", name, "A member is a symbolic link.", "medium")
                    continue
                if zi.is_dir():
                    continue
                if zi.compress_size and zi.file_size / zi.compress_size > MAX_RATIO and zi.file_size > 64 << 20:
                    refuse("archive.bomb", name, f"Compression ratio {zi.file_size // zi.compress_size}:1.")
                    continue
                total += zi.file_size
                if total > MAX_TOTAL:
                    refuse("archive.too-large", name, "Unpacked size over 8 GiB.")
                    return findings
                out = dest / name
                out.parent.mkdir(parents=True, exist_ok=True)
                with zf.open(zi) as fin, open(out, "wb") as fout:
                    while chunk := fin.read(1 << 20):
                        fout.write(chunk)
    elif tarfile.is_tarfile(src):
        with tarfile.open(src) as tf:
            n = 0
            for ti in tf:
                n += 1
                if n > MAX_MEMBERS:
                    refuse("archive.too-many-members", "", f"over {MAX_MEMBERS} members")
                    return findings
                name = _safe_name(ti.name)
                if name is None:
                    refuse("archive.path-escape", ti.name, "A member's path leaves the archive (tar-slip).")
                    continue
                if ti.issym() or ti.islnk():
                    refuse("archive.symlink", name, f"A member links to {ti.linkname!r}.", "medium")
                    continue
                if ti.isdev() or ti.isfifo():
                    refuse("archive.device", name, "A member is a device or FIFO.")
                    continue
                if not ti.isfile():
                    continue
                if ti.mode & 0o6000:
                    refuse("archive.setid", name, "A member is setuid or setgid.")
                total += ti.size
                if total > MAX_TOTAL:
                    refuse("archive.too-large", name, "Unpacked size over 8 GiB.")
                    return findings
                out = dest / name
                out.parent.mkdir(parents=True, exist_ok=True)
                fin = tf.extractfile(ti)
                with open(out, "wb") as fout:
                    while chunk := fin.read(1 << 20):
                        fout.write(chunk)
                os.chmod(out, 0o644 | (0o111 if ti.mode & 0o111 else 0))
    else:
        refuse("archive.unreadable", src.name, "Not a zip or tar archive.", "medium")
        return findings

    if nested and _depth < 2:
        # Plugin bundles carry an APK payload; engine bundles carry zips.
        for inner in list(dest.rglob("*")):
            if inner.is_file() and inner.suffix.lower() in (".apk", ".zip", ".jar", ".aar") and inner.stat().st_size:
                if inner.suffix.lower() == ".apk":
                    continue  # APKs get the APK analyser, not a blind unpack
                sub = inner.with_name(inner.name + ".d")
                findings += extract(inner, sub, nested, _depth + 1)
    return findings
