"""Native code: ELF and PE hardening, imports, packing, capabilities, YARA.

Real analysers: LIEF (headers, segments, imports), capa (capabilities, on
the architectures its disassembler supports), YARA (rules/yara).
"""
from __future__ import annotations

import hashlib
import math
import os
import subprocess
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from ..findings import Finding
from ..profile import Profile
from ..tools import ToolMissing, harness_finding, run, run_json

A = "native"

# Imports that a library has to have a reason for.
SENSITIVE_IMPORTS = {
    "execve": "process", "execv": "process", "execvp": "process", "execl": "process", "execlp": "process",
    "system": "process", "popen": "process", "fork": "process", "vfork": "process", "posix_spawn": "process",
    "ptrace": "anti-analysis", "process_vm_writev": "injection", "process_vm_readv": "injection",
    "mprotect": "memory", "memfd_create": "memory", "dlopen": "loading", "android_dlopen_ext": "loading",
    "socket": "network", "connect": "network", "getaddrinfo": "network",
    "CreateRemoteThread": "injection", "WriteProcessMemory": "injection", "VirtualAllocEx": "injection",
    "SetWindowsHookExA": "keylogging", "SetWindowsHookExW": "keylogging", "GetAsyncKeyState": "keylogging",
    "IsDebuggerPresent": "anti-analysis", "CheckRemoteDebuggerPresent": "anti-analysis",
    "URLDownloadToFileA": "network", "URLDownloadToFileW": "network", "WinExec": "process", "ShellExecuteW": "process",
}
SEVERE_KINDS = {"injection": "high", "keylogging": "high", "anti-analysis": "medium"}
# Longest namespace prefix wins. capa files plain syscall instructions under
# "anti-analysis", and Android libraries (seccomp, proot) use them on
# purpose, so the bare namespace is low; the specific techniques are not.
CAPA_SEVERITY = {
    "host-interaction/process/inject": "critical", "collection/keylog": "critical",
    "anti-analysis/packer": "critical", "anti-analysis/anti-debugging": "high",
    "anti-analysis/anti-disasm": "high", "anti-analysis/anti-emulation": "high",
    "anti-analysis/anti-vm": "medium", "anti-analysis/obfuscation": "medium",
    "anti-analysis": "low", "persistence": "high", "impact": "high",
    "data-manipulation/encryption": "info", "communication": "info",
}


URL_BYTES = __import__("re").compile(rb"(?:https?|wss?|ftp)://([A-Za-z0-9][A-Za-z0-9.-]{1,252}\.[A-Za-z]{2,24})(?=[:/\x00\"' ]|$)")


def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    n = len(data)
    return -sum(c / n * math.log2(c / n) for c in Counter(data).values())


def is_macho_fat(head: bytes) -> bool:
    """CAFEBABE opens both a universal Mach-O and a Java class file. The next
    four bytes tell them apart: a fat header's architecture count (a handful),
    a class file's version (major 45 and up)."""
    return len(head) >= 8 and head[:4] == b"\xca\xfe\xba\xbe" and int.from_bytes(head[4:8], "big") <= 20


def is_pe(path: Path) -> bool:
    """MZ alone also opens DOS programs and 16-bit NE files (Windows 3.x
    fonts, .fon, which Wine ships). PE is MZ whose e_lfanew (offset 0x3c)
    points at "PE\\0\\0"."""
    try:
        with open(path, "rb") as fh:
            if fh.read(2) != b"MZ":
                return False
            fh.seek(0x3C)
            off = int.from_bytes(fh.read(4), "little")
            fh.seek(off)
            return fh.read(4) == b"PE\0\0"
    except (OSError, ValueError):
        return False


def is_native(path: Path) -> bool:
    try:
        with open(path, "rb") as fh:
            head = fh.read(8)
    except OSError:
        return False
    # ELF, PE, and Mach-O (thin and universal): LIEF parses all of them.
    return head[:4] == b"\x7fELF" or (head[:2] == b"MZ" and is_pe(path)) or head[:4] in (
        b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe") or is_macho_fat(head)


def analyse(root: Path, profile: Profile, facts: dict, rel_base: Path | None = None,
            capa: bool = True) -> list[Finding]:
    import lief

    lief.logging.disable()
    out: list[Finding] = []
    capa_jobs = []
    libs = facts.setdefault("native", {})
    for path in sorted(p for p in root.rglob("*") if p.is_file() and is_native(p)):
        rel = str(path.relative_to(rel_base or root))
        try:
            b = lief.parse(str(path))
        except Exception as e:  # noqa: BLE001
            out.append(harness_finding("lief", e))
            continue
        if b is None:
            out.append(Finding(A, "native.unparseable", "high",
                               "A file looks like native code but does not parse: corrupt or deliberately malformed.",
                               location=rel, category="obfuscation"))
            continue
        info = _describe(b, path)
        libs[rel] = info
        if not profile.lib_ok(path.name):
            out.append(Finding(A, "native.unexpected-library", "medium",
                               f"{path.name} is native code the repo's profile does not list.",
                               location=rel, evidence=info.get("arch", ""), category="native"))
        out += _hardening(b, info, rel)
        # Endpoints in the library's own strings; the endpoints analyser
        # judges them against the profile, as it does the dex's.
        hosts = facts.setdefault("hosts", {})
        for m in URL_BYTES.finditer(path.read_bytes()):
            hosts.setdefault(m.group(1).decode("ascii").lower().rstrip("."), rel)
        for imp in info["imports"]:
            kind = SENSITIVE_IMPORTS.get(imp)
            if kind and kind not in profile.api and f"native-{kind}" not in profile.api:
                out.append(Finding(A, f"native.import.{kind}", SEVERE_KINDS.get(kind, "low"),
                                   f"{path.name} imports {imp} ({kind}).", location=f"{rel}:{imp}",
                                   category="native"))
        if info["max_section_entropy"] > 7.6 and not info["has_symbols"]:
            out.append(Finding(A, "native.packed", "high" if not profile.obfuscation_ok else "low",
                               f"{path.name} has a section with entropy {info['max_section_entropy']:.2f} and no "
                               "symbols: packed or encrypted code.", location=rel, category="obfuscation"))
        if b"UPX!" in path.read_bytes()[:4096]:
            out.append(Finding(A, "native.upx", "critical", f"{path.name} is UPX-packed.", location=rel,
                               category="obfuscation"))
        capa_jobs.append((path, rel, info))
    if capa:
        out += _capa_all(capa_jobs)
    return out


CAPA_TIMEOUT = int(os.environ.get("BUILD_REVIEW_CAPA_TIMEOUT", "600"))
# The whole review's capa time. A library that would start past it is a
# reported coverage gap (medium), not a pass and not a failed review.
CAPA_BUDGET = int(os.environ.get("BUILD_REVIEW_CAPA_BUDGET", "2700"))
_capa_done: dict = {}       # (size, sha256) -> findings, across a release's artefacts
_capa_clock = {"start": None}
CAPA_MAX_BYTES = 64 << 20


def _capa_workers() -> int:
    """capa peaks near 1.5 GB per library; run as many as memory allows."""
    try:
        with open("/proc/meminfo") as fh:
            avail = next(int(l.split()[1]) for l in fh if l.startswith("MemAvailable:")) // (1024 * 1024)
    except (OSError, StopIteration):
        avail = 4
    return max(1, min(os.cpu_count() or 1, (avail - 1) // 2))


def _capa_all(jobs) -> list[Finding]:
    """capa is the slowest analyser (minutes per library), so libraries run
    in parallel, once per distinct file, each within a time budget."""
    import time

    if _capa_clock["start"] is None:
        _capa_clock["start"] = time.monotonic()
    todo, out = [], []
    for path, rel, info in jobs:
        if info["arch"] not in ("i386", "x86_64", "X86_64", "I386", "AMD64"):
            continue
        key = (info["size"], hashlib.sha256(path.read_bytes()).hexdigest())
        if key in _capa_done or any(k == key for k, _j in todo):
            continue   # the same library in another APK of this release: once is enough
        todo.append((key, (path, rel, info)))

    def one(item):
        key, (path, rel, info) = item
        if time.monotonic() - _capa_clock["start"] > CAPA_BUDGET:
            found = [Finding(A, "coverage.capa-skipped", "medium",
                             f"capa's {CAPA_BUDGET} s budget for this review ran out before {path.name} "
                             "(LIEF, YARA and the dynamic run covered it).", location=rel, category="native")]
        else:
            found = _capa(path, rel, info)
        _capa_done[key] = found
        return found

    with ThreadPoolExecutor(max_workers=_capa_workers()) as pool:
        for found in pool.map(one, todo):
            out += found
    return out


def _describe(b, path: Path) -> dict:
    import lief

    imports = sorted({s.name for s in getattr(b, "imported_functions", []) if getattr(s, "name", "")})
    sections = list(getattr(b, "sections", []))
    ent = max((entropy(bytes(s.content)) for s in sections if s.size and s.size < 64 << 20), default=0.0)
    info = {"format": type(b).__name__, "imports": imports, "max_section_entropy": round(ent, 3),
            "size": path.stat().st_size, "has_symbols": False, "arch": ""}
    if isinstance(b, lief.ELF.Binary):
        info["arch"] = str(b.header.machine_type).split(".")[-1]
        info["has_symbols"] = len(b.symtab_symbols) > 0 or len(b.exported_functions) > 0
        info["needed"] = list(b.libraries)
    elif isinstance(b, lief.PE.Binary):
        info["arch"] = str(b.header.machine).split(".")[-1]
        info["has_symbols"] = b.has_exports
        info["needed"] = [lib.name for lib in b.imports]
    return info


def _hardening(b, info: dict, rel: str) -> list[Finding]:
    import lief

    out = []
    if isinstance(b, lief.ELF.Binary):
        for seg in b.segments:
            if seg.type == lief.ELF.Segment.TYPE.GNU_STACK and seg.has(lief.ELF.Segment.FLAGS.X):
                out.append(Finding(A, "native.exec-stack", "high", "Executable stack.", location=rel,
                                   category="vulnerability"))
            if seg.type == lief.ELF.Segment.TYPE.LOAD and seg.has(lief.ELF.Segment.FLAGS.W) and \
                    seg.has(lief.ELF.Segment.FLAGS.X):
                out.append(Finding(A, "native.rwx-segment", "high",
                                   "A loadable segment is writable and executable.", location=rel,
                                   category="vulnerability"))
        if b.has(lief.ELF.DynamicEntry.TAG.TEXTREL):
            out.append(Finding(A, "native.textrel", "medium", "Text relocations (code patched at load).",
                               location=rel, category="vulnerability"))
        if not b.is_pie and b.header.file_type == lief.ELF.Header.FILE_TYPE.EXEC:
            out.append(Finding(A, "native.no-pie", "medium", "Executable is not position-independent.",
                               location=rel, category="vulnerability"))
        if "__stack_chk_fail" not in info["imports"] and info["imports"]:
            out.append(Finding(A, "native.no-canary", "low", "No stack-protector calls.", location=rel,
                               category="vulnerability"))
    elif isinstance(b, lief.PE.Binary):
        chars = b.optional_header.dll_characteristics_lists
        names = {str(c).split(".")[-1] for c in chars}
        if "NX_COMPAT" not in names:
            out.append(Finding(A, "native.pe-no-nx", "medium", "PE is not NX-compatible.", location=rel,
                               category="vulnerability"))
        if "DYNAMIC_BASE" not in names:
            out.append(Finding(A, "native.pe-no-aslr", "medium", "PE has no ASLR.", location=rel,
                               category="vulnerability"))
    return out


def type_name(path: Path) -> str:
    with open(path, "rb") as fh:
        return "ELF" if fh.read(4) == b"\x7fELF" else "PE"


def _capa(path: Path, rel: str, info: dict) -> list[Finding]:
    # capa's ELF support covers x86 and x86-64; ARM libraries are covered by
    # LIEF, YARA and the dynamic run instead (README, "Coverage").
    if info["size"] > CAPA_MAX_BYTES:
        return [Finding(A, "coverage.capa-skipped", "medium",
                        f"{path.name} is over 64 MiB, so capa did not analyse it (LIEF, YARA and the dynamic run did).",
                        location=rel, category="native")]
    try:
        osarg = ["--os", "linux"] if type_name(path) == "ELF" else []
        data = run_json(["capa", "-j", "-q", *osarg, str(path)], timeout=CAPA_TIMEOUT, ok_codes=(0, 1))
    except subprocess.TimeoutExpired:
        # A coverage gap, reported, not a pass: the other native analysers
        # still covered this library.
        return [Finding(A, "coverage.capa-timeout", "medium",
                        f"capa did not finish {path.name} within {CAPA_TIMEOUT} s (LIEF, YARA and the dynamic run "
                        "covered it).", location=rel, category="native")]
    except ToolMissing as e:
        return [harness_finding("capa", e)]
    except Exception as e:  # noqa: BLE001
        return [harness_finding("capa", e)]
    out = []
    for name, rule in ((data or {}).get("rules") or {}).items():
        ns = (rule.get("meta") or {}).get("namespace") or ""
        key = max((k for k in CAPA_SEVERITY if ns == k or ns.startswith(k + "/")), key=len, default=None)
        sev = CAPA_SEVERITY.get(key) if key else None
        if sev is None or sev == "info":
            continue
        out.append(Finding(A, f"capa.{ns}", sev, f"capa: {name}.", location=f"{rel}:{ns}",
                           evidence=name, category="malicious" if sev in ("critical", "high") else "native"))
    return out


def yara_scan(root: Path, rules_dir: Path) -> list[Finding]:
    """YARA over every file: miners, shells, root tools, hooking frameworks."""
    out = []
    rule_files = sorted(str(p) for p in rules_dir.glob("*.yar"))
    if not rule_files:
        return out
    lines = []
    for rf in rule_files:  # the yara CLI takes one rules file per call
        try:
            lines += run(["yara", "-r", "-w", "-m", rf, str(root)], timeout=1800, ok_codes=(0, 1)).stdout.splitlines()
        except Exception as e:  # noqa: BLE001
            return [harness_finding("yara", e)]
    for line in lines:
        # "<rule> [meta] <path>"
        parts = line.split(" ")
        if len(parts) < 2:
            continue
        rule, target = parts[0], parts[-1]
        meta = line[len(rule):len(line) - len(target)].strip(" []")
        sev = "high"
        for kv in meta.split(","):
            if kv.startswith("severity="):
                sev = kv.split("=", 1)[1].strip('"')
        try:
            rel = str(Path(target).relative_to(root))
        except ValueError:
            rel = target
        out.append(Finding("yara", f"yara.{rule}", sev, f"YARA rule {rule} matches.", location=rel,
                           evidence=meta, category="malicious"))
    return out
