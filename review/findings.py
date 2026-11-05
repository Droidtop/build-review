"""Findings: what every analyser returns, and how two reviews are compared.

A finding's fingerprint leaves out what changes from build to build (version
numbers, build ids, hashes and the extraction root), so a rebuild of the same
commit that has the same problem gives the same fingerprint. Step 3 of the
standard build review loop (Droidtop/tracker#550) depends on that: "if that
rebuild has the same issues, then the issue is in the code".
"""
from __future__ import annotations

import dataclasses
import hashlib
import json
import re
from typing import Iterable

SEVERITIES = ("info", "low", "medium", "high", "critical")
# A build with any finding at or above this severity is not clean. Profiles
# can raise single rules to blocking (profile `block:`), never lower a
# critical one.
BLOCKING = ("high", "critical")

_VOLATILE = [
    re.compile(r"\b[0-9a-f]{32,64}\b", re.I),        # hashes
    re.compile(r"\bv?\d+(\.\d+){1,3}([-+][\w.]+)?\b"),  # versions
    re.compile(r"\bbuild-\d+\b"),
    re.compile(r"\bdev\.\d+\b"),
]


def _stable(text: str) -> str:
    for pat in _VOLATILE:
        text = pat.sub("#", text)
    return text


@dataclasses.dataclass
class Finding:
    analyser: str            # "apk", "native", "secrets", ...
    rule: str                # stable rule id, e.g. "permission.undeclared-purpose"
    severity: str            # one of SEVERITIES
    title: str               # one plain sentence
    location: str = ""       # path inside the artefact, a component name, a host
    evidence: str = ""       # the line, the string, the tool's own output (trimmed)
    category: str = ""       # malicious | vulnerability | nonsense | purpose | network |
                             # process | filesystem | native | obfuscation | secret |
                             # dependency | diff
    fingerprint: str = ""

    def __post_init__(self) -> None:
        if self.severity not in SEVERITIES:
            raise ValueError(f"unknown severity {self.severity!r}")
        self.evidence = self.evidence[:2000]
        if not self.fingerprint:
            key = "|".join((self.analyser, self.rule, _stable(self.location)))
            self.fingerprint = hashlib.sha256(key.encode()).hexdigest()[:16]

    @property
    def blocking(self) -> bool:
        return self.severity in BLOCKING

    def to_dict(self) -> dict:
        d = dataclasses.asdict(self)
        d["blocking"] = self.blocking
        return d

    @classmethod
    def from_dict(cls, d: dict) -> "Finding":
        d = {k: v for k, v in d.items() if k in {f.name for f in dataclasses.fields(cls)}}
        return cls(**d)


def raise_severity(findings: Iterable[Finding], rules: Iterable[str], to: str = "high") -> list[Finding]:
    """Profile `block:` list: those rules block for this repo."""
    wanted = set(rules)
    out = []
    for f in findings:
        if f.rule in wanted and SEVERITIES.index(f.severity) < SEVERITIES.index(to):
            f = dataclasses.replace(f, severity=to)
        out.append(f)
    return out


def apply_explained(findings: Iterable[Finding], profile) -> list[Finding]:
    """Findings the owning lane has explained (profile `explained:`, each
    with its reason and the tracker comment it was given in) drop to info.
    They stay in the report, marked, so an explanation is never invisible."""
    out = []
    for f in findings:
        e = profile.explanation(f.rule, f.location)
        if e and f.category != "harness":
            f = dataclasses.replace(f, severity="info", title=f"{f.title} Explained: {e['reason']} ({e['source']})")
        out.append(f)
    return out


def blocking_set(findings: Iterable[Finding]) -> set[str]:
    return {f.fingerprint for f in findings if f.blocking}


def load(path: str) -> list[Finding]:
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    return [Finding.from_dict(d) for d in data.get("findings", data if isinstance(data, list) else [])]
