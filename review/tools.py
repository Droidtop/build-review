"""Running the external analysers.

A missing or failing analyser never lets a build through: it becomes a
`harness.*` finding, and a review with one is "can't be reviewed", which the
policy lists for the owner (Droidtop/tracker#550: "Releases that fail, or
can't be reviewed, aren't re-signed").
"""
from __future__ import annotations

import json
import os
import shutil
import signal
import subprocess

from .findings import Finding


class ToolMissing(Exception):
    pass


def run(cmd: list[str], timeout: int = 1800, ok_codes=(0,), cwd=None) -> subprocess.CompletedProcess:
    if shutil.which(cmd[0]) is None:
        raise ToolMissing(cmd[0])
    # Own process group, so a timeout takes the tool's children with it
    # (capa's bootloader forks the real analyser, which otherwise outlives it).
    with subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, cwd=cwd,
                          start_new_session=True) as p:
        try:
            out, err = p.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            os.killpg(p.pid, signal.SIGKILL)
            p.communicate()
            raise
    proc = subprocess.CompletedProcess(cmd, p.returncode, out, err)
    if proc.returncode not in ok_codes:
        raise RuntimeError(f"{cmd[0]} exited {proc.returncode}: {proc.stderr[-1500:]}")
    return proc


def run_json(cmd: list[str], **kw):
    out = run(cmd, **kw).stdout
    return json.loads(out) if out.strip() else None


def harness_finding(analyser: str, exc: BaseException) -> Finding:
    if isinstance(exc, ToolMissing):
        rule, title = "harness.tool-missing", f"The analyser {exc} is not installed, so this part was not reviewed."
    elif isinstance(exc, subprocess.TimeoutExpired):
        rule, title = "harness.timeout", f"{analyser} timed out, so this part was not reviewed."
    else:
        rule, title = "harness.analyser-failed", f"{analyser} failed, so this part was not reviewed."
    return Finding(analyser, rule, "critical", title, evidence=str(exc), category="harness")
