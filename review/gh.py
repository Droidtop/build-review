"""The few GitHub REST calls the harness makes. All of them read.

Every repo the harness reads is public, so it uses the run's own
GITHUB_TOKEN (for the rate limit) or none. There is no harness token and the
harness writes nothing to GitHub through this module (owner, 2026-11-05:
"Drop the token, file the issues yourself").
"""
from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

API = os.environ.get("GITHUB_API_URL", "https://api.github.com")


class GitHub:
    def __init__(self, token: str | None = None):
        self.token = token or os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN") or ""

    def _req(self, method: str, path: str, body=None, accept="application/vnd.github+json", raw=False):
        if method != "GET":
            raise RuntimeError("the build review harness only reads from GitHub")
        url = path if path.startswith("http") else f"{API}{path}"
        data = json.dumps(body).encode() if body is not None else None
        for attempt in range(5):
            req = urllib.request.Request(url, data=data, method=method)
            req.add_header("Accept", accept)
            req.add_header("X-GitHub-Api-Version", "2022-11-28")
            req.add_header("User-Agent", "droidtop-build-review")
            if self.token:
                req.add_header("Authorization", f"Bearer {self.token}")
            if data is not None:
                req.add_header("Content-Type", "application/json")
            try:
                with urllib.request.urlopen(req, timeout=120) as resp:
                    payload = resp.read()
                    return payload if raw else (json.loads(payload) if payload else None)
            except urllib.error.HTTPError as e:
                if e.code in (403, 429, 502, 503) and attempt < 4:
                    wait = int(e.headers.get("Retry-After") or 2 ** (attempt + 1))
                    time.sleep(min(wait, 60))
                    continue
                raise

    def get(self, path, **kw):
        return self._req("GET", path, **kw)

    def paged(self, path: str):
        sep = "&" if "?" in path else "?"
        page = 1
        while True:
            items = self.get(f"{path}{sep}per_page=100&page={page}")
            if not items:
                return
            yield from items
            if len(items) < 100:
                return
            page += 1

    # Releases
    def release(self, repo: str, tag: str) -> dict:
        return self.get(f"/repos/{repo}/releases/tags/{urllib.parse.quote(tag, safe='')}")

    def releases(self, repo: str) -> list[dict]:
        return list(self.paged(f"/repos/{repo}/releases"))

    def download_asset(self, repo: str, asset: dict, dest: Path) -> Path:
        dest.mkdir(parents=True, exist_ok=True)
        out = dest / Path(asset["name"]).name
        data = self.get(f"/repos/{repo}/releases/assets/{asset['id']}", accept="application/octet-stream", raw=True)
        out.write_bytes(data)
        return out

    def tag_commit(self, repo: str, tag: str) -> str:
        ref = self.get(f"/repos/{repo}/git/ref/tags/{urllib.parse.quote(tag, safe='')}")
        obj = ref["object"]
        while obj["type"] == "tag":
            obj = self.get(obj["url"])["object"]
        return obj["sha"]

    # Issues
    def issue(self, repo: str, number: int) -> dict:
        return self.get(f"/repos/{repo}/issues/{number}")

    def comments(self, repo: str, number: int) -> list[dict]:
        return list(self.paged(f"/repos/{repo}/issues/{number}/comments"))
