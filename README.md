# build-review

The automated build review harness for droidtop, Enginehost, gamegrab and
every other Droidtop release. It puts into practice the owner's standard
build review loop (Droidtop/tracker#550, 2026-10-15), so no build is reviewed
by hand. The owner, 2026-11-04: "We need to write the review harness anyway,
so you aren't reviewing it manually".

> "No. We check the build itself for issues. If we find some, then we attempt
> a rebuild. if that rebuild has the same issues, then the issue is in the
> code (whether the code was tampered with or not was irrelevant, we may find
> unknown legitimate vulnerabilities during this process). We patch the code,
> rebuild, and retest. this should be our standard build review system"
> (owner, 2026-10-15)

The harness never signs, re-signs or revokes anything, and never sees a
signing secret. Signing stays with the coordinator. The harness says what
may be signed.

## The loop

| Step | What happens | Where |
|---|---|---|
| 1. Review | Every artefact goes through the static analysers. The dynamic run follows where it applies. | `review-release.yml` jobs `static`, `dynamic` |
| 2. Findings? | Rebuild from the same commit, with no secrets, and review the rebuild the same way. | jobs `rebuild`, `review-rebuild` |
| 3. Decide | **approved**, **rebuilt** or **refused** (with a reason). | job `decide`, `review/decide.py` |
| 4. Fix in code | If the rebuild has the same findings, the harness files a Droidtop/tracker issue (label `build-review`) with the evidence. The owning lane fixes the code, and the fixed build goes through this same loop. | `python -m review file-issue` |

The outcome for each release:

| Outcome | Reason | Meaning | Signable |
|---|---|---|---|
| approved | clean | No blocking finding. | yes, as built |
| rebuilt | build | The published build had blocking findings and the rebuild from its commit has none, so the published build was the problem. | yes, **the rebuild** (`sign-artifact`) |
| refused | code | The rebuild has the same findings, so the issue is in the code. An issue is filed. | no, the fixed release is |
| refused | rebuild-differs | Both builds have blocking findings, but different ones: the build is not reproducible enough to tell the build from the code. | no |
| refused | not-rebuildable | Findings, and no rebuild: no source at the commit, no build command, or the build failed. | no |
| refused | unreviewable | An analyser could not run, the dynamic run was needed and didn't finish, or the repo has no profile. "Releases that fail, or can't be reviewed, aren't re-signed." | no |

Every refused release is listed for the owner: in the inventory's tick, in
the per-repo results comment, and in `build-review-results.json`.

### What blocks

Findings are graded info / low / medium / high / critical. **High and
critical block.** Medium and below go into the report and do not block. A
repo's profile can raise single rules to blocking (`block:`). It can never
lower a high or critical finding.

"Same findings" means the same fingerprint. A fingerprint is the analyser,
the rule and the location, with versions, build numbers and hashes taken
out. A rebuild with a different version string still matches.

## What is reviewed, and with what

Real analysers, pinned to exact versions, and each download checked against
a pinned SHA-256 (`scripts/install-tools.sh`, `requirements.txt`). Every
check maps to an item in the owner's list:

| Policy item | Analysers | Notes |
|---|---|---|
| Malicious behaviour, anything that doesn't make sense | Quark-Engine (Android behaviour rules), YARA `rules/yara` (miners, shells, root tools, hooking frameworks, exfiltration channels), Semgrep `rules/semgrep` (decode-and-exec, download-and-exec, curl into a shell, in Python, Ren'Py, JS, Lua and shell payloads), capa (native capabilities), archive checks (zip-slip, duplicate entries, links, setuid, bombs), manifest checks (payload hash against bytes, unlisted files) | |
| Vulnerabilities | androguard (debuggable, cleartext, unguarded exported components, trust-all TLS managers), LIEF (exec stack, RWX segments, TEXTREL, PIE, canaries, PE NX/ASLR), Semgrep (TLS verify off, pickle, shell=True) | |
| Permissions and API use against the stated purpose | androguard: manifest permissions and dex cross-references to sensitive API categories, against the repo's profile. Plugin `manifest.json` host-API permissions, and `priv.*` requires that aren't optional (plugin API §2.7). | `profiles/` |
| Network endpoints | Hosts and IPs from dex strings, native strings, manifests and catalogs, against the profile. Known exfiltration hosts are critical, a hard-coded public IP is high. Catalog entries must be HTTPS and carry a hash. | |
| Process and filesystem behaviour | Dynamic run: processes started, files written outside the app's own storage. Static: exec and process imports. | `scripts/dynamic-android.sh` |
| Native code and obfuscation | LIEF (format, imports, section entropy, symbols), APKiD (packers, obfuscators, anti-VM, anti-debug), UPX detection, capa | capa only disassembles x86 and x86-64. ARM libraries get LIEF, YARA and the dynamic run. |
| Embedded secrets | gitleaks over everything unpacked | Public keys and certificates (`enginehost-public-key.json`, `droidtop-plugin-key.json`, `.crt`) are expected. |
| Dependencies and CVEs | Syft (SBOM of what ships) with Grype, and OSV-Scanner over the source's lockfiles at the release's commit | Grype's database is updated once per run and its build date is logged. |
| Differences from the build's own earlier releases | The previous published release is reviewed the same way and diffed: new permissions, host permissions, API categories, endpoints, native files, components and native imports; package change; version regression; native growth; a catalog entry whose download changed at the same version | `review/analysers/behaviour.py: diff` |

### Static on everything, dynamic where it applies

This is the standard (owner, 2026-11-04). Every artefact gets the full
static pass. The dynamic run happens for every APK and plugin bundle (whose
payload is an APK), and for any other artefact whose static findings are
blocking and malicious, obfuscation, process or network in kind. It runs in
a throwaway KVM Android emulator (API 34, google_apis x86_64 with ARM
translation). The app is installed, launched and driven by the monkey with a
fixed seed. The emulator's `-tcpdump` captures every packet. Processes are
sampled every 2 s. Files written since install are listed, and logcat is
scanned. `tshark` reads DNS queries, TLS SNI, and connections made without a
lookup, and the emulator's own Google traffic is left out. The observer has
root; the app under test never does. No game content is installed: the app
runs with what it ships.

A plugin bundle's APK is run on its own, not inside droidtop's plugin host.
That covers install-time and component behaviour. In-host behaviour is
covered statically by the declared host-API permissions. Engine bundles and
catalogs that hold no runnable Android code get the static pass only.

### Kinds of artefact

| Kind | Detected by | Gets |
|---|---|---|
| `apk` | `.apk` | APK analysers, native analysers on its `lib/`, and everything generic |
| `plugin-bundle` | `.droidplugin.tar.xz` | Safe unpack, manifest and payload hash checks, host-API permissions, APK analysers on the payload, everything generic |
| `engine-bundle` | profile (Enginehost core bundles) | The same as a plugin bundle, plus the `lockdown` flag |
| `catalog` | `catalog*.json` / `.jws` | Entry checks (HTTPS, hash, duplicates), endpoints, silent changes against the previous catalog |
| `archive` / native | zip, tar, ELF, PE | Safe unpack, native, YARA, secrets, SBOM and CVEs, scripts |

## Profiles: the stated purpose

`profiles/<owner>/<repo>.yml` (template: `profiles/_template.yml`) records a
repo's purpose as rules: which assets are reviewed, how to rebuild, and the
permissions, host-API permissions, API categories, endpoints, native
libraries and exported components it needs, each with its reason. Anything
not listed is unexpected.

- Profiles live here, not in the repo under review. An old release is
  judged against today's statement of purpose, and a tampered repo can't
  widen its own allowance.
- A repo with no profile gets `profile.missing` (refused, unreviewable).
  That is deliberate: without a stated purpose nothing can be judged. Each
  owning lane writes its own repo's profile. A profile change is reviewed
  like code, because it widens what a build may do.
- Today only `Droidtop/droidtop` has one, a pilot draft taken from main's
  manifests at 8b447d7. The droidtop lane confirms it against
  `docs/SPEC.md`.

## Rebuilds

The `rebuild` job checks out the repo at the release's commit and builds it
with the profile's `build.command`. Its toolchain is the repo's own
`.github/actions/android-setup` at that commit (`setup: repo-android-setup`),
or a pinned Java, Python or Rust. The job holds no secret. Its token can only
read, and signing variables are set empty. A rebuild is therefore unsigned
by construction. droidtop's Gradle falls back to the debug key when
`SIGNING_KEYSTORE_PATH` is unset (`app/build.gradle.kts:98-145`). The
rebuild is compared by findings, not bytes: "verifying older plugins means
checking for malicious behavior or stuff that doesn't make sense, not
verifying it's exactly what we had" (owner, 2026-10-15).

## Using it

### The standing gate before signing new builds

Each repo's release workflow splits build from sign, and calls the review in
between (full example: `docs/caller-gate.yml`):

```yaml
review:
  needs: build
  uses: Droidtop/build-review/.github/workflows/review-release.yml@v1
  with: {release: "build-${{ github.run_number }}", source: artifact, artifact-name: unsigned, mode: gate}
  secrets: {BUILD_REVIEW_TOKEN: "${{ secrets.BUILD_REVIEW_TOKEN }}"}
sign:
  needs: review
  if: needs.review.outputs.sign == 'true'
  # sign needs.review.outputs.sign-artifact
```

Pass only `BUILD_REVIEW_TOKEN`, never `secrets: inherit`. Three modes:

- `gate`: the review job fails unless the outcome is approved or rebuilt,
  so an unsignable build is not signed.
- `report`: the same review and outputs, never failing. This is how the
  gate is rolled out: releases are signed as today, and every outcome is in
  the run's summary. Callers take the mode from one variable,
  `vars.BUILD_REVIEW_MODE` (default `report`), so the owner switches every
  repo to `gate` at once.
- `audit`: the batch runner's mode. It records the outcome and carries on. Repos whose
build job signs inline (droidtop's `android-build.yml`, for example) must
first move signing into a job of its own. That change belongs to the lane
and the coordinator, not to this repo.

### The forced audit (batch runner)

`batch.yml` is started by hand only. The owner decided, 2026-11-04, not to
re-audit the releases signed under the exposed chain: "No, we're not gonna
retest this time. This wasn't a key theft, it was an exposure in a secure
environment". So the backlog in #876 is not run. The runner exists for the
next revocation, and for a pilot dry run (`limit: 1`). It reads the inventory issue (default Droidtop/tracker#876)
from its body and its continuation comments, carrying the `### owner/repo`
heading across. It takes the unticked lines that match `repos` and `tags`, up
to `limit` (256 at most per run), and reviews each in audit mode. Then it:

- ticks each line with its outcome and a link to its report, keeping the
  signer evidence as written:
  `- [x] \`build-130\` 2026-10-31 | sha256 list only — **refused** (code), [report](…)`.
  The inventory sits near GitHub's 65,536-character limit, so a line carries
  its link only while its part has room. Past that the tick carries the
  outcome alone.
- keeps one results comment per repo on the inventory, with every release,
  its outcome and its report link, whether or not the line had room;
- writes `build-review-results.json` and attaches it to this repo's
  `audit-results` release.

Its `dry-run` input is on by default. A dry run reviews the releases but
ticks nothing, files nothing and publishes nothing.

### Publishing with the catalog

`build-review-results.json` (`schema: droidtop.build-review-results/1`)
lists every release with its outcome, reason, report link, artefact hashes,
any filed issue, and the rebuilt artefacts. The coordinator publishes it
with the catalog, beside the revocation list, at signing time. The harness
doesn't write to `droidtop-components`, because the catalog is signed.

### Locally

```bash
bash scripts/install-tools.sh ~/.local/bin
```

```bash
python -m review review --repo Droidtop/droidtop --release v0.2.0-dev.2898 --out record.json path/to/droidtop.apk
```

```bash
python -m review decide --original record.json --out decision.json --markdown report.md
```

```bash
python -m pytest -q tests
```

## Setup this needs (owner or coordinator)

- **This repo, public.** Reusable workflows can be called across
  organisations (Droidtop and gamegrab-sources) only from a public repo.
  Callers pin `@v1`, a tag on a reviewed commit.
- **`BUILD_REVIEW_TOKEN`** (optional; the owner's, pending): contents:read
  on every repo in the inventory and issues:write on Droidtop/tracker. It is
  set as a secret here, for the batch runner, and in each calling repo, and
  it is never a signing secret. Without it, everything still runs on the
  run's own token, which reads public repos, releases and the tracker. Only
  writing to the tracker is skipped, with a warning: filed issues, and the
  batch runner's ticks, which then run as a dry run. Private repos need the
  token.
- A `v1` tag on the reviewed commit that callers pin.
- A `build-review` label on Droidtop/tracker (exists).

## Limits, stated

- capa covers x86 and x86-64 native code only. ARM code is judged by LIEF,
  YARA, the imports and the dynamic run.
- The dynamic run sees what a monkey-driven session triggers. Code behind a
  login, a date or a server-side switch may not run. The static API and
  string checks cover it instead.
- Grype needs its database host (`grype.anchore.io`). Without it the review
  is unreviewable, not passed.
- A release with no reviewable asset (the inventory marks some
  `droidtop-agent` builds "sha256 list only") makes `fetch` fail. Its line
  stays unticked rather than being marked refused, so that a network failure
  is never recorded as an outcome. Such releases need their artefacts found
  first.
