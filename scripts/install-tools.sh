#!/usr/bin/env bash
# Installs every analyser at a pinned version, each download checked against
# a pinned SHA-256 (taken from the project's own published checksums). A
# mismatch stops the run: the harness never reviews with a tool it can't
# vouch for.
set -euo pipefail
bin="${1:-$HOME/.local/bin}"
mkdir -p "$bin"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

fetch() { # url sha256 out
  curl -sSfL --retry 4 -o "$3" "$1"
  echo "$2  $3" | sha256sum -c --quiet -
}

fetch https://github.com/gitleaks/gitleaks/releases/download/v8.30.1/gitleaks_8.30.1_linux_x64.tar.gz \
  551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb "$tmp/gitleaks.tgz"
tar -xzf "$tmp/gitleaks.tgz" -C "$bin" gitleaks

fetch https://github.com/anchore/syft/releases/download/v1.56.0/syft_1.56.0_linux_amd64.tar.gz \
  1c2493cfcf52d3367d6cb25780d9190c111c2219c34c820574c43e8bae15c528 "$tmp/syft.tgz"
tar -xzf "$tmp/syft.tgz" -C "$bin" syft

fetch https://github.com/anchore/grype/releases/download/v0.121.1/grype_0.121.1_linux_amd64.tar.gz \
  bc3ea3f9e6fd56ac781c08c6c5e614271b79f438200757f6932085c19b0a4657 "$tmp/grype.tgz"
tar -xzf "$tmp/grype.tgz" -C "$bin" grype

fetch https://github.com/google/osv-scanner/releases/download/v2.7.0/osv-scanner_linux_amd64 \
  160c6253e2922e9e0a6a9771c5c4c40a4b3c6090b34a3cdd5e80c96cc2e4218b "$bin/osv-scanner"
chmod +x "$bin/osv-scanner"

fetch https://github.com/mandiant/capa/releases/download/v10.0.0/capa-v10.0.0-linux.zip \
  96cb5115f495024a478b0e9f9f77f9027058155589235fbd4c50e7382055fcca "$tmp/capa.zip"
unzip -q -o "$tmp/capa.zip" -d "$bin"
chmod +x "$bin/capa"

if command -v apt-get >/dev/null && [ "${INSTALL_APT:-1}" = 1 ]; then
  sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -q yara tshark aapt >/dev/null
fi
python3 -m pip install -q -r "$(dirname "$0")/../requirements.txt"
# Quark's behaviour rules, at a pinned commit of quark-engine/quark-rules.
rules="$HOME/.quark-engine/quark-rules"
if [ ! -d "$rules/.git" ]; then
  git init -q "$rules" && git -C "$rules" remote add origin https://github.com/quark-engine/quark-rules
fi
git -C "$rules" fetch -q --depth 1 origin 514c21ca43e1cd41c51c72054d3b5581c59e1f0f
git -C "$rules" checkout -q FETCH_HEAD
# Grype's CVE database, fetched once per run so every release in a batch is
# judged against the same data; its build date goes in the record.
"$bin/grype" db update -q || "$bin/grype" db update
"$bin/grype" db status | tee "$bin/grype-db-status.txt"
echo "$bin" >> "${GITHUB_PATH:-/dev/null}"
