#!/usr/bin/env bash
# The dynamic run: install one APK in a throwaway emulator, drive it, and
# write what it did to <out>/trace.json for `python -m review judge-dynamic`.
#
# Runs inside reactivecircus/android-emulator-runner's script, with a
# google_apis image (adb root works there; the release under review never
# gets root, only the observer does). The emulator was started with
# -tcpdump <out>/net.pcap, so every packet the app sends is in the capture.
#
#   PCAP=<capture> dynamic-android.sh <apk> <out-dir> [monkey-events]
#
# One emulator boot runs several APKs one after another; each trace reads
# only the packets captured from its own start time on.
#
# Nothing here uploads anything: the trace and pcap stay in the run's
# artefacts. No game content is installed; the app runs with what it ships.
set -euo pipefail
apk="$1"; out="$2"; events="${3:-600}"
mkdir -p "$out"
adb wait-for-device
adb root >/dev/null 2>&1 || true
adb wait-for-device
until [ "$(adb shell getprop sys.boot_completed | tr -d '\r')" = "1" ]; do sleep 2; done

pkg=$(aapt2 dump packagename "$apk" 2>/dev/null || aapt dump badging "$apk" | sed -n "s/^package: name='\([^']*\)'.*/\1/p")
echo "package: $pkg"

marker=/data/local/tmp/.review-marker
adb shell "touch $marker"
adb shell 'ps -A -o PID,PPID,UID,NAME' > "$out/ps-before.txt" || true
adb logcat -c || true
adb logcat -v threadtime > "$out/logcat.txt" 2>&1 &
logpid=$!

installed=true; install_error=""
if ! adb install -r -g "$apk" > "$out/install.txt" 2>&1; then
  installed=false; install_error=$(tail -c 600 "$out/install.txt")
fi

uid=""; launched=false; crashed=false
start=$(date +%s)
pcap="${PCAP:-$out/net.pcap}"
if $installed; then
  uid=$(adb shell "dumpsys package $pkg" | sed -n 's/.*userId=\([0-9]*\).*/\1/p' | head -1 | tr -d '\r')
  if adb shell monkey -p "$pkg" -c android.intent.category.LAUNCHER 1 > "$out/launch.txt" 2>&1; then launched=true; fi
  sleep 15
  # Sample processes while the monkey drives the UI.
  ( for _ in $(seq 1 90); do adb shell 'ps -A -o PID,PPID,UID,ARGS' 2>/dev/null; sleep 2; done ) > "$out/ps-samples.txt" &
  sampler=$!
  adb shell monkey -p "$pkg" --pct-syskeys 0 --throttle 150 -s 4242 -v "$events" > "$out/monkey.txt" 2>&1 || crashed=true
  sleep 20
  kill $sampler 2>/dev/null || true
fi
kill $logpid 2>/dev/null || true
duration=$(( $(date +%s) - start ))

# Files written since the marker, anywhere the observer can see.
adb shell "find /data /sdcard /storage/emulated/0 -xdev -newer $marker -type f 2>/dev/null" \
  | tr -d '\r' | grep -v -E '^/data/(system|misc|log|tombstones|anr|dalvik-cache|vendor|local/tmp/\.review)|^/data/user_de/0/com\.android|^/data/data/com\.(android|google)' \
  > "$out/files-written.txt" || true

python3 -I - "$out" "$pkg" "$uid" "$installed" "$install_error" "$launched" "$crashed" "$events" "$duration" "$pcap" "$start" <<'PY'
import json, re, subprocess, sys
from pathlib import Path
out, pkg, uid, installed, ierr, launched, crashed, events, dur, pcap, start = sys.argv[1:]
o = Path(out)
dns, sni, direct = set(), set(), set()
pcap = Path(pcap)
if pcap.exists():
    def fields(filt, *f):
        filt = f"({filt}) && frame.time_epoch >= {int(start) - 5}"
        cmd = ["tshark", "-r", str(pcap), "-Y", filt, "-T", "fields"] + sum([["-e", x] for x in f], [])
        return subprocess.run(cmd, capture_output=True, text=True).stdout.splitlines()
    dns = {l.strip().lower() for l in fields("dns.flags.response == 0", "dns.qry.name") if l.strip()}
    sni = {l.strip().lower() for l in fields("tls.handshake.type == 1", "tls.handshake.extensions_server_name") if l.strip()}
    resolved = {a for l in fields("dns.flags.response == 1", "dns.a") for a in l.split(",") if a}
    for l in fields("tcp.flags.syn == 1 && tcp.flags.ack == 0", "ip.dst"):
        ip = l.strip()
        if ip and ip not in resolved and not ip.startswith(("10.", "127.", "192.168.", "172.")):
            direct.add(ip)
# The emulator's own lookups (Google services, time, connectivity checks)
# are the platform's, not the app's.
platform = re.compile(r"(google|gstatic|googleapis|android|gvt1|1e100|ggpht|youtube|doubleclick|googleusercontent)\.(com|net)$|^time\.|connectivitycheck")
dns = {h for h in dns if not platform.search(h)}
sni = {h for h in sni if not platform.search(h)}
children = set()
samples = (o / "ps-samples.txt").read_text(errors="replace") if (o / "ps-samples.txt").exists() else ""
for line in samples.splitlines():
    parts = line.split(None, 3)
    if len(parts) == 4 and uid and parts[2].strip() in (uid, f"u0_a{int(uid) - 10000}" if uid.isdigit() and int(uid) >= 10000 else uid):
        args = parts[3].strip()
        if not args.startswith(pkg):
            children.add(args[:200])
flags = []
log = (o / "logcat.txt").read_text(errors="replace") if (o / "logcat.txt").exists() else ""
for line in log.splitlines():
    if pkg and re.search(r"(DexClassLoader|InMemoryDexClassLoader|Runtime\.exec|su: |avc: denied .*%s|ptrace)" % re.escape(pkg), line):
        flags.append(line.strip()[:300])
files = [l for l in (o / "files-written.txt").read_text().splitlines() if l] if (o / "files-written.txt").exists() else []
trace = {"package": pkg, "installed": installed == "true", "installError": ierr, "launched": launched == "true",
         "crashed": crashed == "true", "events": int(events), "durationSeconds": int(dur),
         "dnsQueries": sorted(dns), "tlsSni": sorted(sni), "directIps": sorted(direct),
         "childProcesses": sorted(children), "filesWritten": sorted(set(files)), "logFlags": flags[:50]}
(o / "trace.json").write_text(json.dumps(trace, indent=2))
print(json.dumps({k: (len(v) if isinstance(v, list) else v) for k, v in trace.items()}))
PY
adb uninstall "$pkg" >/dev/null 2>&1 || true
