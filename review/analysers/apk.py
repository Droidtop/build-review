"""APK: manifest, permissions, components, dex API use, strings, obfuscation.

Real analysers: androguard (manifest and dex cross-references), APKiD
(packers, obfuscators, anti-analysis, by YARA), Quark-Engine (behaviour
rules for Android malware).
"""
from __future__ import annotations

import logging
import os
import re
from pathlib import Path

from ..findings import Finding
from ..profile import Profile
from ..tools import harness_finding, run, run_json

A = "apk"

# Permissions whose mere presence needs a stated reason, and how bad it is
# when the profile gives none.
HIGH_RISK_PERMS = {
    "android.permission.BIND_ACCESSIBILITY_SERVICE": "critical",
    "android.permission.BIND_DEVICE_ADMIN": "critical",
    "android.permission.READ_SMS": "critical",
    "android.permission.SEND_SMS": "critical",
    "android.permission.RECEIVE_SMS": "critical",
    "android.permission.READ_CALL_LOG": "critical",
    "android.permission.PROCESS_OUTGOING_CALLS": "critical",
    "android.permission.BIND_NOTIFICATION_LISTENER_SERVICE": "high",
    "android.permission.READ_CONTACTS": "high",
    "android.permission.RECORD_AUDIO": "high",
    "android.permission.CAMERA": "high",
    "android.permission.ACCESS_FINE_LOCATION": "high",
    "android.permission.ACCESS_BACKGROUND_LOCATION": "high",
    "android.permission.REQUEST_INSTALL_PACKAGES": "high",
    "android.permission.REQUEST_DELETE_PACKAGES": "high",
    "android.permission.SYSTEM_ALERT_WINDOW": "high",
    "android.permission.QUERY_ALL_PACKAGES": "medium",
    "android.permission.MANAGE_EXTERNAL_STORAGE": "medium",
    "android.permission.READ_PHONE_STATE": "high",
    "android.permission.GET_ACCOUNTS": "high",
    "android.permission.USE_CREDENTIALS": "high",
    "android.permission.WRITE_SETTINGS": "medium",
    "android.permission.WRITE_SECURE_SETTINGS": "critical",
    "android.permission.INSTALL_PACKAGES": "critical",
    "android.permission.READ_LOGS": "high",
}

# Sensitive API categories: (class prefix, method name or None) -> category.
API_CATEGORIES = {
    "exec": [("Ljava/lang/Runtime;", "exec"), ("Ljava/lang/ProcessBuilder;", "start")],
    "dynamic-code": [("Ldalvik/system/DexClassLoader;", None), ("Ldalvik/system/InMemoryDexClassLoader;", None),
                     ("Ldalvik/system/PathClassLoader;", "<init>"), ("Ldalvik/system/BaseDexClassLoader;", "<init>")],
    "native-load": [("Ljava/lang/System;", "load"), ("Ljava/lang/System;", "loadLibrary"),
                    ("Ljava/lang/Runtime;", "load"), ("Ljava/lang/Runtime;", "loadLibrary")],
    "reflection": [("Ljava/lang/reflect/Method;", "invoke"), ("Ljava/lang/Class;", "forName")],
    "sms": [("Landroid/telephony/SmsManager;", None)],
    "telephony-ids": [("Landroid/telephony/TelephonyManager;", "getDeviceId"),
                      ("Landroid/telephony/TelephonyManager;", "getImei"),
                      ("Landroid/telephony/TelephonyManager;", "getSubscriberId"),
                      ("Landroid/telephony/TelephonyManager;", "getLine1Number")],
    "accounts": [("Landroid/accounts/AccountManager;", "getAccounts"),
                 ("Landroid/accounts/AccountManager;", "getAuthToken")],
    "clipboard-read": [("Landroid/content/ClipboardManager;", "getPrimaryClip")],
    "device-admin": [("Landroid/app/admin/DevicePolicyManager;", None)],
    "accessibility": [("Landroid/accessibilityservice/AccessibilityService;", None)],
    "package-install": [("Landroid/content/pm/PackageInstaller;", None)],
    "webview-js-bridge": [("Landroid/webkit/WebView;", "addJavascriptInterface")],
    "location": [("Landroid/location/LocationManager;", "requestLocationUpdates"),
                 ("Landroid/location/LocationManager;", "getLastKnownLocation")],
    "camera": [("Landroid/hardware/camera2/CameraManager;", "openCamera"), ("Landroid/hardware/Camera;", "open")],
    "audio-record": [("Landroid/media/AudioRecord;", "<init>"), ("Landroid/media/MediaRecorder;", "setAudioSource")],
    "contacts": [("Landroid/provider/ContactsContract", None)],
    "screen-capture": [("Landroid/media/projection/MediaProjectionManager;", None)],
    "su": [],  # from strings, below
    "trust-all-tls": [],  # from code shape, below
}
API_SEVERITY = {"sms": "critical", "device-admin": "critical", "accessibility": "high", "telephony-ids": "high",
                "accounts": "high", "su": "high", "trust-all-tls": "high", "screen-capture": "high",
                "audio-record": "high", "camera": "high", "contacts": "high", "location": "high",
                "clipboard-read": "medium", "dynamic-code": "high", "package-install": "high",
                "webview-js-bridge": "medium", "exec": "medium", "native-load": "low", "reflection": "info"}

URL_RE = re.compile(r"\b(?:https?|wss?|ftp)://([A-Za-z0-9.-]+)(?::\d+)?[^\s\"'<>]*")
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
SU_RE = re.compile(r"(^|/)(su|busybox|magisk)$|/system/xbin/su|/sbin/su")


def analyse(apk_path: str, profile: Profile, facts: dict) -> list[Finding]:
    out: list[Finding] = []
    try:
        out += _androguard(apk_path, profile, facts)
    except Exception as e:  # noqa: BLE001 - every failure becomes a finding
        out.append(harness_finding("androguard", e))
    # androguard's analysis of a large APK holds several GB; let it go
    # before APKiD, Quark and the native analysers start.
    import gc
    gc.collect()
    try:
        out += _apkid(apk_path, profile)
    except Exception as e:  # noqa: BLE001
        out.append(harness_finding("apkid", e))
    try:
        out += _quark(apk_path)
    except Exception as e:  # noqa: BLE001
        out.append(harness_finding("quark", e))
    return out


def _androguard(apk_path: str, profile: Profile, facts: dict) -> list[Finding]:
    logging.getLogger("androguard").setLevel(logging.ERROR)
    try:
        from loguru import logger as _l  # androguard 4 logs through loguru
        _l.remove()
    except Exception:  # noqa: BLE001
        pass
    from androguard.misc import AnalyzeAPK

    a, _d, dx = AnalyzeAPK(apk_path)
    out: list[Finding] = []
    name = Path(apk_path).name
    perms = sorted(set(a.get_permissions()))
    facts.update({
        "package": a.get_package(),
        "versionName": a.get_androidversion_name(),
        "versionCode": a.get_androidversion_code(),
        "minSdk": a.get_min_sdk_version(),
        "targetSdk": a.get_target_sdk_version(),
        "permissions": perms,
        "activities": sorted(a.get_activities()),
        "services": sorted(a.get_services()),
        "receivers": sorted(a.get_receivers()),
        "providers": sorted(a.get_providers()),
        "nativeLibs": sorted(f for f in a.get_files() if f.startswith("lib/") and f.endswith(".so")),
        "signers": [c.sha256_fingerprint for c in a.get_certificates()] if hasattr(a, "get_certificates") else [],
    })

    # Permissions against stated purpose.
    for p in perms:
        if p in profile.permissions:
            continue
        sev = HIGH_RISK_PERMS.get(p, "medium" if p.startswith("android.permission.") else "low")
        out.append(Finding(A, "permission.not-in-purpose", sev,
                           f"Declares {p}, which the repo's stated purpose does not list.",
                           location=f"{name}:AndroidManifest.xml", evidence=p, category="purpose"))

    # Manifest flags.
    app = a.get_android_manifest_xml().find("application")
    ns = "{http://schemas.android.com/apk/res/android}"
    if app is not None:
        if app.get(ns + "debuggable") == "true":
            out.append(Finding(A, "manifest.debuggable", "high", "The release is debuggable.",
                               location=f"{name}:AndroidManifest.xml", category="vulnerability"))
        if app.get(ns + "usesCleartextTraffic") == "true":
            out.append(Finding(A, "manifest.cleartext", "medium", "The app allows cleartext HTTP.",
                               location=f"{name}:AndroidManifest.xml", category="network"))
        if app.get(ns + "testOnly") == "true":
            out.append(Finding(A, "manifest.test-only", "medium", "The release is marked testOnly.",
                               location=f"{name}:AndroidManifest.xml", category="nonsense"))

    # Exported components with no permission guarding them.
    for tag in ("activity", "activity-alias", "service", "receiver", "provider"):
        for item in a.get_android_manifest_xml().iter(tag):
            comp = item.get(ns + "name") or "?"
            exported = item.get(ns + "exported")
            has_filter = item.find("intent-filter") is not None
            if exported == "true" or (exported is None and has_filter):
                guards = [item.get(ns + "permission")]
                if tag == "provider":
                    # A provider is guarded by readPermission and
                    # writePermission too; both must be set to count.
                    guards.append(item.get(ns + "readPermission") and item.get(ns + "writePermission"))
                if any(guards):
                    continue
                is_launcher = any(c.get(ns + "name") == "android.intent.category.LAUNCHER"
                                  for f in item.iter("intent-filter") for c in f.iter("category"))
                if is_launcher or any(comp.endswith(x) or comp == x for x in profile.exported_ok):
                    continue
                sev = "high" if tag in ("provider", "service") else "medium"
                out.append(Finding(A, f"component.exported-unguarded.{tag}", sev,
                                   f"The {tag} {comp} is exported with no permission and the profile does not "
                                   "say why.", location=comp, category="vulnerability"))

    # API use against stated purpose, from dex cross-references.
    used: dict[str, list[str]] = {}
    for cat, sigs in API_CATEGORIES.items():
        for cls, meth in sigs:
            for m in dx.find_methods(classname=re.escape(cls) + ("" if cls.endswith(";") else ".*"),
                                     methodname=(re.escape(meth) + "$") if meth else ".*"):
                callers = [f"{c.name}->{mm.name}" for c, mm, _o in m.get_xref_from()]
                callers = [c for c in callers if not c.startswith(("Landroidx/", "Lkotlin/", "Landroid/"))]
                if callers:
                    used.setdefault(cat, []).extend(callers)

    strings = [s.get_value() for s in dx.get_strings()]
    if any(SU_RE.search(s) for s in strings):
        used.setdefault("su", []).append(next(s for s in strings if SU_RE.search(s)))

    # TrustManagers whose checkServerTrusted does nothing: a known MITM hole.
    for cls in dx.get_classes():
        if cls.is_external():
            continue
        ifaces = cls.implements or []
        if "Ljavax/net/ssl/X509TrustManager;" in ifaces:
            for meth in cls.get_methods():
                if meth.name == "checkServerTrusted" and not meth.is_external():
                    code = meth.get_method().get_code()
                    if code is not None and code.get_length() <= 2:
                        used.setdefault("trust-all-tls", []).append(cls.name)

    # Callers the profile names, each with its reason, don't count: the
    # category still counts for any other caller.
    for cat, ok in (profile.api_callers_ok or {}).items():
        if cat in used:
            used[cat] = [c for c in used[cat] if not any(c.startswith(p) for p in ok)]
            if not used[cat]:
                del used[cat]
    facts["apiCategories"] = sorted(used)
    for cat, where in sorted(used.items()):
        if cat in profile.api:
            continue
        out.append(Finding(A, f"api.not-in-purpose.{cat}", API_SEVERITY.get(cat, "medium"),
                           f"Uses {cat} API, which the repo's stated purpose does not list.",
                           location=f"{name}:{cat}", evidence="\n".join(sorted(set(where))[:10]),
                           category="purpose"))

    # Endpoints in dex strings; the endpoints analyser judges them.
    hosts = facts.setdefault("hosts", {})
    for s in strings:
        for m in URL_RE.finditer(s):
            hosts.setdefault(m.group(1).lower(), f"{name}:dex")
        for ip in IP_RE.findall(s):
            parts = [int(x) for x in ip.split(".")]
            if all(p <= 255 for p in parts) and parts[0] not in (0, 10, 127, 255) and not ip.startswith(("192.168.", "169.254.")):
                if s.strip() == ip or "://" in s:
                    hosts.setdefault(ip, f"{name}:dex")
    return out


def _apkid(apk_path: str, profile: Profile) -> list[Finding]:
    data = run_json(["apkid", "-j", "-t", "300", apk_path], timeout=900)
    out = []
    for f in (data or {}).get("files", []):
        # "<path>!classes2.dex": keep the part inside the APK, so the
        # fingerprint doesn't carry the work folder.
        where = f.get("filename", "")
        where = where.split("!", 1)[1] if "!" in where else Path(where).name
        for key, vals in (f.get("matches") or {}).items():
            if key in ("compiler",):
                continue
            sev = {"packer": "critical", "dropper": "critical", "manipulator": "high",
                   "anti_vm": "medium", "anti_debug": "medium", "anti_hook": "medium", "anti_disassembly": "high",
                   "obfuscator": "low" if profile.obfuscation_ok else "medium"}.get(key, "medium")
            out.append(Finding(A, f"apkid.{key}", sev, f"APKiD detects {key}: {', '.join(vals)}.",
                               location=where, evidence=", ".join(vals), category="obfuscation"))
    return out


def _quark(apk_path: str) -> list[Finding]:
    import json
    import tempfile

    with tempfile.TemporaryDirectory() as tmp:
        report = Path(tmp) / "quark.json"
        rules = os.environ.get("QUARK_RULES", str(Path.home() / ".quark-engine/quark-rules/rules"))
        run(["quark", "-a", apk_path, "-r", rules, "-o", str(report)], timeout=1800)
        data = json.loads(report.read_text()) if report.exists() else None
    out = []
    for crime in (data or {}).get("crimes", []):
        conf = int(str(crime.get("confidence", "0")).rstrip("%") or 0)
        if conf < 80:
            continue
        label = crime.get("crime", "")
        # Quark's 100% means the whole behaviour chain is in the code. It
        # reads as a lead, not a verdict: medium, unless the profile blocks.
        out.append(Finding(A, f"quark.{crime.get('rule', label)[:40]}", "medium",
                           f"Quark: {label} ({conf}%).", location=label, category="malicious",
                           evidence="; ".join(str(x) for x in crime.get("permissions", []))))
    return out
