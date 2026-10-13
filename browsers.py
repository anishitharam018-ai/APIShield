"""Reads installed browsers: extensions, saved-login COUNT, recent domains."""
import json
import os
import platform
import shutil
import sqlite3
import tempfile
from datetime import datetime, timedelta
from urllib.parse import urlparse


# ------------------------------------------------------------- browsers -----
# Reads what is already on this computer's disk: which browsers are
# installed, which extensions they have, how many saved logins each profile
# holds (a COUNT only - the encrypted password values are never opened or
# decrypted), and a short list of recently visited domains for your own
# review. Nothing here is sent anywhere; it is shown only on this dashboard.
BROWSER_PROCESS_NAMES = {
    "chrome.exe": "Chrome", "chrome": "Chrome",
    "msedge.exe": "Edge", "msedge": "Edge",
    "firefox.exe": "Firefox", "firefox": "Firefox",
    "brave.exe": "Brave", "brave": "Brave",
    "opera.exe": "Opera", "opera": "Opera",
    "iexplore.exe": "Internet Explorer",
}
_WEBKIT_EPOCH = datetime(1601, 1, 1)


def running_browsers(procs):
    seen = {}
    for p in procs.values():
        disp = BROWSER_PROCESS_NAMES.get((p.get("name") or "").lower())
        if disp:
            seen[disp] = seen.get(disp, 0) + 1
    return [{"name": n, "windows": c} for n, c in sorted(seen.items())]


def _copy_locked(path, tmpdir):
    if not os.path.isfile(path):
        return None
    dst = os.path.join(tmpdir, os.path.basename(path) + ("_%d" % len(os.listdir(tmpdir))))
    try:
        shutil.copy2(path, dst)
        return dst
    except Exception:
        return None


def _chromium_user_data_dirs():
    out = {}
    if os.name == "nt":
        local = os.environ.get("LOCALAPPDATA", "")
        out["Chrome"] = os.path.join(local, "Google", "Chrome", "User Data")
        out["Edge"] = os.path.join(local, "Microsoft", "Edge", "User Data")
        out["Brave"] = os.path.join(local, "BraveSoftware", "Brave-Browser", "User Data")
    elif platform.system() == "Darwin":
        home = os.path.expanduser("~")
        out["Chrome"] = os.path.join(home, "Library", "Application Support", "Google", "Chrome")
        out["Edge"] = os.path.join(home, "Library", "Application Support", "Microsoft Edge")
    else:
        home = os.path.expanduser("~")
        out["Chrome"] = os.path.join(home, ".config", "google-chrome")
        out["Edge"] = os.path.join(home, ".config", "microsoft-edge")
    return {k: v for k, v in out.items() if os.path.isdir(v)}


def _chromium_profiles(base):
    out = []
    for name in os.listdir(base):
        p = os.path.join(base, name)
        if os.path.isdir(p) and (name == "Default" or name.startswith("Profile ")):
            out.append((name, p))
    return out


def chromium_history(profile_path, tmpdir, limit=12):
    src = os.path.join(profile_path, "History")
    copy = _copy_locked(src, tmpdir)
    if not copy:
        return None, "History file not found or locked (close the browser and scan again)."
    try:
        con = sqlite3.connect(copy)
        rows = con.execute(
            "SELECT url, visit_count, last_visit_time FROM urls ORDER BY last_visit_time DESC LIMIT ?", (limit,)
        ).fetchall()
        con.close()
        out = []
        for url, visits, last in rows:
            try:
                dt = _WEBKIT_EPOCH + timedelta(microseconds=last)
            except Exception:
                dt = None
            out.append({"domain": urlparse(url).netloc or url, "visits": visits,
                         "last_visit": dt.isoformat() if dt else None})
        return out, None
    except Exception as exc:
        return None, "Could not read history (%s)." % exc


def chromium_login_count(profile_path, tmpdir):
    src = os.path.join(profile_path, "Login Data")
    copy = _copy_locked(src, tmpdir)
    if not copy:
        return None
    try:
        con = sqlite3.connect(copy)
        n = con.execute("SELECT COUNT(*) FROM logins").fetchone()[0]
        con.close()
        return n
    except Exception:
        return None


def chromium_extensions(profile_path):
    ext_dir = os.path.join(profile_path, "Extensions")
    out = []
    if not os.path.isdir(ext_dir):
        return out
    try:
        for ext_id in os.listdir(ext_dir):
            vdir = os.path.join(ext_dir, ext_id)
            if not os.path.isdir(vdir):
                continue
            versions = sorted(os.listdir(vdir), reverse=True)
            for v in versions:
                manifest = os.path.join(vdir, v, "manifest.json")
                if os.path.isfile(manifest):
                    try:
                        with open(manifest, encoding="utf-8", errors="ignore") as fh:
                            data = json.load(fh)
                        name = data.get("name") or ext_id
                        if name.startswith("__MSG_"):
                            name = ext_id  # localized name file not worth resolving here
                        out.append({"id": ext_id, "name": name, "version": data.get("version") or v})
                    except Exception:
                        pass
                    break
    except Exception:
        pass
    return out


def _firefox_profiles():
    if os.name == "nt":
        base = os.path.join(os.environ.get("APPDATA", ""), "Mozilla", "Firefox", "Profiles")
    elif platform.system() == "Darwin":
        base = os.path.expanduser("~/Library/Application Support/Firefox/Profiles")
    else:
        base = os.path.expanduser("~/.mozilla/firefox")
    if not os.path.isdir(base):
        return []
    return [(name, os.path.join(base, name)) for name in os.listdir(base) if os.path.isdir(os.path.join(base, name))]


def firefox_history(profile_path, tmpdir, limit=12):
    src = os.path.join(profile_path, "places.sqlite")
    copy = _copy_locked(src, tmpdir)
    if not copy:
        return None, "History file not found or locked (close Firefox and scan again)."
    try:
        con = sqlite3.connect(copy)
        rows = con.execute(
            "SELECT url, visit_count, last_visit_date FROM moz_places "
            "WHERE last_visit_date IS NOT NULL ORDER BY last_visit_date DESC LIMIT ?", (limit,)
        ).fetchall()
        con.close()
        out = []
        for url, visits, last in rows:
            try:
                dt = datetime(1970, 1, 1) + timedelta(microseconds=last)
            except Exception:
                dt = None
            out.append({"domain": urlparse(url).netloc or url, "visits": visits or 0,
                         "last_visit": dt.isoformat() if dt else None})
        return out, None
    except Exception as exc:
        return None, "Could not read history (%s)." % exc


def firefox_login_count(profile_path):
    src = os.path.join(profile_path, "logins.json")
    if not os.path.isfile(src):
        return None
    try:
        with open(src, encoding="utf-8", errors="ignore") as fh:
            data = json.load(fh)
        return len(data.get("logins") or [])
    except Exception:
        return None


def firefox_extensions(profile_path):
    src = os.path.join(profile_path, "extensions.json")
    out = []
    if not os.path.isfile(src):
        return out
    try:
        with open(src, encoding="utf-8", errors="ignore") as fh:
            data = json.load(fh)
        for a in data.get("addons") or []:
            if a.get("type") != "extension" or not a.get("active", True):
                continue
            loc = a.get("defaultLocale") or {}
            out.append({"id": a.get("id") or "?", "name": loc.get("name") or a.get("id") or "?",
                        "version": a.get("version") or ""})
    except Exception:
        pass
    return out


def browser_scan(procs):
    """Everything this section knows: which browsers are running, and, for
    each installed browser profile, its extensions, a saved-login COUNT
    (never the passwords themselves), and recently visited domains."""
    result = {"running": running_browsers(procs), "browsers": [], "notes": []}
    with tempfile.TemporaryDirectory(prefix="apishield_") as tmpdir:
        for disp, base in _chromium_user_data_dirs().items():
            try:
                profiles = _chromium_profiles(base)
            except Exception:
                profiles = []
            for pname, ppath in profiles:
                history, note = chromium_history(ppath, tmpdir)
                entry = {
                    "name": disp, "profile": pname,
                    "extensions": chromium_extensions(ppath),
                    "saved_logins": chromium_login_count(ppath, tmpdir),
                    "history": history or [],
                }
                if note:
                    result["notes"].append("%s (%s): %s" % (disp, pname, note))
                result["browsers"].append(entry)

        for pname, ppath in _firefox_profiles():
            if not (os.path.isfile(os.path.join(ppath, "places.sqlite"))
                    or os.path.isfile(os.path.join(ppath, "extensions.json"))):
                continue
            history, note = firefox_history(ppath, tmpdir)
            entry = {
                "name": "Firefox", "profile": pname,
                "extensions": firefox_extensions(ppath),
                "saved_logins": firefox_login_count(ppath),
                "history": history or [],
            }
            if note:
                result["notes"].append("Firefox (%s): %s" % (pname, note))
            result["browsers"].append(entry)
    return result
