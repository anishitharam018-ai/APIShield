"""Transparent rule-based scoring and shared helpers."""
import ipaddress
import os

# ---------------------------------------------------------------- rules -----
SUSPICIOUS_DIRS = ("/appdata/local/temp/", "/windows/temp/", "/downloads/", "/users/public/",
                   "/$recycle.bin/", "/tmp/", "/var/tmp/", "/dev/shm/")
SYSTEM_NAMES = {"svchost.exe", "lsass.exe", "csrss.exe", "services.exe", "winlogon.exe",
                "smss.exe", "wininit.exe", "explorer.exe"}
LOLBINS = {"powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe",
           "rundll32.exe", "regsvr32.exe", "certutil.exe", "bitsadmin.exe"}
COMMON_PORTS = {20, 21, 22, 25, 53, 80, 110, 123, 143, 443, 465, 587, 853, 993, 995,
                5222, 5228, 5353, 8080, 8443}
REMOTE_ACCESS_PORTS = {23: "Telnet", 3389: "Remote Desktop", 5900: "VNC", 5985: "Windows Remote Management"}
SYSROOT = os.environ.get("SystemRoot", "C:\\Windows").lower().replace("\\", "/")


def norm(path):
    return (path or "").lower().replace("\\", "/")


def in_suspicious_dir(exe):
    e = norm(exe)
    return any(m in e for m in SUSPICIOUS_DIRS)


def is_admin():
    try:
        if os.name == "nt":
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        return os.geteuid() == 0
    except Exception:
        return False


def ip_kind(ip):
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return "unknown"
    if a.is_loopback:
        return "loopback"
    if a.is_global:
        return "public"
    return "private"


def rule_score_connection(proc, ip, port, proc_conns):
    """Returns (score 0..1, list of reasons). Simple, transparent rules -
    these back up the deep-learning model and explain its more obvious calls."""
    kind = ip_kind(ip)
    name = (proc.get("name") or "").lower()
    exe = proc.get("exe") or ""
    score = 0.02 if kind == "private" else 0.05
    reasons = []
    if in_suspicious_dir(exe):
        score += 0.35
        reasons.append("The program runs from a temporary, downloads or public folder")
    if name in SYSTEM_NAMES and exe and not norm(exe).startswith(SYSROOT):
        score += 0.50
        reasons.append("It has a Windows system name but is not in the Windows folder")
    if kind == "public":
        if name in LOLBINS:
            score += 0.35
            reasons.append("A scripting or system tool is connecting to the internet")
        if port not in COMMON_PORTS:
            score += 0.20
            reasons.append("It uses an uncommon remote port (%d)" % port)
    if proc_conns > 100:
        score += 0.10
        reasons.append("The program has more than 100 open connections")
    return round(min(score, 0.99), 2), reasons
