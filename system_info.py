"""Startup entries, hosts file and firewall checks (read-only)."""
import os
import subprocess


def startup_entries():
    out = []
    if os.name == "nt":
        try:
            import winreg
            for hive, hname in ((winreg.HKEY_CURRENT_USER, "HKCU"), (winreg.HKEY_LOCAL_MACHINE, "HKLM")):
                for sub in (r"Software\Microsoft\Windows\CurrentVersion\Run",
                            r"Software\Microsoft\Windows\CurrentVersion\RunOnce"):
                    try:
                        with winreg.OpenKey(hive, sub) as key:
                            i = 0
                            while True:
                                try:
                                    name, val, _ = winreg.EnumValue(key, i)
                                except OSError:
                                    break
                                out.append({"name": name, "command": str(val)})
                                i += 1
                    except OSError:
                        pass
        except ImportError:
            pass
        folders = (os.path.join(os.environ.get("APPDATA", ""), r"Microsoft\Windows\Start Menu\Programs\Startup"),
                   os.path.join(os.environ.get("ProgramData", ""), r"Microsoft\Windows\Start Menu\Programs\StartUp"))
    else:
        folders = (os.path.expanduser("~/.config/autostart"),)
    for base in folders:
        if base and os.path.isdir(base):
            for f in os.listdir(base):
                if f.lower() != "desktop.ini":
                    out.append({"name": f, "command": os.path.join(base, f)})
    return out


def custom_hosts():
    path = r"C:\Windows\System32\drivers\etc\hosts" if os.name == "nt" else "/etc/hosts"
    out = []
    try:
        with open(path, encoding="utf-8", errors="ignore") as fh:
            for line in fh:
                line = line.split("#")[0].strip()
                parts = line.split()
                if len(parts) >= 2 and not all(n.lower() in ("localhost", "localhost.localdomain", "ip6-localhost", "ip6-loopback",
                                                                 "broadcasthost") for n in parts[1:]):
                    out.append("%s %s" % (parts[0], " ".join(parts[1:])))
    except OSError:
        pass
    return out


def firewall_state():
    if os.name != "nt":
        return None
    try:
        r = subprocess.run(["netsh", "advfirewall", "show", "allprofiles", "state"], capture_output=True, text=True,
                           timeout=8, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        states = [ln.split()[-1].lower() for ln in r.stdout.splitlines() if ln.strip().lower().startswith("state")]
        if states:
            return "off" if "off" in states else "on"
    except Exception:
        pass
    return None
