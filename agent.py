"""The Agent: collects processes/connections, scores them, runs scans."""
import os
import platform
import socket
import threading
import time
from collections import deque
from concurrent.futures import ThreadPoolExecutor

import psutil

from browsers import BROWSER_PROCESS_NAMES, browser_scan, running_browsers
from deep_learning import Autoencoder, score_connection
from rules import (LOLBINS, REMOTE_ACCESS_PORTS, SYSROOT, SYSTEM_NAMES, in_suspicious_dir,
                   ip_kind, is_admin, norm)
from system_info import custom_hosts, firewall_state, startup_entries
from threats import classify_download, classify_url



class Agent:
    def __init__(self, use_dns=True):
        self.lock = threading.Lock()
        self.state = None
        self.events = deque(maxlen=200)
        self.active = set()
        self.scored = {}  # connection -> (score, reasons), scored once when first seen
        self.next_id = 1
        self.prev_net = None
        self.rdns = {}
        self.pending = set()
        self.pool = ThreadPoolExecutor(max_workers=8) if use_dns else None
        self.dl = Autoencoder()  # the deep-learning anomaly detector, trained live on this machine
        self.browser_events = deque(maxlen=200)  # events reported by the APIShield browser extension
        self.browser_status = None  # most recent page-visit classification

    # reverse DNS, cached, never blocks the collector
    def domain_for(self, ip):
        if self.pool is None or ip_kind(ip) != "public":
            return None
        if ip in self.rdns:
            return self.rdns[ip] or None
        if ip not in self.pending:
            self.pending.add(ip)
            self.pool.submit(self._lookup, ip)
        return None

    def _lookup(self, ip):
        try:
            self.rdns[ip] = socket.gethostbyaddr(ip)[0]
        except Exception:
            self.rdns[ip] = ""
        finally:
            self.pending.discard(ip)

    def collect_procs(self):
        procs = {}
        attrs = ["pid", "name", "exe", "username", "cpu_percent", "memory_info"]
        for p in psutil.process_iter(attrs, ad_value=None):
            i = p.info
            mem = i.get("memory_info")
            procs[i["pid"]] = {
                "pid": i["pid"], "name": i.get("name") or "?", "exe": i.get("exe") or "",
                "user": (i.get("username") or "").split("\\")[-1],
                "cpu": i.get("cpu_percent") or 0.0,
                "mem_mb": (mem.rss / 1048576) if mem else 0.0,
            }
        return procs

    def connections(self, notes):
        try:
            return psutil.net_connections(kind="inet")
        except (psutil.AccessDenied, PermissionError):
            msg = "Connection list needs administrator (or root) rights on this system."
            if msg not in notes:
                notes.append(msg)
            return []

    def snapshot(self):
        notes = []
        procs = self.collect_procs()
        conns = self.connections(notes)

        now = time.time()
        net = psutil.net_io_counters()
        if self.prev_net:
            dt = max(now - self.prev_net[0], 0.001)
            down = (net.bytes_recv - self.prev_net[1]) / dt
            up = (net.bytes_sent - self.prev_net[2]) / dt
        else:
            down = up = 0.0
        self.prev_net = (now, net.bytes_recv, net.bytes_sent)

        per_pid = {}
        for c in conns:
            if c.raddr and c.status in ("ESTABLISHED", "SYN_SENT") and ip_kind(c.raddr.ip) != "loopback":
                per_pid[c.pid] = per_pid.get(c.pid, 0) + 1

        current = set()
        top = {}
        for c in conns:
            if not (c.raddr and c.status in ("ESTABLISHED", "SYN_SENT")):
                continue
            ip, port = c.raddr.ip, c.raddr.port
            if ip_kind(ip) == "loopback":
                continue
            key = (c.pid, c.laddr.port, ip, port)
            current.add(key)
            proc = procs.get(c.pid) or {"pid": c.pid, "name": "?", "exe": ""}
            if key in self.scored:
                score, reasons = self.scored[key]
            else:
                score, reasons = score_connection(self.dl, proc, ip, port, per_pid.get(c.pid, 0))
                self.scored[key] = (score, reasons)
            top[c.pid] = max(top.get(c.pid, 0.0), score)
            if key not in self.active:
                self.events.appendleft({
                    "id": self.next_id, "t": now, "pid": c.pid, "proc": proc["name"], "exe": proc["exe"],
                    "ip": ip, "domain": self.domain_for(ip), "port": port,
                    "proto": "TCP" if c.type == socket.SOCK_STREAM else "UDP",
                    "status": c.status, "score": score, "reasons": reasons,
                })
                self.next_id += 1
        self.active = current
        self.scored = {k: v for k, v in self.scored.items() if k in current}

        # fill in domains that finished resolving after the event was created
        events = list(self.events)
        for e in events:
            if not e["domain"]:
                d = self.rdns.get(e["ip"])
                if d:
                    e["domain"] = d

        plist = []
        for pid, n in per_pid.items():
            p = procs.get(pid)
            if p:
                plist.append({"pid": pid, "name": p["name"], "user": p["user"], "cpu": p["cpu"],
                              "mem_mb": p["mem_mb"], "conns": n, "top_score": top.get(pid, 0.0)})
        plist.sort(key=lambda x: (-x["top_score"], -x["conns"]))

        vm = psutil.virtual_memory()
        anchor = os.path.abspath(os.sep)
        try:
            du = psutil.disk_usage(anchor)
        except Exception:
            du = None
        return {
            "ts": now,
            "host": {
                "hostname": socket.gethostname(),
                "os": "%s %s" % (platform.system(), platform.release()),
                "user": os.environ.get("USERNAME") or os.environ.get("USER") or "unknown",
                "admin": is_admin(), "boot_time": psutil.boot_time(),
            },
            "metrics": {
                "cpu": psutil.cpu_percent(interval=None), "cpu_count": psutil.cpu_count() or 0,
                "mem_percent": vm.percent, "mem_used": vm.used, "mem_total": vm.total,
                "disk_percent": du.percent if du else 0, "disk_used": du.used if du else 0,
                "disk_total": du.total if du else 0,
                "proc_count": len(procs), "proc_net_count": len(per_pid),
                "conn_count": len(current), "net_down": max(down, 0.0), "net_up": max(up, 0.0),
            },
            "events": events[:120],
            "processes": plist[:20],
            "notes": notes,
            "browser_threat": self.browser_threat_snapshot(events, procs),
        }

    def loop(self):
        psutil.cpu_percent(interval=None)
        while True:
            try:
                snap = self.snapshot()
                with self.lock:
                    self.state = snap
            except Exception as exc:  # keep the agent alive
                print("collector error:", exc)
            time.sleep(2)

    # ------------------------------------------------------------- scan -----
    def scan(self):
        t0 = time.time()
        findings = []
        notes = []
        procs = self.collect_procs()
        conns = self.connections(notes)
        est = [c for c in conns if c.raddr and c.status == "ESTABLISHED" and ip_kind(c.raddr.ip) == "public"]
        pub_by_pid = {}
        for c in est:
            pub_by_pid.setdefault(c.pid, []).append(c)

        def add(sev, title, detail):
            findings.append({"severity": sev, "title": title, "detail": detail})

        for pid, p in procs.items():
            name = p["name"].lower()
            online = pid in pub_by_pid
            if in_suspicious_dir(p["exe"]):
                add("high" if online else "medium",
                    "%s runs from a temporary or downloads folder%s" % (p["name"], " and is online" if online else ""),
                    "pid %d, %s" % (pid, p["exe"]))
            if name in SYSTEM_NAMES and p["exe"] and not norm(p["exe"]).startswith(SYSROOT):
                add("high", "%s is not in the Windows folder" % p["name"], "pid %d, %s" % (pid, p["exe"]))
            if name in LOLBINS and online:
                add("medium", "%s has a connection to the internet" % p["name"],
                    "pid %d, %d connection(s)" % (pid, len(pub_by_pid[pid])))

        listening = {}
        for c in conns:
            if c.status == "LISTEN" and c.laddr:
                listening[(c.laddr.port, c.pid)] = c
        wide = []
        for (port, pid), c in listening.items():
            who = (procs.get(pid) or {}).get("name", "unknown")
            if c.laddr.ip in ("0.0.0.0", "::"):
                wide.append("%d (%s)" % (port, who))
                if port in REMOTE_ACCESS_PORTS:
                    add("medium", "%s is listening on all network interfaces" % REMOTE_ACCESS_PORTS[port],
                        "port %d, %s. Turn it off if you do not use it." % (port, who))
        if wide:
            add("info", "%d ports accept connections from the network" % len(wide), ", ".join(sorted(wide)[:14]))

        startup = startup_entries()
        for s in startup:
            if in_suspicious_dir(s["command"]):
                add("medium", "Startup entry runs from a temporary or downloads folder", "%s: %s" % (s["name"], s["command"]))
        if startup:
            add("info", "%d programs start with the computer" % len(startup), ", ".join(s["name"] for s in startup[:14]))

        hosts = custom_hosts()
        if hosts:
            add("info", "The hosts file has %d custom entries" % len(hosts), "; ".join(hosts[:6]))

        fw = firewall_state()
        if fw == "off":
            add("high", "Windows Firewall is off for at least one profile", "Turn it on in Windows Security.")
        elif fw == "on":
            add("info", "Windows Firewall is on", "All profiles report ON.")

        browsers = browser_scan(procs)
        for b in browsers["browsers"]:
            add("info", "%s (%s): %d extension(s), %s saved login(s)" % (
                b["name"], b["profile"], len(b["extensions"]),
                b["saved_logins"] if b["saved_logins"] is not None else "unknown"),
                "Only counts are read - saved password values are never opened.")
        for n in browsers["notes"]:
            add("info", "Browser data was not fully readable", n)

        if not is_admin():
            add("info", "The agent is running without administrator rights",
                "Some process paths and connections may be hidden. Run the terminal as administrator for a full scan.")
        for n in notes:
            add("info", "Limited access", n)
        if not any(f["severity"] != "info" for f in findings):
            add("info", "No suspicious programs, connections or startup entries", "Checked with the rules described on this page.")

        return {
            "seconds": time.time() - t0,
            "summary": {"processes": len(procs), "connections": len(conns), "listening": len(listening), "startup": len(startup)},
            "findings": findings,
            "browsers": browsers,
        }

    # ------------------------------------------------------ browser threats -
    def record_browser_event(self, payload):
        kind = payload.get("type")
        ts = time.time()
        if kind == "nav":
            c = classify_url(payload.get("url") or "")
            event = {"ts": ts, "type": "nav", "url": payload.get("url"), "domain": c["domain"],
                     "severity": c["severity"], "category": c["category"], "indicators": c["indicators"]}
            with self.lock:
                self.browser_status = event
        elif kind == "download":
            c = classify_download(payload.get("url") or "", payload.get("filename") or "")
            event = {"ts": ts, "type": "download", "url": payload.get("url"), "filename": c["filename"],
                     "domain": c["domain"], "severity": c["severity"], "category": c["category"], "indicators": c["indicators"]}
        else:
            return False
        with self.lock:
            self.browser_events.appendleft(event)
        return True

    def browser_threat_snapshot(self, recent_net_events, procs):
        with self.lock:
            status = dict(self.browser_status) if self.browser_status else None
            events = list(self.browser_events)[:30]
        data_theft = "not detected"
        if status and status["severity"] in ("medium", "unsafe"):
            hot = any(ev.get("score", 0) >= 0.6 and (ev.get("proc") or "").lower() in BROWSER_PROCESS_NAMES
                      for ev in recent_net_events)
            if hot:
                data_theft = "suspicious"
        running = running_browsers(procs)
        return {
            "browser": running[0]["name"] if running else None,
            "status": status,
            "data_theft": data_theft,
            "events": events,
        }
