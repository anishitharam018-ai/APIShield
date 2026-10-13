#!/usr/bin/env python3
"""
APIShield local agent - entry point
===================================
Reads this computer (processes, network connections, listening ports, startup
entries) and shows it in a live dashboard in your browser.

    pip install psutil numpy
    python apishield.py

Then open http://127.0.0.1:8765  (it opens by itself).

Files:
    apishield.py     this entry point (argument parsing, starts the server)
    agent.py         collects processes/connections, scoring, scans
    deep_learning.py autoencoder anomaly model + combined score
    rules.py         transparent rules and shared helpers
    system_info.py   startup entries, hosts file, firewall
    browsers.py      installed browsers, extensions, login counts, history
    threats.py       URL / download heuristics for the browser extension
    server.py        local HTTP server (127.0.0.1 only)
    dashboard.html   the dashboard page

Options: --port 8765   --no-browser   --no-dns
"""
import argparse
import sys
import threading
import webbrowser
from http.server import ThreadingHTTPServer

try:
    import psutil  # noqa: F401
except ImportError:
    print("psutil is missing. Install it with:  pip install psutil")
    sys.exit(1)

try:
    import numpy  # noqa: F401
except ImportError:
    print("numpy is missing (needed for the deep-learning model). Install it with:  pip install numpy")
    sys.exit(1)

import server
from agent_old import Agent
from rules import is_admin

HOST = "127.0.0.1"


def main():
    ap = argparse.ArgumentParser(description="APIShield local agent")
    ap.add_argument("--port", type=int, default=8765)
    ap.add_argument("--no-browser", action="store_true")
    ap.add_argument("--no-dns", action="store_true", help="do not look up website names for IP addresses")
    args = ap.parse_args()

    server.AGENT = Agent(use_dns=not args.no_dns)
    threading.Thread(target=server.AGENT.loop, daemon=True).start()

    httpd = None
    for port in range(args.port, args.port + 10):
        try:
            httpd = ThreadingHTTPServer((HOST, port), server.Handler)
            break
        except OSError:
            continue
    if httpd is None:
        print("Could not open a port. Try --port 9000")
        sys.exit(1)

    url = "http://%s:%d" % (HOST, httpd.server_address[1])
    print("APIShield agent running. Open %s" % url)
    if not is_admin():
        print("Note: not running as administrator, so some process details will be hidden.")
    print("Press Ctrl+C to stop.")
    if not args.no_browser:
        threading.Timer(1.0, lambda: webbrowser.open(url)).start()
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")


if __name__ == "__main__":
    main()
