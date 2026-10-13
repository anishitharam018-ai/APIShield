# APIShield

A local security monitor for your own PC. It reads running processes, network connections, listening ports and startup entries, then shows them in a live dashboard in your browser.

Scores come from two things: a few plain rules (program running from Downloads/Temp, fake system names, odd ports) and a small autoencoder written in NumPy. The autoencoder trains live on your own traffic, so it learns what normal looks like for your machine.

Read-only. It never changes, blocks or stops anything. It listens on 127.0.0.1 only and sends nothing anywhere.

## Run it

Needs Python 3.8+ and Windows (some checks are Windows-specific).

    pip install -r requirements.txt
    python apishield.py

Open http://127.0.0.1:8765 (it opens by itself). Run the terminal as administrator to see every process's details.

Options: `--port 8765` `--no-browser` `--no-dns`

## Files

- `apishield.py` entry point
- `agent.py` collects processes and connections, scoring, scans
- `deep_learning.py` autoencoder and combined score
- `rules.py` rule-based scoring
- `system_info.py` startup entries, hosts file, firewall
- `browsers.py` browser extensions, saved-login counts, history
- `threats.py` URL and download checks
- `server.py` local HTTP server
- `dashboard.html` the dashboard

## Limits

- Scores are heuristic. A new, unusual connection (like a cloud sync tool on an odd port) can be flagged even when it's harmless.
- The browser threat monitor needs a browser extension that isn't included yet, so that section stays empty.