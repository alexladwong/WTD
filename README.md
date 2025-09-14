# WTD


Use it: click Start Server, then Open in Browser (or hit http://127.0.0.1:8000/). Requests will stream into the table; select a row to Block or run ARP MAC Lookup (LAN only).

Below is a drop-in replacement that:

Auto-starts the Flask server when the window opens.

Auto-opens your browser to the page.

Self-pings the server to generate the first log row.

Adds a simple console panel so you can see status/errors.

Keeps the Python-3.9 type hints and the dark-theme fix.

pip install flask geoip2 requests scapy
python tk_guard.py
