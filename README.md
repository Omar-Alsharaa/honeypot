# Custom Honeypot

This project implements a simple, local honeypot that simulates vulnerable SSH and HTTP services for lab/learning purposes only.

WARNING: Run this only in an isolated lab or VM, not on a public-facing host.

Files:


Vulnerable simulation
---------------------

This honeypot can simulate a safe, training-only vulnerable endpoint at `/vuln` when the operator enables it. It never executes attacker input. Instead it pattern-matches requests and returns deterministic outcomes (for example, a simulated flag).

Usage example (enable vuln):

```powershell
python -u "d:\New folder\scripts\run_honeypot.py" --ssh-port 2222 --http-port 8080 --log "d:\New folder\honeypot.log" --enable-vuln &
```

Then an attacker (or student) can probe `/vuln`:

```powershell
# simulated attack that requests the flag
python -c "import requests; print(requests.get('http://127.0.0.1:8080/vuln?payload=show_flag').text)"
```

The endpoint recognizes simple markers such as `show_flag`, `FLAG`, `give_me_flag`, or basic SQL-like patterns and returns a simulated outcome. This is designed for training and scoring only — it does not execute arbitrary input.

Start / Stop helpers and leaderboard
-----------------------------------

There are helper scripts in `scripts/`:

- `start_honeypot.py` — starts the honeypot and writes `honeypot.pid`.
- `stop_honeypot.py` — stops the process recorded in `honeypot.pid` (uses `psutil` if available).
- `leaderboard.py` — prints a summary of captured flags from `honeypot_scores.jsonl`.

Usage (PowerShell):

```powershell
# start
python "d:\New folder\scripts\start_honeypot.py"


Hints for people who find it hard to start
-----------------------------------------

If this is your first time running the project, here are a few quick tips to get you going.

- Run in the foreground first so you can see errors:

```powershell
python -u "d:\New folder\scripts\run_honeypot.py" --ssh-port 2222 --http-port 8080 --log "d:\New folder\honeypot.log" --enable-vuln
# (Press Ctrl+C to stop)
```

- If the server appears to start but your test times out, check these in order:
	- Use `Invoke-WebRequest` or open http://127.0.0.1:8080/vuln?payload=show_flag in your browser (use 127.0.0.1 not 0.0.0.0).
	- Tail the log to see incoming requests and errors:

```powershell
Get-Content -Path "d:\New folder\honeypot.log" -Tail 200 -Wait
```

	- Confirm the process and port are active (replace PID if needed):

```powershell
# simulate an attacker getting the flag
Invoke-WebRequest -Uri 'http://127.0.0.1:8080/vuln?payload=show_flag' -UseBasicParsing | Select-Object -ExpandProperty Content

# view leaderboard
python "d:\New folder\scripts\leaderboard.py"

- If Start-Process fails because of spaces in paths, use the helper which quotes paths for you:

```powershell

# stop

- Web UI troubleshooting:
	- The UI runs on port 9000. Use http://127.0.0.1:9000.
	- If you see a blank page, try reloading or check the web UI process and logs.

If these hints don't fix the issue, paste the exact error text you see (or the last 20 lines of `honeypot.log`) and I will help you debug the specific problem.
python "d:\New folder\scripts\stop_honeypot.py"
```
