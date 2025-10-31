# Honeypot Training Lab

An intentionally instrumented **ethical hacking lab** that simulates common SSH and HTTP targets without ever executing attacker-controlled input. Use it to practise reconnaissance, web exploitation workflow, log triage, and leaderboard-based scoring in a safe, offline environment.

> **Warning**
> Run this project only inside an isolated VM or lab network. It is designed for classroom capture-the-flag (CTF) style exercises, not for exposure to the public internet.

---

## Why this honeypot?

* **Multi-level training presets** – Pick from curated scenarios (Baseline Recon, Web Exploitation Basics, Hybrid LFI, and CTF Gauntlet) that align with different student skill levels and workshop goals.
* **Deterministic, safe responses** – Payloads are pattern matched; nothing is executed. Flag exposure and scoring are fully simulated.
* **Actionable telemetry** – JSONL logs, scoreboards, and analysis helpers make it easy to review what participants attempted and how many points they earned.
* **Familiar protocols** – Ships with a faux SSH banner and an HTTP service that mimics the look of an outdated Apache host.

---

## Project layout

```
.
├── honeypot/
│   ├── server.py          ← asyncio-based SSH/HTTP listener and vuln simulator
│   ├── scenarios.py       ← scenario metadata (objectives, hints, difficulty)
│   └── analyze.py         ← JSON log summariser for after-action reviews
├── scripts/
│   ├── run_honeypot.py    ← CLI wrapper for local runs (supports scenario presets)
│   ├── start_honeypot.py  ← Background launcher that writes `honeypot.pid`
│   ├── stop_honeypot.py   ← Stops the recorded PID (uses psutil when available)
│   ├── leaderboard.py     ← Pretty prints recent flag captures + scoring
│   └── web_ui.py          ← Optional dashboard (run separately if desired)
├── requirements.txt
└── tests/                 ← pytest-based verification of core behaviours
```

---

## Quick start

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python -m pytest  # optional verification
```

### Launch the honeypot

```bash
python scripts/run_honeypot.py --ssh-port 2222 --http-port 8080 --log honeypot.log --scenario web-basic --enable-vuln
```

The command above exposes:

* SSH banner on `127.0.0.1:2222` (`SSH-2.0-OpenSSH_4.3p2 Debian-3ubuntu5`)
* HTTP site + scenario briefing on `http://127.0.0.1:8080/`
* Optional vulnerable simulator at `http://127.0.0.1:8080/vuln?payload=...`

Stop the process with `Ctrl+C` or run `python scripts/stop_honeypot.py` if launched in the background.

---

## Scenario presets (ethical hacking levels)

| Scenario | Best for | Highlights | Suggested challenges |
| --- | --- | --- | --- |
| `baseline` | New analysts learning telemetry | Recon focus, banner grabbing, basic HTTP hits | `easy`, `normal` |
| `web-basic` | Intro to web exploitation | Safe flag capture, SQLi/XSS marker detection | `easy`, `normal`, `hard` |
| `hybrid-lfi` | Intermediate workshops | Directory traversal + command chaining markers | `normal`, `hard`, `expert` |
| `gauntlet` | Advanced CTF events | High-scoring RCE markers, chaining encouragement | `hard`, `expert`, `hacker` |

List all scenarios with descriptions:

```bash
python scripts/run_honeypot.py --list-scenarios
```

Each scenario updates the landing page with:

* **Objectives** – learning outcomes to brief participants.
* **Suggested tools & tips** – ideas to get unstuck without revealing solutions.
* **Recommended challenges** – multiplier presets usable via the `challenge` query parameter.

---

## Working with the vulnerable simulator

The `/vuln` endpoint is deterministic. Example payloads:

| Purpose | Example payload | Notes |
| --- | --- | --- |
| Reveal simulated flag | `show_flag`, `FLAG{demo}`, `give_me_flag` | Awards base points × challenge multiplier |
| SQL injection marker | `1 UNION SELECT password FROM users` | Logged as `sqlinjection` |
| Local file inclusion | `../../../../etc/passwd` | Logged as `lfi` |
| Reflected XSS | `<script>alert('xss')</script>` | Response echoes payload safely |
| Command injection | `; cat /etc/passwd` | Logged as `rce` (simulated) |
| Brute force spray | `password=Winter2024!` | Logged as `bruteforce` |

All detections are recorded in `honeypot.log` and appended to `honeypot_scores.jsonl` whenever a flag is awarded. Challenge multipliers (`?challenge=hard`) scale points without changing behaviour.

---

## Observability & analysis

* Tail logs live: `tail -f honeypot.log`
* Show recent scoring events: `python scripts/leaderboard.py`
* Summarise traffic: `python -m honeypot.analyze --log honeypot.log`

The analyzer now includes a scenario breakdown to help facilitators compare activity across multiple exercises.

---

## Deployment tips

1. **Isolate the VM** – disable external routing, or snapshot frequently.
2. **Use the helper scripts** – `scripts/start_honeypot.py` wraps process management and logging paths.
3. **Reset between cohorts** – truncate `honeypot.log` and `honeypot_scores.jsonl` to clear previous attempts.
4. **Extend scenarios** – add new entries to `honeypot/scenarios.py` (title, objectives, hints) and they instantly appear in the CLI and landing page.

---

## Troubleshooting checklist

* Confirm Python ≥ 3.10 and the virtualenv is activated.
* If the server starts but requests hang, ensure you are using `127.0.0.1` (not `0.0.0.0`) as the client target.
* On Windows PowerShell, wrap paths in quotes or rely on `scripts/start_honeypot.py` to handle spacing.
* Still stuck? Share the last lines of `honeypot.log` and the output of `python scripts/leaderboard.py`.

---

## Contributing

Pull requests are welcome! Run `python -m pytest` before submitting changes and document new scenarios so instructors know how to use them.
