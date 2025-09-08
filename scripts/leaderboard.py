import json
from pathlib import Path
from collections import Counter

here = Path(__file__).resolve().parent.parent
scorefile = here / 'honeypot_scores.jsonl'
logfile = here / 'honeypot.log'

ips = Counter()
entries = []

if scorefile.exists():
    with scorefile.open('r', encoding='utf-8') as f:
        for line in f:
            try:
                j = json.loads(line)
            except Exception:
                continue
            ips[j.get('ip','-')] += 1
            entries.append(j)
else:
    # fallback: scan the main log for vuln_attempt records
    if not logfile.exists():
        print('No scores yet and no log available')
        raise SystemExit(0)
    with logfile.open('r', encoding='utf-8') as f:
        for line in f:
            try:
                j = json.loads(line)
            except Exception:
                continue
            va = j.get('vuln_attempt')
            if not va:
                continue
            outcome = va.get('outcome', {})
            if outcome.get('exposed_flag'):
                entry = {
                    'ts': j.get('ts'),
                    'ip': j.get('ip'),
                    'payload': va.get('payload'),
                    'flag': outcome.get('flag'),
                    'points': va.get('outcome', {}).get('points', 0),
                    'challenge': va.get('challenge', 'normal')
                }
                ips[entry.get('ip','-')] += 1
                entries.append(entry)

print('Top IPs by flags obtained:')
for ip, cnt in ips.most_common(10):
    print(f' {ip}: {cnt}')

print('\nRecent flag captures:')
for ev in entries[-10:]:
    print(f"{ev.get('ts')}  {ev.get('ip')}  {ev.get('challenge')}  +{ev.get('points')}  {ev.get('flag')}  payload={ev.get('payload')}")
