import json
from collections import Counter, defaultdict
from pathlib import Path
import argparse


def analyze(logfile: str, top: int = 10):
    p = Path(logfile)
    if not p.exists():
        print('Log file not found:', logfile)
        return
    ips = Counter()
    proto_count = Counter()
    samples = defaultdict(list)
    with p.open('r', encoding='utf-8') as f:
        for line in f:
            try:
                j = json.loads(line)
            except Exception:
                continue
            ips[j.get('ip','-')] += 1
            proto_count[j.get('proto','-')] += 1
            samples[j.get('ip','-')].append(j)
    print('Top IPs:')
    for ip, cnt in ips.most_common(top):
        print(f'  {ip}: {cnt}')
    print('\nBy protocol:')
    for p_name, cnt in proto_count.items():
        print(f'  {p_name}: {cnt}')
    print('\nSample events (one per top IP):')
    for ip, _ in ips.most_common(5):
        print('\n==', ip)
        for ev in samples[ip][:3]:
            print(' ', json.dumps(ev, indent=2, ensure_ascii=False))


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--log', required=True)
    args = parser.parse_args()
    analyze(args.log)
