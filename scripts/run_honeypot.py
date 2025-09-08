import argparse
from pathlib import Path
import sys

# adjust sys.path to import package when running as script
here = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(here))

from honeypot.server import start_servers

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Run the local honeypot')
    parser.add_argument('--ssh-port', type=int, default=2222)
    parser.add_argument('--http-port', type=int, default=8080)
    parser.add_argument('--log', type=str, default=str(Path(here) / 'honeypot.log'))
    parser.add_argument('--enable-vuln', action='store_true', help='Enable the simulated /vuln endpoint')
    args = parser.parse_args()
    try:
        import asyncio
        asyncio.run(start_servers(args.ssh_port, args.http_port, args.log, enable_vuln=args.enable_vuln))
    except KeyboardInterrupt:
        print('Stopping')
