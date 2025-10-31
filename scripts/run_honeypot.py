import argparse
from pathlib import Path
import sys

# adjust sys.path to import package when running as script
here = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(here))

from honeypot.server import start_servers
from honeypot.scenarios import list_scenarios

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Run the local honeypot')
    parser.add_argument('--ssh-port', type=int, default=2222)
    parser.add_argument('--http-port', type=int, default=8080)
    parser.add_argument('--log', type=str, default=str(Path(here) / 'honeypot.log'))
    parser.add_argument('--enable-vuln', action='store_true', help='Enable the simulated /vuln endpoint')
    parser.add_argument('--scenario', default='baseline', help='Scenario preset to use for the run')
    parser.add_argument('--list-scenarios', action='store_true', help='List available scenario presets and exit')
    args = parser.parse_args()

    if args.list_scenarios:
        for scenario in list_scenarios():
            print(f"{scenario.name}: {scenario.title}\n  {scenario.description}\n  Recommended challenges: {', '.join(scenario.recommended_challenges)}\n")
        raise SystemExit(0)
    try:
        import asyncio
        asyncio.run(
            start_servers(
                args.ssh_port,
                args.http_port,
                args.log,
                enable_vuln=args.enable_vuln,
                scenario=args.scenario,
            )
        )
    except KeyboardInterrupt:
        print('Stopping')
