import subprocess
from pathlib import Path
import sys

here = Path(__file__).resolve().parent.parent
log = here / 'honeypot.log'
pidfile = here / 'honeypot.pid'
script = here / 'scripts' / 'run_honeypot.py'

args = [
    sys.executable,
    '-u',
    str(script),
    '--ssh-port', '2222',
    '--http-port', '8080',
    '--log', str(log),
    '--enable-vuln'
]
proc = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, cwd=str(here))
print('Started process PID', proc.pid)
pidfile.write_text(str(proc.pid))
print('Wrote PID to', pidfile)
print('Process output will not be tailed by this script. Use Get-Content -Path "{}" -Tail 200 -Wait to follow logs.'.format(log))
