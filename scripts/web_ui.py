"""Minimal web UI to view the leaderboard and recent log entries.
Runs a simple HTTP server on 0.0.0.0:9000 serving a small HTML page.
"""
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from pathlib import Path
import json

here = Path(__file__).resolve().parent.parent
logfile = here / 'honeypot.log'
scorefile = here / 'honeypot_scores.jsonl'

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path.startswith('/api/leaderboard'):
            data = {'top': [], 'recent': []}
            if scorefile.exists():
                with scorefile.open('r', encoding='utf-8') as f:
                    for line in f:
                        try:
                            data['recent'].append(json.loads(line))
                        except Exception:
                            continue
                # compute top
                counts = {}
                for e in data['recent']:
                    counts[e.get('ip','-')] = counts.get(e.get('ip','-'), 0) + 1
                data['top'] = sorted([{'ip':k,'count':v} for k,v in counts.items()], key=lambda x: -x['count'])
            else:
                # fallback to logfile
                if logfile.exists():
                    with logfile.open('r', encoding='utf-8') as f:
                        for line in f:
                            try:
                                j = json.loads(line)
                            except Exception:
                                continue
                            va = j.get('vuln_attempt')
                            if va and va.get('outcome',{}).get('exposed_flag'):
                                data['recent'].append({'ts': j.get('ts'),'ip': j.get('ip'), 'payload': va.get('payload'), 'flag': va.get('outcome').get('flag'), 'points': va.get('outcome',{}).get('points',0), 'challenge': va.get('challenge','normal')})
                counts = {}
                for e in data['recent']:
                    counts[e.get('ip','-')] = counts.get(e.get('ip','-'), 0) + 1
                data['top'] = sorted([{'ip':k,'count':v} for k,v in counts.items()], key=lambda x: -x['count'])
            self.send_response(200)
            self.send_header('Content-Type','application/json')
            self.end_headers()
            self.wfile.write(json.dumps(data).encode('utf-8'))
            return
        if self.path == '/' or self.path.startswith('/index'):
            html = '''<!doctype html>
<html>
<head>
    <meta charset="utf-8">
    <title>Honeypot Leaderboard</title>
    <style>
        body{font-family:Segoe UI,Roboto,Arial,sans-serif;margin:24px;background:#f7f9fc;color:#222}
        .container{max-width:980px;margin:0 auto;background:#fff;padding:20px;border-radius:8px;box-shadow:0 4px 18px rgba(0,0,0,0.06)}
        h1{margin-top:0;color:#0b3d91}
        .top-ips{display:flex;gap:12px;flex-wrap:wrap}
        .card{background:#f3f6fb;padding:12px;border-radius:6px}
        table{width:100%;border-collapse:collapse;margin-top:8px}
        th,td{padding:8px;border-bottom:1px solid #e6eef6;text-align:left}
        pre{background:#0f1720;color:#e6fffa;padding:12px;border-radius:6px;overflow:auto}
        .controls{margin-top:8px}
        .muted{color:#5b6b7a;font-size:0.9em}
    </style>
</head>
<body>
    <div class="container">
        <h1>Honeypot Leaderboard</h1>
        <div class="controls">
            <button onclick="load()">Refresh</button>
            <span class="muted">Auto-refresh every 3s</span>
        </div>
        <section>
            <h2>Top IPs</h2>
            <div id="top" class="top-ips"></div>
        </section>
            <section style="margin-top:16px">
            <h2>Recent flag captures</h2>
            <table id="recent_table">
                <thead><tr><th>Time (UTC)</th><th>IP</th><th>Challenge</th><th>Points</th><th>Payload</th><th>Flag</th></tr></thead>
                <tbody id="recent"></tbody>
            </table>
        </section>
        <p class="muted">This UI reads from the honeypot score/log files. For production use secure this page.</p>
    </div>
    <script>
        function td(text){const e=document.createElement('td');e.textContent=text;return e}
        async function load(){
            try{
                let r = await fetch('/api/leaderboard');
                let j = await r.json();
                const top = document.getElementById('top'); top.innerHTML='';
                if(j.top.length===0) top.innerHTML='<div class="card">No captures yet</div>';
                else j.top.forEach(x=>{const d=document.createElement('div');d.className='card';d.textContent=`${x.ip}: ${x.count}`;top.appendChild(d)});
                const tbody = document.getElementById('recent'); tbody.innerHTML='';
                j.recent.slice().reverse().forEach(ev=>{ // newest first
                    const tr=document.createElement('tr');
                    tr.appendChild(td(ev.ts || ev.time || ''));
                    tr.appendChild(td(ev.ip||''));
                    tr.appendChild(td(ev.challenge||'normal'));
                    tr.appendChild(td(ev.points||0));
                    tr.appendChild(td(ev.payload||''));
                    tr.appendChild(td(ev.flag||''));
                    tbody.appendChild(tr);
                });
            }catch(e){console.error(e);}
        }
        load(); setInterval(load,3000);
    </script>
</body>
</html>'''
            self.send_response(200)
            self.send_header('Content-Type','text/html; charset=utf-8')
            self.send_header('Content-Length', str(len(html.encode('utf-8'))))
            self.end_headers()
            self.wfile.write(html.encode('utf-8'))
            return
        self.send_response(404)
        self.end_headers()

if __name__ == '__main__':
    addr = ('0.0.0.0', 9000)
    print('Starting web UI on http://%s:%s' % addr)
    httpd = ThreadingHTTPServer(addr, Handler)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print('Stopping web UI')
    finally:
        httpd.server_close()
