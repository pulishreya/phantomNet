"""Tiny stdlib web dashboard: http://localhost:8080"""
import html
import json
import sqlite3
import time
from collections import Counter
from http.server import BaseHTTPRequestHandler, HTTPServer


def compute_stats(db_path):
    db = sqlite3.connect(db_path)
    rows = db.execute("SELECT ts, session, ip, type, data FROM events ORDER BY id").fetchall()
    db.close()
    cmds, creds, techs, ips = Counter(), Counter(), Counter(), Counter()
    sessions, recent, tokens, injections = set(), [], 0, 0
    for ts, sid, ip, typ, data in rows:
        d = json.loads(data or "{}")
        sessions.add(sid)
        ips[ip] += 1
        if typ == "command":
            cmds[d.get("command", "")] += 1
            for t in d.get("techniques", []):
                techs[f'{t["id"]} {t["name"]}'] += 1
            recent.append((ts, ip, d.get("command", "")))
        elif typ == "login_attempt":
            creds[f'{d.get("username")} / {d.get("password")}'] += 1
        elif typ == "honeytoken_access":
            tokens += 1
        elif typ == "prompt_injection_attempt":
            injections += 1
    return {
        "sessions": len(sessions), "events": len(rows), "commands": sum(cmds.values()),
        "honeytoken_hits": tokens, "prompt_injection_attempts": injections,
        "top_commands": cmds.most_common(10), "top_credentials": creds.most_common(10),
        "attack_techniques": techs.most_common(10), "top_ips": ips.most_common(10),
        "recent": recent[-15:][::-1],
    }


def _table(title, pairs):
    body = "".join(f"<tr><td>{html.escape(str(k))}</td><td>{v}</td></tr>" for k, v in pairs) or "<tr><td colspan=2>-</td></tr>"
    return f"<h3>{title}</h3><table>{body}</table>"


def render(st):
    recent = "".join(f"<tr><td>{time.strftime('%H:%M:%S', time.localtime(t))}</td><td>{html.escape(ip)}</td>"
                     f"<td><code>{html.escape(c)}</code></td></tr>" for t, ip, c in st["recent"])
    return f"""<!doctype html><html><head><meta charset=utf-8><meta http-equiv=refresh content=5>
<title>PhantomNet Dashboard</title><style>
body{{font-family:system-ui,sans-serif;background:#0d1117;color:#e6edf3;margin:2rem}}
h1{{color:#58a6ff}} .cards{{display:flex;gap:1rem;flex-wrap:wrap}}
.card{{background:#161b22;padding:1rem 1.5rem;border-radius:8px;border:1px solid #30363d}}
.card b{{display:block;font-size:2rem;color:#3fb950}} table{{border-collapse:collapse;width:100%;max-width:800px}}
td{{border-bottom:1px solid #30363d;padding:4px 8px}} code{{color:#f0883e}}</style></head><body>
<h1>PhantomNet &mdash; Generative Cyber-Deception</h1><div class=cards>
<div class=card><b>{st['sessions']}</b>sessions</div><div class=card><b>{st['commands']}</b>commands</div>
<div class=card><b>{st['honeytoken_hits']}</b>honeytoken hits</div>
<div class=card><b>{st['prompt_injection_attempts']}</b>prompt-injection attempts</div></div>
{_table('MITRE ATT&amp;CK techniques observed', st['attack_techniques'])}
{_table('Top credentials tried', st['top_credentials'])}
{_table('Top commands', st['top_commands'])}
{_table('Top source IPs', st['top_ips'])}
<h3>Recent commands</h3><table>{recent}</table></body></html>"""


def run_dashboard(db_path, port=8080):
    class H(BaseHTTPRequestHandler):
        def do_GET(self):
            st = compute_stats(db_path)
            if self.path == "/api/stats":
                body, ctype = json.dumps(st).encode(), "application/json"
            else:
                body, ctype = render(st).encode(), "text/html; charset=utf-8"
            self.send_response(200)
            self.send_header("Content-Type", ctype)
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):
            pass

    print(f"[PhantomNet] dashboard on http://localhost:{port}")
    HTTPServer(("0.0.0.0", port), H).serve_forever()
