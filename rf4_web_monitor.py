"""手机网页查看 RF4 浮窗事件

在本机启动 HTTP 服务，手机连同一 WiFi 后访问 http://<电脑IP>:8088 即可查看实时来鱼/搏鱼/遥测事件。
按时序排列，可上下翻阅历史。
"""
import json
import socket
import sqlite3
import subprocess
import sys
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path

THIS_DIR = Path(__file__).resolve().parent
DEFAULT_DB = THIS_DIR / "rf4_overlay_events.sqlite3"
PORT = 8088


def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def open_firewall():
    if sys.platform != "win32":
        return
    name = f"RF4 Web Monitor {PORT}"
    try:
        subprocess.run(
            ["netsh", "advfirewall", "firewall", "show", "rule", f"name={name}"],
            capture_output=True, timeout=5,
        )
        return
    except Exception:
        pass
    try:
        subprocess.run(
            ["netsh", "advfirewall", "firewall", "add", "rule",
             f"name={name}", "dir=in", "action=allow", "protocol=tcp",
             f"localport={PORT}"],
            capture_output=True, timeout=5,
        )
        print(f"  已添加防火墙规则: {name}")
    except Exception:
        print(f"  防火墙规则添加失败，请手动放行 TCP {PORT} 端口")


HTML_PAGE = r"""<!DOCTYPE html>
<html lang="zh">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,user-scalable=no">
<title>RF4 浮窗</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{background:#1a1a2e;color:#eee;font-family:system-ui,sans-serif;padding:8px 8px 40px 8px}
.event{background:#16213e;border-radius:8px;padding:10px 12px;margin-bottom:6px;line-height:1.4;font-size:14px;border-left:3px solid #0f3460;word-break:break-all}
.event.fish{border-left-color:#e94560}
.event.telemetry{border-left-color:#533483;font-size:13px;color:#bbb}
.event.chat{border-left-color:#0f3460;color:#aaa;font-size:13px}
.event.generic{border-left-color:#533483}
#status{position:fixed;bottom:0;left:0;right:0;background:#0f3460;color:#aaa;text-align:center;padding:6px;font-size:12px}
</style>
</head>
<body>
<div id="events"></div>
<div id="status">连接中...</div>
<script>
let lastId = 0;
let eventsEl = document.getElementById('events');
let statusEl = document.getElementById('status');
let firstLoad = true;

function poll() {
    fetch('/events?since=' + lastId)
    .then(r => r.json())
    .then(data => {
        statusEl.textContent = '在线 | ' + new Date().toLocaleTimeString('zh-CN', {hour12: false});
        let newCount = 0;
        data.events.forEach(e => {
            if (e.id <= lastId) return;
            lastId = e.id;
            newCount++;
            let div = document.createElement('div');
            let evName = '', text = '', gear = '';
            try {
                let p = JSON.parse(e.payload);
                evName = p.event || '';
                text = p.text || '';
                gear = p.gear_slot || '';
            } catch(err) {}
            if (evName === 'reset') return;
            let cls = 'event';
            if (evName.startsWith('fish_')) cls += ' fish';
            else if (evName === 'telemetry') cls += ' telemetry';
            else if (evName === 'chat') cls += ' chat';
            else cls += ' generic';
            div.className = cls;
            let ts = new Date(e.ts * 1000).toLocaleTimeString('zh-CN', {hour12: false, hour:'2-digit', minute:'2-digit', second:'2-digit'});
            let display = gear ? gear + ' ' + text : text;
            div.textContent = ts + ' ' + (display || evName);
            eventsEl.appendChild(div);
        });
        while (eventsEl.children.length > 500) eventsEl.removeChild(eventsEl.firstChild);
        if (newCount > 0) window.scrollTo(0, document.body.scrollHeight);
    })
    .catch(() => { statusEl.textContent = '断线，重连中...'; })
    .finally(() => { setTimeout(poll, 1000); });
}
poll();
</script>
</body>
</html>"""


class Handler(BaseHTTPRequestHandler):
    db_path = str(DEFAULT_DB)

    def do_GET(self):
        if self.path == "/" or self.path == "/index.html":
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(HTML_PAGE.encode())
        elif self.path.startswith("/events"):
            since = 0
            if "?" in self.path:
                for part in self.path.split("?", 1)[1].split("&"):
                    if part.startswith("since="):
                        try: since = int(part.split("=", 1)[1])
                        except ValueError: pass
            rows = []
            try:
                con = sqlite3.connect(self.db_path, timeout=1.0)
                try:
                    con.execute("PRAGMA busy_timeout = 1000")
                    rows = con.execute(
                        "SELECT id, ts, event_type, payload FROM overlay_events WHERE id > ? ORDER BY id ASC LIMIT 200",
                        (since,),
                    ).fetchall()
                finally:
                    con.close()
            except Exception:
                pass
            result = [{"id": r[0], "ts": r[1], "event": r[2], "payload": r[3]} for r in rows]
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(json.dumps({"events": result}, ensure_ascii=False).encode())
        else:
            self.send_error(404)

    def log_message(self, format, *args):
        pass


def main():
    db = sys.argv[1] if len(sys.argv) > 1 else str(DEFAULT_DB)
    Handler.db_path = db
    ip = get_local_ip()
    open_firewall()
    server = HTTPServer(("0.0.0.0", PORT), Handler)
    print()
    print("========================================")
    print("  RF4 浮窗网页查看器")
    print("========================================")
    print(f"  电脑访问: http://127.0.0.1:{PORT}")
    print(f"  手机访问: http://{ip}:{PORT}")
    print(f"  数据库:   {db}")
    print("========================================")
    print("  按 Ctrl+C 停止")
    print()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n已停止")


if __name__ == "__main__":
    main()
