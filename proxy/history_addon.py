from mitmproxy import http
import sqlite3, time

DB = "proxy_history.db"

# إنشاء الجدول لو مش موجود
conn = sqlite3.connect(DB)
conn.execute("""CREATE TABLE IF NOT EXISTS history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    method TEXT,
    url TEXT,
    status_code INTEGER,
    request_headers TEXT,
    request_body TEXT,
    response_headers TEXT,
    response_body TEXT,
    time TEXT
)""")
conn.close()

class HistoryAddon:
    def response(self, flow: http.HTTPFlow):
        conn = sqlite3.connect(DB)
        conn.execute(
            """INSERT INTO history
            (method, url, status_code, request_headers, request_body,
             response_headers, response_body, time)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                flow.request.method,
                flow.request.url,
                flow.response.status_code,
                str(flow.request.headers),
                flow.request.text,
                str(flow.response.headers),
                flow.response.text,
                time.strftime("%Y-%m-%d %H:%M:%S")
            )
        )
        conn.commit()
        conn.close()

addons = [HistoryAddon()]
