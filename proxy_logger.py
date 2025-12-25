from mitmproxy import http
import sqlite3
import datetime
import json
import os

DB_FILE = "proxy_history.db"

def init_db():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            method TEXT,
            url TEXT,
            status_code INTEGER,
            request_headers TEXT,
            request_body TEXT,
            response_headers TEXT,
            response_body TEXT,
            time TEXT
        )
    """)
    conn.commit()
    conn.close()

class ProxyLogger:
    def __init__(self):
        init_db()

    def request(self, flow: http.HTTPFlow):
        self.method = flow.request.method
        self.url = flow.request.url
        self.req_headers = json.dumps(dict(flow.request.headers), ensure_ascii=False)
        self.req_body = flow.request.text if flow.request.text else ""

    def response(self, flow: http.HTTPFlow):
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()

        c.execute("""
            INSERT INTO history (
                method, url, status_code, 
                request_headers, request_body,
                response_headers, response_body, time
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            self.method,
            self.url,
            flow.response.status_code,
            self.req_headers,
            self.req_body,
            json.dumps(dict(flow.response.headers), ensure_ascii=False),
            flow.response.text if flow.response.text else "",
            str(datetime.datetime.now())
        ))

        conn.commit()
        conn.close()


addons = [
    ProxyLogger()
]
