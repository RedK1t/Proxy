from mitmproxy import http
import json
import datetime
import os

LOG_FILE = "proxy_traffic.log"

class LoggingAddon:
    def __init__(self):
        # لو الملف مش موجود، أنشئه
        if not os.path.exists(LOG_FILE):
            with open(LOG_FILE, "w") as f:
                f.write("=== MITM PROXY LOG START ===\n\n")

    def request(self, flow: http.HTTPFlow):
        log = {
            "time": str(datetime.datetime.now()),
            "type": "request",
            "method": flow.request.method,
            "url": flow.request.url,
            "headers": dict(flow.request.headers),
            "body": flow.request.text if flow.request.text else ""
        }
        self.write_log(log)

    def response(self, flow: http.HTTPFlow):
        log = {
            "time": str(datetime.datetime.now()),
            "type": "response",
            "url": flow.request.url,
            "status_code": flow.response.status_code,
            "headers": dict(flow.response.headers),
            "body": flow.response.text if flow.response.text else ""
        }
        self.write_log(log)

    def write_log(self, data):
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(data, ensure_ascii=False, indent=2))
            f.write("\n\n----------------------------\n\n")

addons = [
    LoggingAddon()
]
