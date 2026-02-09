import json
from mitmproxy import http

RULE_FILE = "rewrite_rules.json"

class RewriteEngine:
    def __init__(self):
        with open(RULE_FILE, "r") as f:
            self.rules = json.load(f)

    def request(self, flow: http.HTTPFlow):
        url = flow.request.url

        for rule in self.rules:
            if rule["match"] in url:

                # -------- Replace URL ----------
                if "replace_url" in rule:
                    print(f"[Rewrite] URL changed → {rule['replace_url']}")
                    flow.request.url = rule["replace_url"]

                # -------- Replace Header ----------
                if "replace_header" in rule:
                    for k, v in rule["replace_header"].items():
                        print(f"[Rewrite] Header {k} → {v}")
                        flow.request.headers[k] = v

                # -------- Replace Body ----------
                if "replace_body" in rule:
                    print("[Rewrite] Body replaced")
                    flow.request.text = rule["replace_body"]

    def response(self, flow: http.HTTPFlow):
        url = flow.request.url

        for rule in self.rules:
            if rule["match"] in url:

                # -------- Replace Response Body ----------
                if "replace_response_body" in rule:
                    print("[Rewrite] Response Body replaced")
                    flow.response.text = rule["replace_response_body"]

addons = [
    RewriteEngine()
]
