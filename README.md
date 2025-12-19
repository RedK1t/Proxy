# RedKit Proxy

Lightweight mitmproxy-based proxy addons + FastAPI dashboard.

Contents
- Proxy addons:
  - [`rewrite_engine.RewriteEngine`](rewrite_engine.py) — request/response rewrite rules driven by [rewrite_rules.json](rewrite_rules.json)
  - [`proxy_logger.ProxyLogger`](proxy_logger.py) — logs requests/responses into SQLite DB `proxy_history.db`
  - [`logging_addon.LoggingAddon`](logging_addon.py) — JSON log file `proxy_traffic.log`
  - [`intercept_proxy.InterceptAddon`](intercept_proxy.py) — example header/body modifications
  - [`intercept_mode.InterceptMode`](intercept_mode.py) — interactive CLI intercept flow
  - [`history_addon.HistoryAddon`](history_addon.py) — lightweight history inserter to SQLite
- Dashboard server:
  - [`gui_api.dashboard`](gui_api.py) serves [index.html](index.html) and provides API endpoints:
    - [`gui_api.api_traffic`](gui_api.py)  GET /api/traffic
    - [`gui_api.api_request`](gui_api.py)  GET /api/request/{id}
    - [`gui_api.api_response`](gui_api.py) GET /api/response/{id}
    - [`gui_api.clear_requests`](gui_api.py) DELETE /api/clear-requests
    - [`gui_api.websocket_terminal`](gui_api.py) WebSocket /ws/terminal

Quick setup
1. Create a virtualenv and install deps:
```bash
python -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```
2. Create a virtualenv and install deps:
```bash
python [gui_api.py](http://_vscodecontentref_/23)
# or
uvicorn gui_api:app --host 0.0.0.0 --port 5050
```
3. Run mitmproxy with your addons:
```bash
mitmproxy -s [rewrite_engine.py](http://_vscodecontentref_/24) -s [proxy_logger.py](http://_vscodecontentref_/25) -s [logging_addon.py](http://_vscodecontentref_/26) -s [intercept_proxy.py](http://_vscodecontentref_/27) -s [intercept_mode.py](http://_vscodecontentref_/28) -s [history_addon.py](http://_vscodecontentref_/29)
```

4. Run mitmdumb with your addons:
```bash
mitmdump -s intercept_proxy.py -s proxy_logger.py -s intercept_mode.py -p 8080
```

5. how to run the project 
1- python3 gui_api.py
2- mitmdump -s intercept_proxy.py -s proxy_logger.py -s intercept_mode.py -p 8080
