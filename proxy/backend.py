"""
RedKit Proxy - WebSocket-Only Backend with GUI Interceptor
Uses SQLite for IPC between FastAPI and mitmproxy addon
"""

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
from typing import List, Dict, Any
from concurrent.futures import ThreadPoolExecutor
import sqlite3
import uvicorn
import json
import asyncio
import requests
import urllib3
import time
import re
import datetime
import uuid
import threading

# Mitmproxy imports
try:
    from mitmproxy import http
    MITMPROXY_AVAILABLE = True
except ImportError:
    MITMPROXY_AVAILABLE = False
    print("[WARNING] mitmproxy not available - running in API-only mode")

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Database
DB_FILE = "proxy_history.db"

def init_database():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    
    # History table
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
    
    # Intercept queue table for IPC
    c.execute("""
        CREATE TABLE IF NOT EXISTS intercept_queue (
            id TEXT PRIMARY KEY,
            method TEXT,
            url TEXT,
            host TEXT,
            headers TEXT,
            body TEXT,
            raw_request TEXT,
            status TEXT DEFAULT 'pending',
            notified INTEGER DEFAULT 0,
            modified_method TEXT,
            modified_url TEXT,
            modified_headers TEXT,
            modified_body TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    
    # Migration: Add notified column if it doesn't exist
    try:
        c.execute("SELECT notified FROM intercept_queue LIMIT 1")
    except sqlite3.OperationalError:
        # Column doesn't exist, add it
        c.execute("ALTER TABLE intercept_queue ADD COLUMN notified INTEGER DEFAULT 0")
        print("[DB Migration] Added 'notified' column to intercept_queue table")
    
    # Migration: Add response interception columns if they don't exist
    try:
        c.execute("SELECT response_headers FROM intercept_queue LIMIT 1")
    except sqlite3.OperationalError:
        c.execute("ALTER TABLE intercept_queue ADD COLUMN response_headers TEXT")
        c.execute("ALTER TABLE intercept_queue ADD COLUMN response_body TEXT")
        c.execute("ALTER TABLE intercept_queue ADD COLUMN raw_response TEXT")
        c.execute("ALTER TABLE intercept_queue ADD COLUMN status_code INTEGER")
        c.execute("ALTER TABLE intercept_queue ADD COLUMN modified_response_headers TEXT")
        c.execute("ALTER TABLE intercept_queue ADD COLUMN modified_response_body TEXT")
        c.execute("ALTER TABLE intercept_queue ADD COLUMN item_type TEXT DEFAULT 'request'")
        c.execute("ALTER TABLE intercept_queue ADD COLUMN parent_id TEXT")
        print("[DB Migration] Added response interception columns to intercept_queue table")
    
    # Intercept settings table for IPC
    c.execute("""
        CREATE TABLE IF NOT EXISTS intercept_settings (
            key TEXT PRIMARY KEY,
            value TEXT
        )
    """)
    
    # Initialize intercept settings
    c.execute("INSERT OR REPLACE INTO intercept_settings (key, value) VALUES ('enabled', 'false')")
    c.execute("INSERT OR REPLACE INTO intercept_settings (key, value) VALUES ('response_enabled', 'false')")
    
    conn.commit()
    conn.close()

init_database()

# Helper functions for IPC
def is_intercept_enabled():
    """Check if interception is enabled via database"""
    try:
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute("SELECT value FROM intercept_settings WHERE key = 'enabled'")
        row = c.fetchone()
        conn.close()
        return row and row[0] == 'true'
    except:
        return False

def set_intercept_enabled(enabled: bool):
    """Set interception enabled status"""
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("INSERT OR REPLACE INTO intercept_settings (key, value) VALUES ('enabled', ?)", 
              ('true' if enabled else 'false',))
    conn.commit()
    conn.close()

def is_response_intercept_enabled():
    """Check if response interception is enabled via database"""
    try:
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute("SELECT value FROM intercept_settings WHERE key = 'response_enabled'")
        row = c.fetchone()
        conn.close()
        return row and row[0] == 'true'
    except:
        return False

def set_response_intercept_enabled(enabled: bool):
    """Set response interception enabled status"""
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("INSERT OR REPLACE INTO intercept_settings (key, value) VALUES ('response_enabled', ?)", 
              ('true' if enabled else 'false',))
    conn.commit()
    conn.close()

def add_to_intercept_queue(req_id, method, url, host, headers, body, raw_request):
    """Add request to intercept queue"""
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("""
        INSERT INTO intercept_queue (id, method, url, host, headers, body, raw_request, status, item_type)
        VALUES (?, ?, ?, ?, ?, ?, ?, 'pending', 'request')
    """, (req_id, method, url, host, headers, body, raw_request))
    conn.commit()
    conn.close()

def add_response_to_queue(resp_id, parent_id, method, url, host, status_code, response_headers, response_body, raw_response):
    """Add response to intercept queue"""
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("""
        INSERT INTO intercept_queue (id, parent_id, method, url, host, status_code, response_headers, response_body, 
                                     raw_response, status, item_type)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', 'response')
    """, (resp_id, parent_id, method, url, host, status_code, response_headers, response_body, raw_response))
    conn.commit()
    conn.close()

def get_intercept_status(req_id):
    """Get the status of an intercepted request"""
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT status, modified_method, modified_url, modified_headers, modified_body, item_type, modified_response_headers, modified_response_body FROM intercept_queue WHERE id = ?", (req_id,))
    row = c.fetchone()
    conn.close()
    return row

def get_response_intercept_status(resp_id):
    """Get the status of an intercepted response"""
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT status, modified_response_headers, modified_response_body FROM intercept_queue WHERE id = ?", (resp_id,))
    row = c.fetchone()
    conn.close()
    return row

def update_intercept_status(req_id, status, modified=None, response_modified=None):
    """Update intercept status (called from WebSocket)"""
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    if modified:
        c.execute("""
            UPDATE intercept_queue 
            SET status = ?, modified_method = ?, modified_url = ?, modified_headers = ?, modified_body = ?
            WHERE id = ?
        """, (status, modified.get('method'), modified.get('url'), modified.get('headers'), modified.get('body'), req_id))
    elif response_modified:
        c.execute("""
            UPDATE intercept_queue 
            SET status = ?, modified_response_headers = ?, modified_response_body = ?
            WHERE id = ?
        """, (status, response_modified.get('headers'), response_modified.get('body'), req_id))
    else:
        c.execute("UPDATE intercept_queue SET status = ? WHERE id = ?", (status, req_id))
    conn.commit()
    conn.close()

def remove_from_intercept_queue(req_id):
    """Remove request from queue"""
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("DELETE FROM intercept_queue WHERE id = ?", (req_id,))
    conn.commit()
    conn.close()

def get_pending_intercepts():
    """Get all pending intercepts that haven't been notified yet"""
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("""
        SELECT id, method, url, host, headers, body, raw_request, item_type, status_code, 
               response_headers, response_body, raw_response, parent_id 
        FROM intercept_queue 
        WHERE status = 'pending' AND notified = 0 
        ORDER BY created_at
    """)
    rows = c.fetchall()
    conn.close()
    return rows

def mark_intercept_notified(req_id):
    """Mark an intercept as notified"""
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("UPDATE intercept_queue SET notified = 1 WHERE id = ?", (req_id,))
    conn.commit()
    conn.close()

def clear_intercept_queue():
    """Clear all intercepts"""
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("DELETE FROM intercept_queue")
    conn.commit()
    conn.close()

def get_all_pending_intercepts():
    """Get all pending intercepts"""
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT id, method, url, host, headers, body FROM intercept_queue WHERE status = 'pending'")
    rows = c.fetchall()
    conn.close()
    return rows

def forward_all_pending_intercepts():
    """Forward all pending intercepts"""
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("UPDATE intercept_queue SET status = 'forward' WHERE status = 'pending'")
    conn.commit()
    conn.close()

# Payload Generator
class PayloadGenerator:
    @staticmethod
    def common_passwords():
        return ["123456", "password", "12345678", "qwerty", "admin", "root", "toor", "guest"]
    
    @staticmethod
    def common_usernames():
        return ["admin", "administrator", "root", "user", "test", "guest"]
    
    @staticmethod
    def sqli_payloads():
        return ["'", "' OR '1'='1", "' OR 1=1--", "admin'--", "1' ORDER BY 1--"]
    
    @staticmethod
    def xss_payloads():
        return ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>"]
    
    @staticmethod
    def path_traversal_payloads():
        return ["../", "../../", "../../../etc/passwd"]
    
    @staticmethod
    def numbers(start, end, step=1):
        return [str(i) for i in range(start, end + 1, step)]

# Intruder
class Intruder:
    POSITION_MARKER = "§"
    
    def __init__(self, threads=10):
        self.threads = threads
        self.results = []
        self.session = requests.Session()
        self.stop_flag = False
    
    def find_positions(self, template):
        pattern = re.compile(f'{self.POSITION_MARKER}(.*?){self.POSITION_MARKER}')
        return [(m.start(), m.end(), m.group(1)) for m in pattern.finditer(template)]
    
    def replace_position(self, template, pos_idx, payload):
        positions = self.find_positions(template)
        if pos_idx >= len(positions):
            return template
        result = template
        for i, (start, end, _) in enumerate(reversed(positions)):
            actual = len(positions) - 1 - i
            if actual == pos_idx:
                result = result[:start] + payload + result[end:]
            else:
                result = result[:start] + positions[actual][2] + result[end:]
        return result
    
    def replace_all_positions(self, template, payload):
        pattern = re.compile(f'{self.POSITION_MARKER}(.*?){self.POSITION_MARKER}')
        return pattern.sub(payload, template)
    
    def attack_sniper(self, template, payloads):
        self.results = []
        self.stop_flag = False
        all_text = f"{template['url']}\n{json.dumps(template.get('headers', {}))}\n{template.get('body', '')}"
        positions = self.find_positions(all_text)
        
        def send_request(req_data, payload, pos):
            start = time.time()
            try:
                resp = self.session.request(
                    method=req_data['method'].upper(),
                    url=req_data['url'],
                    headers=req_data.get('headers', {}),
                    data=req_data.get('body') if req_data.get('body') else None,
                    timeout=req_data.get('timeout', 30),
                    verify=False
                )
                return {
                    'payload': payload, 'position': pos,
                    'status_code': resp.status_code,
                    'length': len(resp.content),
                    'time': round(time.time() - start, 3),
                    'error': None
                }
            except Exception as e:
                return {'payload': payload, 'position': pos, 'status_code': 0, 'length': 0, 'time': time.time() - start, 'error': str(e)}
        
        with ThreadPoolExecutor(max_workers=self.threads) as exe:
            futures = []
            if positions:
                for pos_idx in range(len(positions)):
                    for payload in payloads:
                        if self.stop_flag:
                            break
                        new_url = self.replace_position(template['url'], pos_idx, payload)
                        new_headers = {k: self.replace_position(v, pos_idx, payload) for k, v in template.get('headers', {}).items()}
                        new_body = self.replace_position(template.get('body', ''), pos_idx, payload)
                        req = {'method': template['method'], 'url': new_url, 'headers': new_headers, 'body': new_body, 'timeout': template.get('timeout', 30)}
                        futures.append(exe.submit(send_request, req, payload, pos_idx))
            else:
                for payload in payloads:
                    if self.stop_flag:
                        break
                    futures.append(exe.submit(send_request, template, payload, 0))
            
            for f in futures:
                if not self.stop_flag:
                    self.results.append(f.result())
        
        return self.results
    
    def attack_battering_ram(self, template, payloads):
        self.results = []
        self.stop_flag = False
        
        def send_request(req_data, payload):
            start = time.time()
            try:
                resp = self.session.request(
                    method=req_data['method'].upper(),
                    url=req_data['url'],
                    headers=req_data.get('headers', {}),
                    data=req_data.get('body') if req_data.get('body') else None,
                    timeout=req_data.get('timeout', 30),
                    verify=False
                )
                return {'payload': payload, 'position': -1, 'status_code': resp.status_code, 'length': len(resp.content), 'time': round(time.time() - start, 3), 'error': None}
            except Exception as e:
                return {'payload': payload, 'position': -1, 'status_code': 0, 'length': 0, 'time': time.time() - start, 'error': str(e)}
        
        with ThreadPoolExecutor(max_workers=self.threads) as exe:
            futures = []
            for payload in payloads:
                if self.stop_flag:
                    break
                new_url = self.replace_all_positions(template['url'], payload)
                new_headers = {k: self.replace_all_positions(v, payload) for k, v in template.get('headers', {}).items()}
                new_body = self.replace_all_positions(template.get('body', ''), payload)
                req = {'method': template['method'], 'url': new_url, 'headers': new_headers, 'body': new_body, 'timeout': template.get('timeout', 30)}
                futures.append(exe.submit(send_request, req, payload))
            
            for f in futures:
                if not self.stop_flag:
                    self.results.append(f.result())
        
        return self.results
    
    def stop(self):
        self.stop_flag = True

# Global state for WebSocket broadcasting
active_websockets = []
intercept_enabled = False

# FastAPI App
app = FastAPI(title="RedKit Proxy WebSocket", version="4.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])

intruder_instance = Intruder(threads=10)

# Connection Manager
class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []
    
    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)
        active_websockets.append(websocket)
    
    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
        if websocket in active_websockets:
            active_websockets.remove(websocket)
    
    async def send_personal_message(self, message: dict, websocket: WebSocket):
        try:
            await websocket.send_json(message)
        except:
            pass
    
    async def broadcast(self, message: dict):
        for connection in list(self.active_connections):
            try:
                await connection.send_json(message)
            except:
                pass

manager = ConnectionManager()

# Database helpers
def save_to_history(method, url, status_code, req_headers, req_body, resp_headers, resp_body):
    try:
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute("INSERT INTO history (method, url, status_code, request_headers, request_body, response_headers, response_body, time) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                 (method, url, status_code, req_headers, req_body, resp_headers, resp_body, str(datetime.datetime.now())))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"Error saving to history: {e}")

# Track notified requests in memory to avoid duplicates within the same session
notified_requests = set()

# Background task to poll for new intercepts and notify clients
async def poll_intercepts():
    """Background task to check for new intercepts and notify WebSocket clients"""
    while True:
        try:
            await asyncio.sleep(0.3)
            
            # Check for pending intercepts that haven't been notified
            pending = get_pending_intercepts()
            
            # Notify all connected clients about new pending intercepts
            for row in pending:
                req_id, method, url, host, headers, body, raw_request, item_type, status_code, response_headers, response_body, raw_response, parent_id = row
                
                # Skip if already notified in this session
                if req_id in notified_requests:
                    continue
                
                # Mark as notified in database and memory
                mark_intercept_notified(req_id)
                notified_requests.add(req_id)
                
                # Notify all connected WebSocket clients
                for ws in list(active_websockets):
                    try:
                        if item_type == 'response':
                            await manager.send_personal_message({
                                'type': 'intercepted_response',
                                'id': req_id,
                                'parent_id': parent_id,
                                'method': method,
                                'url': url,
                                'host': host,
                                'status_code': status_code,
                                'response_headers': response_headers,
                                'response_body': response_body,
                                'raw_response': raw_response
                            }, ws)
                        else:
                            await manager.send_personal_message({
                                'type': 'intercepted_request',
                                'id': req_id,
                                'method': method,
                                'url': url,
                                'host': host,
                                'headers': headers,
                                'body': body,
                                'raw': raw_request
                            }, ws)
                    except:
                        pass
                        
        except Exception as e:
            print(f"Error in poll_intercepts: {e}")

# Start background task
@app.on_event("startup")
async def startup_event():
    asyncio.create_task(poll_intercepts())

# Main WebSocket endpoint
@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    
    try:
        while True:
            data = await websocket.receive_json()
            action = data.get('action')
            
            # INTERCEPTOR ACTIONS
            if action == 'toggle_intercept':
                global intercept_enabled
                intercept_enabled = data.get('enabled', False)
                set_intercept_enabled(intercept_enabled)
                
                # If turning OFF intercept, auto-forward all pending requests
                if not intercept_enabled:
                    pending_count = len(get_all_pending_intercepts())
                    if pending_count > 0:
                        forward_all_pending_intercepts()
                        # Notify all clients to clear their queues
                        await manager.broadcast({'type': 'queue_cleared'})
                
                await manager.send_personal_message({'type': 'intercept_status', 'enabled': intercept_enabled}, websocket)
            
            elif action == 'toggle_response_intercept':
                response_enabled = data.get('enabled', False)
                set_response_intercept_enabled(response_enabled)
                await manager.send_personal_message({'type': 'response_intercept_status', 'enabled': response_enabled}, websocket)
            
            elif action == 'forward_request':
                req_id = data.get('id')
                modified = data.get('request', {})
                update_intercept_status(req_id, 'forward', modified)
                await manager.send_personal_message({'type': 'forwarded', 'id': req_id}, websocket)
            
            elif action == 'drop_request':
                req_id = data.get('id')
                update_intercept_status(req_id, 'drop')
                await manager.send_personal_message({'type': 'dropped', 'id': req_id}, websocket)
            
            elif action == 'forward_response':
                resp_id = data.get('id')
                modified = data.get('response', {})
                update_intercept_status(resp_id, 'forward', response_modified=modified)
                await manager.send_personal_message({'type': 'forwarded', 'id': resp_id}, websocket)
            
            elif action == 'drop_response':
                resp_id = data.get('id')
                update_intercept_status(resp_id, 'drop')
                await manager.send_personal_message({'type': 'dropped', 'id': resp_id}, websocket)
            
            elif action == 'forward_all':
                requests_list = data.get('requests', [])
                for req in requests_list:
                    req_id = req.get('id')
                    update_intercept_status(req_id, 'forward', req)
                await manager.send_personal_message({'type': 'queue_cleared'}, websocket)
            
            elif action == 'drop_all':
                ids = data.get('ids', [])
                for req_id in ids:
                    update_intercept_status(req_id, 'drop')
                await manager.send_personal_message({'type': 'queue_cleared'}, websocket)
            
            # HISTORY ACTIONS
            elif action == 'get_history':
                conn = sqlite3.connect(DB_FILE)
                c = conn.cursor()
                c.execute("SELECT id, method, url, status_code, time FROM history ORDER BY id DESC LIMIT 100")
                rows = c.fetchall()
                conn.close()
                await manager.send_personal_message({'type': 'history', 'data': rows}, websocket)
            
            elif action == 'get_history_detail':
                req_id = data.get('id')
                conn = sqlite3.connect(DB_FILE)
                c = conn.cursor()
                c.execute("SELECT request_headers, request_body, response_headers, response_body FROM history WHERE id = ?", (req_id,))
                row = c.fetchone()
                conn.close()
                if row:
                    await manager.send_personal_message({
                        'type': 'history_detail',
                        'request_headers': row[0],
                        'request_body': row[1],
                        'response_headers': row[2],
                        'response_body': row[3]
                    }, websocket)
            
            elif action == 'clear_history':
                conn = sqlite3.connect(DB_FILE)
                c = conn.cursor()
                c.execute("DELETE FROM history")
                conn.commit()
                conn.close()
                await manager.send_personal_message({'type': 'history_cleared'}, websocket)
            
            # REPEATER ACTIONS
            elif action == 'repeater_send':
                req_data = data.get('request', {})
                start = time.time()
                try:
                    resp = requests.request(
                        method=req_data.get('method', 'GET').upper(),
                        url=req_data.get('url', ''),
                        headers=req_data.get('headers', {}),
                        data=req_data.get('body') if req_data.get('body') else None,
                        timeout=req_data.get('timeout', 30),
                        allow_redirects=req_data.get('follow_redirects', True),
                        verify=False
                    )
                    await manager.send_personal_message({
                        'type': 'repeater_response',
                        'success': True,
                        'data': {
                            'status_code': resp.status_code,
                            'headers': dict(resp.headers),
                            'body': resp.text,
                            'elapsed_time': round(time.time() - start, 3),
                            'size': len(resp.content)
                        }
                    }, websocket)
                except Exception as e:
                    await manager.send_personal_message({
                        'type': 'repeater_response',
                        'success': False,
                        'error': str(e)
                    }, websocket)
            
            # INTRUDER ACTIONS
            elif action == 'intruder_attack':
                global intruder_instance
                intruder_instance = Intruder(threads=data.get('threads', 10))
                template = {
                    'method': data.get('method', 'GET'),
                    'url': data.get('url', ''),
                    'headers': data.get('headers', {}),
                    'body': data.get('body', ''),
                    'timeout': data.get('timeout', 30)
                }
                attack_type = data.get('attack_type', 'sniper')
                payloads = data.get('payloads', [])
                
                if attack_type == 'sniper':
                    results = intruder_instance.attack_sniper(template, payloads)
                elif attack_type == 'battering_ram':
                    results = intruder_instance.attack_battering_ram(template, payloads)
                else:
                    results = intruder_instance.attack_sniper(template, payloads)
                
                await manager.send_personal_message({
                    'type': 'intruder_results',
                    'total': len(results),
                    'results': results
                }, websocket)
            
            elif action == 'intruder_stop':
                intruder_instance.stop()
                await manager.send_personal_message({'type': 'intruder_stopped'}, websocket)
            
            elif action == 'get_payloads':
                payload_type = data.get('payload_type', 'passwords')
                if payload_type == 'passwords':
                    payloads = PayloadGenerator.common_passwords()
                elif payload_type == 'usernames':
                    payloads = PayloadGenerator.common_usernames()
                elif payload_type == 'sqli':
                    payloads = PayloadGenerator.sqli_payloads()
                elif payload_type == 'xss':
                    payloads = PayloadGenerator.xss_payloads()
                elif payload_type == 'path_traversal':
                    payloads = PayloadGenerator.path_traversal_payloads()
                elif payload_type == 'numbers':
                    payloads = PayloadGenerator.numbers(data.get('start', 0), data.get('end', 100), data.get('step', 1))
                else:
                    payloads = []
                
                await manager.send_personal_message({
                    'type': 'payloads',
                    'payload_type': payload_type,
                    'payloads': payloads
                }, websocket)
            
            # Unknown action
            else:
                await manager.send_personal_message({'type': 'error', 'message': f'Unknown action: {action}'}, websocket)
                
    except WebSocketDisconnect:
        manager.disconnect(websocket)
    except Exception as e:
        print(f"WebSocket error: {e}")
        manager.disconnect(websocket)

# Serve frontend
@app.get("/")
def dashboard():
    try:
        with open("index.html", "r", encoding="utf-8") as f:
            return HTMLResponse(content=f.read())
    except FileNotFoundError:
        return HTMLResponse(content="<h1>index.html not found</h1>")

# Global storage for intercepted flows
intercepted_flows = {}
intercepted_responses = {}

# Mitmproxy Addons
if MITMPROXY_AVAILABLE:
    class GUIInterceptAddon:
        """Intercept addon that queues requests for GUI approval via SQLite"""
        
        def __init__(self):
            self.excluded_hosts = ["127.0.0.1", "localhost", "0.0.0.0"]
            self.excluded_ports = [5050]
            self.excluded_patterns = [r"/ws"]
            self.stop_processing = False
            self.flow_request_ids = {}  # Map flow to request_id for response interception
            # Start background thread to process intercepted flows
            self.processing_thread = threading.Thread(target=self._process_intercepted_flows, daemon=True)
            self.processing_thread.start()
        
        def should_intercept(self, flow):
            if flow.request.host in self.excluded_hosts:
                return False
            if flow.request.port in self.excluded_ports:
                return False
            for pattern in self.excluded_patterns:
                if re.search(pattern, flow.request.path):
                    return False
            return True
        
        def _process_intercepted_flows(self):
            """Background thread that processes intercepted flows"""
            while not self.stop_processing:
                try:
                    # Get all pending intercepts from database
                    conn = sqlite3.connect(DB_FILE)
                    c = conn.cursor()
                    c.execute("SELECT id, status, modified_method, modified_url, modified_headers, modified_body, modified_response_headers, modified_response_body, item_type FROM intercept_queue WHERE status != 'pending'")
                    rows = c.fetchall()
                    conn.close()
                    
                    for row in rows:
                        item_id, action, mod_method, mod_url, mod_headers, mod_body, mod_resp_headers, mod_resp_body, item_type = row
                        
                        # Handle request interception
                        if item_type == 'request' or item_type is None:
                            # Find the corresponding flow
                            if item_id in intercepted_flows:
                                flow = intercepted_flows.pop(item_id)
                                
                                if action == 'drop':
                                    flow.response = http.Response.make(403, b"Request Dropped by Interceptor")
                                elif action == 'forward':
                                    # Apply any modifications
                                    if mod_method:
                                        flow.request.method = mod_method
                                    if mod_url:
                                        flow.request.url = mod_url
                                    if mod_headers:
                                        new_headers = {}
                                        for line in mod_headers.split('\n'):
                                            if ':' in line:
                                                k, v = line.split(':', 1)
                                                new_headers[k.strip()] = v.strip()
                                        flow.request.headers.clear()
                                        for k, v in new_headers.items():
                                            flow.request.headers[k] = v
                                    if mod_body is not None:
                                        flow.request.text = mod_body
                                
                                # Resume the flow
                                if hasattr(flow, 'resume'):
                                    flow.resume()
                                
                                # Remove from database
                                remove_from_intercept_queue(item_id)
                        
                        # Handle response interception
                        elif item_type == 'response':
                            # Find the corresponding flow
                            if item_id in intercepted_responses:
                                flow = intercepted_responses.pop(item_id)
                                
                                if action == 'drop':
                                    flow.response = http.Response.make(403, b"Response Dropped by Interceptor")
                                elif action == 'forward':
                                    # Apply any response modifications
                                    if mod_resp_headers or mod_resp_body is not None:
                                        # Parse modified headers
                                        if mod_resp_headers:
                                            new_headers = {}
                                            for line in mod_resp_headers.split('\n'):
                                                if ':' in line:
                                                    k, v = line.split(':', 1)
                                                    new_headers[k.strip()] = v.strip()
                                            flow.response.headers.clear()
                                            for k, v in new_headers.items():
                                                flow.response.headers[k] = v
                                        if mod_resp_body is not None:
                                            flow.response.text = mod_resp_body
                                
                                # Resume the flow
                                if hasattr(flow, 'resume'):
                                    flow.resume()
                                
                                # Remove from database
                                remove_from_intercept_queue(item_id)
                    
                    time.sleep(0.1)  # Poll every 100ms
                except Exception as e:
                    print(f"Error in processing thread: {e}")
                    time.sleep(0.5)
        
        def request(self, flow):
            # Check if intercept is enabled via database (IPC)
            if not is_intercept_enabled() or not self.should_intercept(flow):
                # Still track the flow for potential response interception
                if is_response_intercept_enabled() and self.should_intercept(flow):
                    req_id = str(uuid.uuid4())
                    self.flow_request_ids[flow] = req_id
                return
            
            # Generate unique ID
            req_id = str(uuid.uuid4())
            self.flow_request_ids[flow] = req_id
            
            # Build raw request
            raw_request = f"{flow.request.method} {flow.request.path} HTTP/1.1\n"
            headers_dict = dict(flow.request.headers)
            headers_str = ""
            for k, v in headers_dict.items():
                raw_request += f"{k}: {v}\n"
                headers_str += f"{k}: {v}\n"
            body = flow.request.text if flow.request.text else ""
            if body:
                raw_request += f"\n{body}"
            
            # Add to database queue
            add_to_intercept_queue(
                req_id, 
                flow.request.method, 
                flow.request.url, 
                flow.request.host,
                headers_str, 
                body, 
                raw_request
            )
            
            # Store flow reference and intercept (NON-BLOCKING)
            intercepted_flows[req_id] = flow
            flow.intercept()  # This pauses the flow without blocking mitmproxy
        
        def response(self, flow):
            # First, check if we need to intercept the response
            if is_response_intercept_enabled() and self.should_intercept(flow):
                # Get the request ID for this flow (if it was intercepted as a request)
                req_id = self.flow_request_ids.pop(flow, None)
                
                # Generate a unique response ID
                resp_id = str(uuid.uuid4())
                
                # Build raw response
                raw_response = f"HTTP/1.1 {flow.response.status_code} {flow.response.reason}\n"
                headers_dict = dict(flow.response.headers)
                headers_str = ""
                for k, v in headers_dict.items():
                    raw_response += f"{k}: {v}\n"
                    headers_str += f"{k}: {v}\n"
                body = flow.response.text if flow.response.text else ""
                if body:
                    raw_response += f"\n{body}"
                
                # Add response to database queue
                add_response_to_queue(
                    resp_id,
                    req_id,  # Parent request ID
                    flow.request.method,
                    flow.request.url,
                    flow.request.host,
                    flow.response.status_code,
                    headers_str,
                    body,
                    raw_response
                )
                
                # Store flow reference and intercept (NON-BLOCKING)
                intercepted_responses[resp_id] = flow
                flow.intercept()  # This pauses the flow without blocking mitmproxy
            
            # Save to history (always do this)
            try:
                save_to_history(
                    flow.request.method,
                    flow.request.url,
                    flow.response.status_code,
                    json.dumps(dict(flow.request.headers), ensure_ascii=False),
                    flow.request.text if flow.request.text else "",
                    json.dumps(dict(flow.response.headers), ensure_ascii=False),
                    flow.response.text if flow.response.text else ""
                )
            except Exception as e:
                print(f"Error saving to history: {e}")
    
    addons = [GUIInterceptAddon()]

if __name__ == "__main__":
    print("=" * 60)
    print("  RedKit Proxy WebSocket v4.0 - GUI Interceptor")
    print("=" * 60)
    print("\n[+] Starting WebSocket server on ws://0.0.0.0:5050/ws")
    print("[+] Dashboard: http://localhost:5050")
    print("[+] Features: Interceptor, HTTP History, Repeater, Intruder")
    print("\n[!] For intercept mode: mitmdump -s backend.py -p 8080")
    print("=" * 60 + "\n")
    uvicorn.run(app, host="0.0.0.0", port=5050)
