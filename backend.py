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
import itertools
import fnmatch

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
            intercept_response INTEGER DEFAULT 0,
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
    
    # Migration: Add intercept_response column if it doesn't exist
    try:
        c.execute("SELECT intercept_response FROM intercept_queue LIMIT 1")
    except sqlite3.OperationalError:
        c.execute("ALTER TABLE intercept_queue ADD COLUMN intercept_response INTEGER DEFAULT 0")
        print("[DB Migration] Added 'intercept_response' column to intercept_queue table")
    
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

    # Scope rules table: target-scope include/exclude patterns + excluded extensions
    c.execute("""
        CREATE TABLE IF NOT EXISTS scope_rules (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            rule_type TEXT,
            pattern TEXT,
            UNIQUE(rule_type, pattern)
        )
    """)

    # Scope toggles persist across restarts (INSERT OR IGNORE keeps the user's choice)
    c.execute("INSERT OR IGNORE INTO intercept_settings (key, value) VALUES ('scope_enabled', 'false')")
    c.execute("INSERT OR IGNORE INTO intercept_settings (key, value) VALUES ('extension_exclude_enabled', 'true')")

    # Seed default excluded extensions exactly once (so the user can delete them later)
    c.execute("SELECT value FROM intercept_settings WHERE key = 'extensions_seeded'")
    if not c.fetchone():
        for ext in ['js', 'css', 'html', 'jpg', 'png', 'gif', 'svg', 'ico', 'woff', 'woff2', 'ttf']:
            c.execute("INSERT OR IGNORE INTO scope_rules (rule_type, pattern) VALUES ('extension', ?)", (ext,))
        c.execute("INSERT OR REPLACE INTO intercept_settings (key, value) VALUES ('extensions_seeded', 'true')")

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

# ---------- Scope settings & rules (IPC via SQLite) ----------
def _get_setting(key, default='false'):
    try:
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute("SELECT value FROM intercept_settings WHERE key = ?", (key,))
        row = c.fetchone()
        conn.close()
        return row[0] if row else default
    except Exception:
        return default

def _set_setting(key, value):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("INSERT OR REPLACE INTO intercept_settings (key, value) VALUES (?, ?)", (key, value))
    conn.commit()
    conn.close()

def is_scope_enabled():
    return _get_setting('scope_enabled') == 'true'

def set_scope_enabled(enabled):
    _set_setting('scope_enabled', 'true' if enabled else 'false')

def is_extension_exclude_enabled():
    return _get_setting('extension_exclude_enabled') == 'true'

def set_extension_exclude_enabled(enabled):
    _set_setting('extension_exclude_enabled', 'true' if enabled else 'false')

def get_scope_rules(rule_type):
    """Return just the patterns for a rule type ('include' | 'exclude' | 'extension')."""
    try:
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute("SELECT pattern FROM scope_rules WHERE rule_type = ? ORDER BY id", (rule_type,))
        rows = [r[0] for r in c.fetchall()]
        conn.close()
        return rows
    except Exception:
        return []

def get_scope_rules_with_ids(rule_type):
    """Return [{id, pattern}, ...] for the UI."""
    try:
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute("SELECT id, pattern FROM scope_rules WHERE rule_type = ? ORDER BY id", (rule_type,))
        rows = [{'id': r[0], 'pattern': r[1]} for r in c.fetchall()]
        conn.close()
        return rows
    except Exception:
        return []

def add_scope_rule(rule_type, pattern):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("INSERT OR IGNORE INTO scope_rules (rule_type, pattern) VALUES (?, ?)", (rule_type, pattern))
    conn.commit()
    conn.close()

def remove_scope_rule(rule_id):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("DELETE FROM scope_rules WHERE id = ?", (rule_id,))
    conn.commit()
    conn.close()

def get_full_scope():
    """Full scope snapshot sent to the dashboard."""
    return {
        'enabled': is_scope_enabled(),
        'extension_enabled': is_extension_exclude_enabled(),
        'include': get_scope_rules_with_ids('include'),
        'exclude': get_scope_rules_with_ids('exclude'),
        'extensions': get_scope_rules_with_ids('extension'),
    }

def _pattern_matches(pattern, text):
    """Match as RegEx; if the pattern isn't valid regex, fall back to glob wildcards."""
    try:
        return re.search(pattern, text, re.IGNORECASE) is not None
    except re.error:
        return fnmatch.fnmatch(text.lower(), pattern.lower())

def _path_extension(path):
    """Extract a file extension from a request path (ignoring query/fragment)."""
    path = path.split('?')[0].split('#')[0]
    last = path.rsplit('/', 1)[-1]
    if '.' in last:
        return last.rsplit('.', 1)[-1].lower()
    return ''

def is_flow_in_scope(url, path):
    """Apply extension-exclude + target-scope rules. Returns False to skip the flow."""
    if is_extension_exclude_enabled():
        ext = _path_extension(path)
        if ext and ext in [e.lower() for e in get_scope_rules('extension')]:
            return False
    if is_scope_enabled():
        includes = get_scope_rules('include')
        excludes = get_scope_rules('exclude')
        # An empty include list means "everything is in scope" (Burp behaviour).
        if includes and not any(_pattern_matches(p, url) for p in includes):
            return False
        if any(_pattern_matches(p, url) for p in excludes):
            return False
    return True

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

def get_request_by_id(req_id):
    """Get request data by ID"""
    try:
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute("SELECT method, url, host, headers, body, raw_request FROM intercept_queue WHERE id = ?", (req_id,))
        row = c.fetchone()
        conn.close()
        if row:
            return {
                'method': row[0],
                'url': row[1],
                'host': row[2],
                'headers': row[3],
                'body': row[4],
                'raw': row[5]
            }
        return None
    except:
        return None

def parse_raw_request(raw):
    """Parse raw HTTP request string into components"""
    lines = raw.replace('\r\n', '\n').split('\n')
    if not lines:
        return {}
    
    # Parse first line: METHOD /path HTTP/1.1 OR METHOD https://host/path HTTP/1.1
    first_line = lines[0].strip()
    parts = first_line.split(' ')
    method = parts[0] if len(parts) > 0 else 'GET'
    path_or_url = parts[1] if len(parts) > 1 else '/'
    
    # Find where headers end and body begins
    headers_list = []
    body_start = -1
    host = ''
    
    for i in range(1, len(lines)):
        line = lines[i]
        if line.strip() == '':
            body_start = i + 1
            break
        headers_list.append(line)
        if line.lower().startswith('host:'):
            host = line.split(':', 1)[1].strip()
    
    # Reconstruct headers string
    headers = '\n'.join(headers_list)
    
    # Get body
    body = '\n'.join(lines[body_start:]) if body_start > 0 else ''
    
    # Build full URL from path and host
    # Handle both path-only format (/path) and full-URL format (https://host/path)
    if path_or_url.startswith(('http://', 'https://')):
        # Full URL in request line - extract path from it
        try:
            from urllib.parse import urlparse
            parsed = urlparse(path_or_url)
            path = parsed.path if parsed.path else '/'
            if parsed.query:
                path += '?' + parsed.query
            # Use host from URL if not found in headers
            if not host and parsed.hostname:
                host = parsed.hostname
        except:
            path = '/'
    else:
        # Already a path
        path = path_or_url
    
    # Build full URL for mitmproxy
    if host:
        url = f"https://{host}{path}"
    else:
        url = path_or_url  # Fallback to original if no host
    
    return {
        'method': method,
        'url': url,
        'headers': headers,
        'body': body
    }

def parse_raw_response(raw):
    """Parse raw HTTP response string into components"""
    lines = raw.split('\n')
    if not lines:
        return {}
    
    # Parse first line: HTTP/1.1 200 OK
    # Status code is not needed for forwarding, but we keep it for completeness
    
    # Find where headers end and body begins
    headers_list = []
    body_start = -1
    
    for i in range(1, len(lines)):
        line = lines[i]
        if line.strip() == '':
            body_start = i + 1
            break
        headers_list.append(line)
    
    # Reconstruct headers string
    headers = '\n'.join(headers_list)
    
    # Get body
    body = '\n'.join(lines[body_start:]) if body_start > 0 else ''
    
    return {
        'headers': headers,
        'body': body
    }

def parse_raw_http_request(raw, scheme='https', default_host=''):
    """Parse a raw HTTP request (Burp-style) into method, url, headers dict, and body.

    Used by the Repeater so the user can edit the full request on the wire.
    The destination is built from the request-line path plus the Host header
    (or an explicit target override via `scheme`/`default_host`).
    """
    raw = raw.replace('\r\n', '\n').replace('\r', '\n')
    lines = raw.split('\n')
    if not lines or not lines[0].strip():
        return None

    parts = lines[0].strip().split(' ')
    method = parts[0] if parts else 'GET'
    path = parts[1] if len(parts) > 1 else '/'

    headers = {}
    host = ''
    body_start = len(lines)
    for i in range(1, len(lines)):
        if lines[i].strip() == '':
            body_start = i + 1
            break
        if ':' in lines[i]:
            k, v = lines[i].split(':', 1)
            k = k.strip()
            v = v.strip()
            if not k:
                continue
            headers[k] = v
            if k.lower() == 'host':
                host = v

    body = '\n'.join(lines[body_start:]) if body_start < len(lines) else ''

    # Build the full URL. A request line may carry a full URL (proxy form) or just a path.
    if path.startswith(('http://', 'https://')):
        url = path
    else:
        target_host = default_host or host
        url = f"{scheme}://{target_host}{path}"

    return {'method': method, 'url': url, 'headers': headers, 'body': body, 'host': host}

def forward_all_pending_intercepts():
    """Forward all pending intercepts"""
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("UPDATE intercept_queue SET status = 'forward' WHERE status = 'pending'")
    conn.commit()
    conn.close()

def capitalize_header_name(header_name):
    """Capitalize HTTP header names properly (e.g., 'content-type' -> 'Content-Type')"""
    # Special cases for common headers
    special_cases = {
        'www-authenticate': 'WWW-Authenticate',
        'x-xss-protection': 'X-XSS-Protection',
        'x-webkit-csp': 'X-WebKit-CSP',
        'x-dns-prefetch-control': 'X-DNS-Prefetch-Control',
        'x-frame-options': 'X-Frame-Options',
        'x-content-type-options': 'X-Content-Type-Options',
        'x-powered-by': 'X-Powered-By',
        'x-ua-compatible': 'X-UA-Compatible',
        'x-request-id': 'X-Request-ID',
        'x-correlation-id': 'X-Correlation-ID',
        'x-real-ip': 'X-Real-IP',
        'x-forwarded-for': 'X-Forwarded-For',
        'x-forwarded-host': 'X-Forwarded-Host',
        'x-forwarded-proto': 'X-Forwarded-Proto',
        'x-csrf-token': 'X-CSRF-Token',
        'x-xsrf-token': 'X-XSRF-Token',
        'x-api-key': 'X-API-Key',
        'x-auth-token': 'X-Auth-Token',
        'accept-ch': 'Accept-CH',
        'accept-ch-lifetime': 'Accept-CH-Lifetime',
        'dnt': 'DNT',
        'ect': 'ECT',
        'etag': 'ETag',
        'last-event-id': 'Last-Event-ID',
        'nel': 'NEL',
        'sec-ch-ua': 'Sec-CH-UA',
        'sec-ch-ua-arch': 'Sec-CH-UA-Arch',
        'sec-ch-ua-bitness': 'Sec-CH-UA-Bitness',
        'sec-ch-ua-full-version': 'Sec-CH-UA-Full-Version',
        'sec-ch-ua-full-version-list': 'Sec-CH-UA-Full-Version-List',
        'sec-ch-ua-mobile': 'Sec-CH-UA-Mobile',
        'sec-ch-ua-model': 'Sec-CH-UA-Model',
        'sec-ch-ua-platform': 'Sec-CH-UA-Platform',
        'sec-ch-ua-platform-version': 'Sec-CH-UA-Platform-Version',
        'sec-fetch-dest': 'Sec-Fetch-Dest',
        'sec-fetch-mode': 'Sec-Fetch-Mode',
        'sec-fetch-site': 'Sec-Fetch-Site',
        'sec-fetch-user': 'Sec-Fetch-User',
        'sec-websocket-accept': 'Sec-WebSocket-Accept',
        'sec-websocket-extensions': 'Sec-WebSocket-Extensions',
        'sec-websocket-key': 'Sec-WebSocket-Key',
        'sec-websocket-protocol': 'Sec-WebSocket-Protocol',
        'sec-websocket-version': 'Sec-WebSocket-Version',
        'www-authenticate': 'WWW-Authenticate',
        'content-md5': 'Content-MD5',
        'content-sha256': 'Content-SHA256',
    }
    
    lower_name = header_name.lower()
    if lower_name in special_cases:
        return special_cases[lower_name]
    
    # General rule: capitalize first letter of each word
    return '-'.join(word.capitalize() for word in header_name.split('-'))

def build_raw_request(flow_request):
    """Build properly formatted raw HTTP request"""
    # Build request line with path only (not full URL)
    # This is the standard HTTP/1.1 format
    path = flow_request.path if flow_request.path else '/'
    raw_request = f"{flow_request.method} {path} HTTP/1.1\r\n"
    
    # Ensure Host header is first and properly formatted
    host = flow_request.host
    if host:
        raw_request += f"Host: {host}\r\n"
    
    # Add other headers with proper capitalization
    for header_name, header_value in flow_request.headers.items():
        # Skip Host header as we already added it
        if header_name.lower() == 'host':
            continue
        
        # Capitalize header name properly
        capitalized_name = capitalize_header_name(header_name)
        raw_request += f"{capitalized_name}: {header_value}\r\n"
    
    # Add body if present
    body = flow_request.text if flow_request.text else ""
    if body:
        raw_request += f"\r\n{body}"
    
    return raw_request

def build_raw_response(flow_response):
    """Build properly formatted raw HTTP response"""
    # Build status line
    raw_response = f"HTTP/1.1 {flow_response.status_code} {flow_response.reason}\r\n"
    
    # Add headers with proper capitalization
    for header_name, header_value in flow_response.headers.items():
        capitalized_name = capitalize_header_name(header_name)
        raw_response += f"{capitalized_name}: {header_value}\r\n"
    
    # Add body if present
    body = flow_response.text if flow_response.text else ""
    if body:
        raw_response += f"\r\n{body}"
    
    return raw_response

def set_request_intercept_response(req_id, intercept_response):
    """Mark a request to have its response intercepted"""
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("UPDATE intercept_queue SET intercept_response = ? WHERE id = ?", (1 if intercept_response else 0, req_id))
    conn.commit()
    conn.close()
    print(f"[DEBUG] Set intercept_response={intercept_response} for request {req_id}")

def should_intercept_response(req_id):
    """Check if a request's response should be intercepted"""
    try:
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute("SELECT intercept_response FROM intercept_queue WHERE id = ?", (req_id,))
        row = c.fetchone()
        conn.close()
        return row and row[0] == 1
    except:
        return False

def remove_parent_request(parent_id):
    """Remove the parent request when response is processed"""
    if parent_id:
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute("DELETE FROM intercept_queue WHERE id = ? AND item_type = 'request'", (parent_id,))
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
        return ["../", "../../", "../../../etc/passwd", "..%2f..%2f..%2fetc%2fpasswd",
                "....//....//etc/passwd", "/etc/passwd", "C:\\Windows\\win.ini"]

    @staticmethod
    def directories():
        return ["admin", "login", "dashboard", "api", "uploads", "backup", "config",
                "test", ".git", ".env", "robots.txt", "wp-admin", "phpmyadmin"]

    @staticmethod
    def fuzz():
        return ["'", "\"", "<", ">", "`", ";", "|", "&&", "${{7*7}}", "{{7*7}}",
                "%00", "../", "$(id)", "\n", "\r\n"]

    @staticmethod
    def http_methods():
        return ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "TRACE", "CONNECT"]

    @staticmethod
    def numbers(start, end, step=1):
        return [str(i) for i in range(start, end + 1, step)]

# Intruder (Burp-style: raw request template with § positions, 4 attack types)
class Intruder:
    POSITION_MARKER = "§"

    def __init__(self, threads=10):
        self.threads = threads
        self.results = []
        self.stop_flag = False

    def find_positions(self, template):
        """Return (start, end, default_value) for each §...§ marker pair."""
        pattern = re.compile(f'{self.POSITION_MARKER}(.*?){self.POSITION_MARKER}')
        return [(m.start(), m.end(), m.group(1)) for m in pattern.finditer(template)]

    def render(self, template, position_values):
        """Replace each marker (in order) with the matching value from position_values."""
        out = []
        last = 0
        idx = 0
        for m in re.finditer(f'{self.POSITION_MARKER}(.*?){self.POSITION_MARKER}', template):
            out.append(template[last:m.start()])
            value = position_values[idx] if idx < len(position_values) else m.group(1)
            out.append(value if value is not None else m.group(1))
            last = m.end()
            idx += 1
        out.append(template[last:])
        return ''.join(out)

    def _build_jobs(self, attack_type, defaults, payload_sets):
        """Build the list of (position_values, label) tuples for the chosen attack type."""
        n = len(defaults)
        jobs = []
        set0 = payload_sets[0] if payload_sets else []

        if n == 0:
            return [([], '')]

        if attack_type == 'battering_ram':
            for payload in set0:
                jobs.append(([payload] * n, payload))
        elif attack_type == 'pitchfork':
            usable = [payload_sets[i] if i < len(payload_sets) else [] for i in range(n)]
            min_len = min((len(s) for s in usable), default=0)
            for i in range(min_len):
                vals = [usable[p][i] for p in range(n)]
                jobs.append((vals, ', '.join(vals)))
        elif attack_type == 'cluster_bomb':
            usable = [payload_sets[i] if (i < len(payload_sets) and payload_sets[i]) else [''] for i in range(n)]
            for combo in itertools.product(*usable):
                jobs.append((list(combo), ', '.join(combo)))
        else:  # sniper (default): one position at a time, others keep default
            for p in range(n):
                for payload in set0:
                    vals = list(defaults)
                    vals[p] = payload
                    jobs.append((vals, payload))
        return jobs

    def attack(self, raw_template, attack_type, payload_sets, scheme='https',
               default_host='', timeout=30, follow_redirects=False, grep=None, on_result=None):
        """Run an Intruder attack. Streams each result via on_result(result) if given."""
        self.results = []
        self.stop_flag = False

        positions = self.find_positions(raw_template)
        defaults = [p[2] for p in positions]
        jobs = self._build_jobs(attack_type, defaults, payload_sets)

        def do_job(req_num, vals, label):
            if self.stop_flag:
                return None
            rendered = self.render(raw_template, vals) if positions else raw_template
            parsed = parse_raw_http_request(rendered, scheme=scheme, default_host=default_host)
            start = time.time()
            if not parsed or not parsed.get('method'):
                return {'request': req_num, 'payload': label, 'status_code': 0, 'length': 0,
                        'time': 0, 'grep': None, 'error': 'Invalid request', 'response': ''}
            try:
                headers = {k: v for k, v in parsed['headers'].items() if k.lower() != 'content-length'}
                resp = requests.request(
                    method=parsed['method'].upper(),
                    url=parsed['url'],
                    headers=headers,
                    data=parsed['body'].encode('utf-8', 'replace') if parsed['body'] else None,
                    timeout=timeout,
                    allow_redirects=follow_redirects,
                    verify=False
                )
                body = resp.text
                raw_response = f"HTTP/1.1 {resp.status_code} {resp.reason}\r\n"
                for hk, hv in resp.headers.items():
                    raw_response += f"{hk}: {hv}\r\n"
                raw_response += "\r\n" + body
                return {
                    'request': req_num, 'payload': label,
                    'status_code': resp.status_code,
                    'length': len(resp.content),
                    'time': round(time.time() - start, 3),
                    'grep': (body.count(grep) if grep else None),
                    'error': None,
                    'response': raw_response[:200000]  # cap stored response
                }
            except Exception as e:
                return {'request': req_num, 'payload': label, 'status_code': 0, 'length': 0,
                        'time': round(time.time() - start, 3), 'grep': None, 'error': str(e), 'response': ''}

        with ThreadPoolExecutor(max_workers=self.threads) as exe:
            futures = []
            for i, (vals, label) in enumerate(jobs):
                if self.stop_flag:
                    break
                futures.append(exe.submit(do_job, i + 1, vals, label))

            for f in futures:
                if self.stop_flag:
                    break
                r = f.result()
                if r is not None:
                    self.results.append(r)
                    if on_result:
                        try:
                            on_result(r)
                        except Exception:
                            pass

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

def format_history_row(row):
    """
    Format a database history row into the frontend Table schema:
    {
      id: string,
      Time: string,
      Type: string,
      Method: string,
      Direction: string,
      Host: string,
      URL: string,
      StatusCode: number,
      Length: number,
      Params: boolean
    }
    """
    h_id, method, url, status_code, time_str, req_headers, req_body, resp_headers, resp_body = row
    
    # Extract host and type
    try:
        from urllib.parse import urlparse
        parsed = urlparse(url)
        host = parsed.netloc
        h_type = parsed.scheme.upper()
        params = bool(parsed.query)
    except:
        host = "unknown"
        h_type = "HTTP"
        params = False

    # Calculate total length (headers + body)
    # Note: req_headers and resp_headers are stored as JSON strings in history table
    # We sum the lengths of the actual content
    total_length = len(req_headers or "") + len(req_body or "") + len(resp_headers or "") + len(resp_body or "")

    return {
        "id": str(h_id),
        "Time": time_str,
        "Type": h_type,
        "Method": method,
        "Direction": "History",
        "Host": host,
        "URL": url,
        "StatusCode": status_code,
        "Length": total_length,
        "Params": params
    }

def get_max_history_id():
    """Return the highest history id currently stored (0 if empty)."""
    try:
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute("SELECT MAX(id) FROM history")
        row = c.fetchone()
        conn.close()
        return row[0] if row and row[0] is not None else 0
    except Exception:
        return 0

def get_history_after(after_id):
    """Return history rows newer than after_id (oldest first) for live updates."""
    try:
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute("SELECT id, method, url, status_code, time, request_headers, request_body, response_headers, response_body FROM history WHERE id > ? ORDER BY id ASC", (after_id,))
        rows = c.fetchall()
        conn.close()
        return rows
    except Exception:
        return []

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
                            # Get parent request data
                            parent_request = get_request_by_id(parent_id) if parent_id else None
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
                                'raw_response': raw_response,
                                'parent_request': parent_request
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

# Background task to broadcast new history rows in real time
async def poll_history():
    """Watch the history table and push newly logged entries to all clients.

    The proxy addon (mitmdump process) writes history to SQLite; this task runs
    in the FastAPI process and bridges those rows to connected WebSocket clients.
    """
    global last_history_id
    last_history_id = get_max_history_id()
    while True:
        try:
            await asyncio.sleep(0.5)
            new_rows = get_history_after(last_history_id)
            for row in new_rows:
                last_history_id = row[0]
                formatted_row = format_history_row(row)
                await manager.broadcast({'type': 'history_new', 'row': formatted_row})
        except Exception as e:
            print(f"Error in poll_history: {e}")

# Highest history id already broadcast to clients
last_history_id = 0

# Start background task
@app.on_event("startup")
async def startup_event():
    asyncio.create_task(poll_intercepts())
    asyncio.create_task(poll_history())

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
            
            elif action == 'mark_for_response_intercept':
                req_id = data.get('id')
                set_request_intercept_response(req_id, True)
                await manager.send_personal_message({'type': 'marked_for_response_intercept', 'id': req_id}, websocket)
            
            elif action == 'unmark_for_response_intercept':
                req_id = data.get('id')
                set_request_intercept_response(req_id, False)
                await manager.send_personal_message({'type': 'unmarked_for_response_intercept', 'id': req_id}, websocket)
            
            elif action == 'forward_request':
                req_id = data.get('id')
                request_raw = data.get('request', '')
                # Parse raw HTTP request
                parsed = parse_raw_request(request_raw)
                modified = {
                    'method': parsed.get('method'),
                    'url': parsed.get('url'),
                    'headers': parsed.get('headers'),
                    'body': parsed.get('body')
                }
                update_intercept_status(req_id, 'forward', modified)
                await manager.send_personal_message({'type': 'forwarded', 'id': req_id}, websocket)
            
            elif action == 'drop_request':
                req_id = data.get('id')
                update_intercept_status(req_id, 'drop')
                await manager.send_personal_message({'type': 'dropped', 'id': req_id}, websocket)
            
            elif action == 'forward_response':
                resp_id = data.get('id')
                response_raw = data.get('response', '')
                # Parse raw HTTP response
                parsed = parse_raw_response(response_raw)
                modified = {
                    'headers': parsed.get('headers'),
                    'body': parsed.get('body')
                }
                update_intercept_status(resp_id, 'forward', response_modified=modified)
                await manager.send_personal_message({'type': 'forwarded', 'id': resp_id}, websocket)
            
            elif action == 'drop_response':
                resp_id = data.get('id')
                update_intercept_status(resp_id, 'drop')
                await manager.send_personal_message({'type': 'dropped', 'id': resp_id}, websocket)
            
            elif action == 'forward_all':
                items_list = data.get('items', [])
                for item_data in items_list:
                    item_id = item_data.get('id')
                    item_type = item_data.get('type', 'request')
                    raw_content = item_data.get('raw', '')
                    
                    if item_type == 'response':
                        # Parse raw HTTP response
                        parsed = parse_raw_response(raw_content)
                        modified = {
                            'headers': parsed.get('headers'),
                            'body': parsed.get('body')
                        }
                        update_intercept_status(item_id, 'forward', response_modified=modified)
                    else:
                        # Parse raw HTTP request
                        parsed = parse_raw_request(raw_content)
                        modified = {
                            'method': parsed.get('method'),
                            'url': parsed.get('url'),
                            'headers': parsed.get('headers'),
                            'body': parsed.get('body')
                        }
                        update_intercept_status(item_id, 'forward', modified)
                await manager.send_personal_message({'type': 'queue_cleared'}, websocket)
            
            elif action == 'drop_all':
                ids = data.get('ids', [])
                for req_id in ids:
                    update_intercept_status(req_id, 'drop')
                await manager.send_personal_message({'type': 'queue_cleared'}, websocket)

            # SCOPE ACTIONS (target-scope rules + extension excludes)
            elif action == 'get_scope':
                await manager.send_personal_message({'type': 'scope', **get_full_scope()}, websocket)

            elif action == 'toggle_scope':
                set_scope_enabled(data.get('enabled', False))
                await manager.broadcast({'type': 'scope', **get_full_scope()})

            elif action == 'toggle_extension_exclude':
                set_extension_exclude_enabled(data.get('enabled', False))
                await manager.broadcast({'type': 'scope', **get_full_scope()})

            elif action == 'add_scope_rule':
                rule_type = data.get('rule_type')
                pattern = (data.get('pattern') or '').strip()
                if rule_type in ('include', 'exclude', 'extension') and pattern:
                    add_scope_rule(rule_type, pattern)
                await manager.broadcast({'type': 'scope', **get_full_scope()})

            elif action == 'remove_scope_rule':
                remove_scope_rule(data.get('id'))
                await manager.broadcast({'type': 'scope', **get_full_scope()})

            # HISTORY ACTIONS
            elif action == 'get_history':
                conn = sqlite3.connect(DB_FILE)
                c = conn.cursor()
                c.execute("SELECT id, method, url, status_code, time, request_headers, request_body, response_headers, response_body FROM history ORDER BY id DESC LIMIT 100")
                rows = c.fetchall()
                conn.close()
                formatted_data = [format_history_row(row) for row in rows]
                await manager.send_personal_message({'type': 'history', 'data': formatted_data}, websocket)
            
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
            
            # REPEATER ACTIONS (Burp-style: edit a raw HTTP request, get a raw response)
            elif action == 'repeater_send':
                raw = data.get('raw', '')
                target = (data.get('target') or '').strip()
                follow_redirects = data.get('follow_redirects', False)
                timeout = data.get('timeout', 30)
                # Optional client tab/request id, echoed back so the UI can route
                # the response to the Repeater tab that sent it.
                req_id = data.get('req_id')

                # An optional target override decides scheme/host when the request
                # line only carries a path (the standard on-the-wire form).
                scheme = 'https'
                default_host = ''
                if target:
                    from urllib.parse import urlparse
                    if '://' not in target:
                        target = 'https://' + target
                    parsed_target = urlparse(target)
                    scheme = parsed_target.scheme or 'https'
                    default_host = parsed_target.netloc

                parsed = parse_raw_http_request(raw, scheme=scheme, default_host=default_host)
                start = time.time()

                if not parsed or not parsed.get('method'):
                    await manager.send_personal_message({
                        'type': 'repeater_response',
                        'req_id': req_id,
                        'success': False,
                        'error': 'Could not parse raw HTTP request'
                    }, websocket)
                else:
                    # Drop Content-Length so requests recomputes it for any edited body.
                    req_headers = {k: v for k, v in parsed['headers'].items()
                                   if k.lower() != 'content-length'}
                    try:
                        resp = requests.request(
                            method=parsed['method'].upper(),
                            url=parsed['url'],
                            headers=req_headers,
                            data=parsed['body'].encode('utf-8', 'replace') if parsed['body'] else None,
                            timeout=timeout,
                            allow_redirects=follow_redirects,
                            verify=False
                        )

                        # Build the raw HTTP response (status line + headers + body)
                        raw_response = f"HTTP/1.1 {resp.status_code} {resp.reason}\r\n"
                        for hk, hv in resp.headers.items():
                            raw_response += f"{capitalize_header_name(hk)}: {hv}\r\n"
                        raw_response += "\r\n" + resp.text

                        await manager.send_personal_message({
                            'type': 'repeater_response',
                            'success': True,
                            'data': {
                                'status_code': resp.status_code,
                                'reason': resp.reason,
                                'url': parsed['url'],
                                'raw_response': raw_response,
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
            
            # INTRUDER ACTIONS (Burp-style: raw request template with § positions)
            elif action == 'intruder_attack':
                global intruder_instance
                intruder_instance = Intruder(threads=data.get('threads', 10))

                raw_template = data.get('raw', '')
                target = (data.get('target') or '').strip()
                attack_type = data.get('attack_type', 'sniper')
                # payload_sets: one list per position. Fall back to a single legacy set.
                payload_sets = data.get('payload_sets')
                if payload_sets is None:
                    payload_sets = [data.get('payloads', [])]
                grep = data.get('grep') or None
                timeout = data.get('timeout', 30)
                follow_redirects = data.get('follow_redirects', False)

                # Resolve scheme/host from an optional target override.
                scheme = 'https'
                default_host = ''
                if target:
                    from urllib.parse import urlparse
                    if '://' not in target:
                        target = 'https://' + target
                    pt = urlparse(target)
                    scheme = pt.scheme or 'https'
                    default_host = pt.netloc

                # Stream each completed result back to this client as it finishes.
                loop = asyncio.get_running_loop()

                def on_result(r):
                    light = {k: r.get(k) for k in
                             ('request', 'payload', 'status_code', 'length', 'time', 'grep', 'error')}
                    asyncio.run_coroutine_threadsafe(
                        manager.send_personal_message({'type': 'intruder_result', 'result': light}, websocket),
                        loop
                    )

                await manager.send_personal_message({'type': 'intruder_started'}, websocket)

                # Run the attack as a background task so the receive loop keeps
                # processing messages (e.g. intruder_stop) while it runs.
                attack_engine = intruder_instance

                async def run_attack():
                    results = await loop.run_in_executor(None, lambda: attack_engine.attack(
                        raw_template, attack_type, payload_sets,
                        scheme=scheme, default_host=default_host,
                        timeout=timeout, follow_redirects=follow_redirects,
                        grep=grep, on_result=on_result
                    ))
                    errors = sum(1 for r in results if r.get('error'))
                    await manager.send_personal_message({
                        'type': 'intruder_complete',
                        'total': len(results),
                        'errors': errors,
                        'stopped': attack_engine.stop_flag
                    }, websocket)

                asyncio.create_task(run_attack())

            elif action == 'intruder_get_response':
                idx = data.get('index')
                found = next((r for r in intruder_instance.results if r.get('request') == idx), None)
                if found:
                    await manager.send_personal_message({
                        'type': 'intruder_response',
                        'index': idx,
                        'payload': found.get('payload'),
                        'status_code': found.get('status_code'),
                        'response': found.get('response', '')
                    }, websocket)
                else:
                    await manager.send_personal_message({
                        'type': 'intruder_response',
                        'index': idx,
                        'response': '(response not available)'
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
                elif payload_type == 'directories':
                    payloads = PayloadGenerator.directories()
                elif payload_type == 'fuzz':
                    payloads = PayloadGenerator.fuzz()
                elif payload_type == 'http_methods':
                    payloads = PayloadGenerator.http_methods()
                elif payload_type == 'numbers':
                    payloads = PayloadGenerator.numbers(data.get('start', 0), data.get('end', 100), data.get('step', 1))
                else:
                    payloads = []

                # Echo the requesting set index so multi-set UIs know where to put it.
                await manager.send_personal_message({
                    'type': 'payloads',
                    'payload_type': payload_type,
                    'set_index': data.get('set_index', 0),
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
            self.url_method_to_req_id = {}  # Map URL+method to request_id for response matching
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

        def _processable(self, flow):
            """True if this flow passes the infra excludes AND the user's scope rules."""
            if not self.should_intercept(flow):
                return False
            return is_flow_in_scope(flow.request.url, flow.request.path)

        def _process_intercepted_flows(self):
            """Background thread that processes intercepted flows"""
            while not self.stop_processing:
                try:
                    # Get all pending intercepts from database
                    conn = sqlite3.connect(DB_FILE)
                    c = conn.cursor()
                    c.execute("SELECT id, status, modified_method, modified_url, modified_headers, modified_body, modified_response_headers, modified_response_body, item_type, parent_id FROM intercept_queue WHERE status != 'pending'")
                    rows = c.fetchall()
                    conn.close()
                    
                    for row in rows:
                        item_id, action, mod_method, mod_url, mod_headers, mod_body, mod_resp_headers, mod_resp_body, item_type, parent_id = row
                        
                        # Handle request interception
                        if item_type == 'request' or item_type is None:
                            # Find the corresponding flow
                            if item_id in intercepted_flows:
                                flow = intercepted_flows.pop(item_id)
                                
                                if action == 'drop':
                                    flow.response = http.Response.make(403, b"Request Dropped by Interceptor")
                                    # Remove from database since request is dropped
                                    remove_from_intercept_queue(item_id)
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
                                    
                                    # Check if this request should have its response intercepted
                                    # If so, DON'T remove it from DB yet
                                    if should_intercept_response(item_id):
                                        print(f"[DEBUG] Request {item_id} marked for response intercept, keeping in DB")
                                    else:
                                        # Remove from database if not intercepting response
                                        remove_from_intercept_queue(item_id)
                                
                                # Resume the flow
                                if hasattr(flow, 'resume'):
                                    flow.resume()
                        
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
                                
                                # Remove response from database
                                remove_from_intercept_queue(item_id)
                                # Also remove the parent request if it exists
                                if parent_id:
                                    remove_parent_request(parent_id)
                    
                    time.sleep(0.1)  # Poll every 100ms
                except Exception as e:
                    print(f"Error in processing thread: {e}")
                    time.sleep(0.5)
        
        def request(self, flow):
            # Scope/extension rules gate everything (interception AND logging).
            if not self._processable(flow):
                return

            # Check if intercept is enabled via database (IPC)
            if not is_intercept_enabled():
                # Still track the flow for potential response interception
                if is_response_intercept_enabled():
                    req_id = str(uuid.uuid4())
                    self.flow_request_ids[flow] = req_id
                return
            
            # Generate unique ID
            req_id = str(uuid.uuid4())
            self.flow_request_ids[flow] = req_id
            
            # Store URL+method mapping for response matching
            url_method_key = f"{flow.request.method}:{flow.request.url}"
            self.url_method_to_req_id[url_method_key] = req_id
            print(f"[DEBUG] Intercepted request {req_id} for {url_method_key}")
            
            # Build raw request with proper formatting
            raw_request = build_raw_request(flow.request)
            
            # Build headers string for database (also properly formatted)
            headers_str = ""
            for header_name, header_value in flow.request.headers.items():
                capitalized_name = capitalize_header_name(header_name)
                headers_str += f"{capitalized_name}: {header_value}\n"
            body = flow.request.text if flow.request.text else ""
            
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
            # Out-of-scope flows are neither intercepted nor logged to history.
            if not self._processable(flow):
                return

            # Try to find the request ID by matching URL and method
            req_id = None
            url_method_key = f"{flow.request.method}:{flow.request.url}"
            
            # First try the flow_request_ids dict (if flow object is same)
            req_id = self.flow_request_ids.get(flow)
            if req_id:
                print(f"[DEBUG] Found req_id {req_id} from flow_request_ids")
            
            # If not found, try the URL+method mapping
            if not req_id:
                req_id = self.url_method_to_req_id.get(url_method_key)
                if req_id:
                    print(f"[DEBUG] Found req_id {req_id} from url_method_to_req_id")
            
            # Clean up the mapping once we have the req_id
            if req_id and url_method_key in self.url_method_to_req_id:
                del self.url_method_to_req_id[url_method_key]
            
            should_intercept = False
            
            if req_id:
                # Check if this specific request was marked for response interception
                if should_intercept_response(req_id):
                    print(f"[DEBUG] Request {req_id} is marked for response interception")
                    should_intercept = True
                else:
                    print(f"[DEBUG] Request {req_id} is NOT marked for response interception")
            else:
                print(f"[DEBUG] No req_id found for {url_method_key}")
            
            # Also check global response intercept toggle
            if not should_intercept and is_response_intercept_enabled() and self.should_intercept(flow):
                print(f"[DEBUG] Global response intercept is ON")
                should_intercept = True
            
            if should_intercept:
                print(f"[DEBUG] Intercepting response for {url_method_key}")
                # Generate a unique response ID
                resp_id = str(uuid.uuid4())
                
                # Build raw response with proper formatting
                raw_response = build_raw_response(flow.response)
                
                # Build headers string for database (also properly formatted)
                headers_str = ""
                for header_name, header_value in flow.response.headers.items():
                    capitalized_name = capitalize_header_name(header_name)
                    headers_str += f"{capitalized_name}: {header_value}\n"
                body = flow.response.text if flow.response.text else ""
                
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
