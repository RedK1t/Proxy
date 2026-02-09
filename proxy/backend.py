"""
RedKit Proxy - Consolidated Backend
A Burp Suite-like web proxy with Interceptor, Repeater, Intruder, and HTTP History
"""

# =============================================================================
# IMPORTS
# =============================================================================
from fastapi import FastAPI, WebSocket, BackgroundTasks
from fastapi.responses import JSONResponse, HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional, List, Dict, Any
from dataclasses import dataclass, asdict
from enum import Enum
from concurrent.futures import ThreadPoolExecutor, as_completed
import sqlite3
import subprocess
import shlex
import uvicorn
import json
import asyncio
import requests
import urllib3
import threading
import time
import re
import os
import datetime
from itertools import product

# Mitmproxy imports (for addon mode)
try:
    from mitmproxy import http
    MITMPROXY_AVAILABLE = True
except ImportError:
    MITMPROXY_AVAILABLE = False
    print("[WARNING] mitmproxy not available - running in API-only mode")

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# =============================================================================
# DATABASE SETUP
# =============================================================================
DB_FILE = "proxy_history.db"

def init_database():
    """Initialize SQLite database for proxy history"""
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

init_database()

# =============================================================================
# REPEATER MODULE
# =============================================================================
@dataclass
class RepeaterRequest:
    """Represents an HTTP Request"""
    method: str
    url: str
    headers: Dict[str, str]
    body: str = ""
    timeout: int = 30
    follow_redirects: bool = True
    verify_ssl: bool = False

@dataclass
class RepeaterResponse:
    """Represents an HTTP Response"""
    status_code: int
    headers: Dict[str, str]
    body: str
    elapsed_time: float
    size: int
    error: Optional[str] = None

class Repeater:
    """Manual HTTP request sender - like Burp Repeater"""
    
    def __init__(self):
        self.history: list = []
        self.session = requests.Session()
    
    def send(self, req: RepeaterRequest) -> RepeaterResponse:
        """Send an HTTP request and return response"""
        start_time = time.time()
        
        try:
            headers = req.headers.copy() if req.headers else {}
            
            response = self.session.request(
                method=req.method.upper(),
                url=req.url,
                headers=headers,
                data=req.body if req.body else None,
                timeout=req.timeout,
                allow_redirects=req.follow_redirects,
                verify=req.verify_ssl
            )
            
            elapsed = time.time() - start_time
            
            resp = RepeaterResponse(
                status_code=response.status_code,
                headers=dict(response.headers),
                body=response.text,
                elapsed_time=round(elapsed, 3),
                size=len(response.content)
            )
            
            self._save_to_history(req, resp)
            return resp
            
        except requests.exceptions.Timeout:
            return RepeaterResponse(
                status_code=0, headers={}, body="",
                elapsed_time=time.time() - start_time, size=0,
                error="Request Timeout"
            )
        except requests.exceptions.ConnectionError as e:
            return RepeaterResponse(
                status_code=0, headers={}, body="",
                elapsed_time=time.time() - start_time, size=0,
                error=f"Connection Error: {str(e)}"
            )
        except Exception as e:
            return RepeaterResponse(
                status_code=0, headers={}, body="",
                elapsed_time=time.time() - start_time, size=0,
                error=f"Error: {str(e)}"
            )
    
    def send_raw(self, raw_request: str, target_host: str, use_https: bool = True) -> RepeaterResponse:
        """Send a raw HTTP request"""
        try:
            parsed = self._parse_raw_request(raw_request, target_host, use_https)
            return self.send(parsed)
        except Exception as e:
            return RepeaterResponse(
                status_code=0, headers={}, body="",
                elapsed_time=0, size=0,
                error=f"Parse Error: {str(e)}"
            )
    
    def _parse_raw_request(self, raw: str, host: str, use_https: bool) -> RepeaterRequest:
        """Parse raw HTTP request into RepeaterRequest"""
        lines = raw.strip().split('\n')
        first_line = lines[0].strip()
        parts = first_line.split(' ')
        method = parts[0]
        path = parts[1] if len(parts) > 1 else '/'
        
        headers = {}
        body_start = 0
        
        for i, line in enumerate(lines[1:], 1):
            line = line.strip()
            if line == '':
                body_start = i + 1
                break
            if ':' in line:
                key, value = line.split(':', 1)
                headers[key.strip()] = value.strip()
        
        body = '\n'.join(lines[body_start:]) if body_start > 0 and body_start < len(lines) else ''
        
        protocol = 'https' if use_https else 'http'
        url = f"{protocol}://{host}{path}"
        
        return RepeaterRequest(method=method, url=url, headers=headers, body=body)
    
    def _save_to_history(self, req: RepeaterRequest, resp: RepeaterResponse):
        """Save request/response to history"""
        entry = {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "request": asdict(req),
            "response": asdict(resp)
        }
        self.history.append(entry)
    
    def get_history(self) -> list:
        return self.history
    
    def clear_history(self):
        self.history = []

def send_from_history(history_id: int, db_path: str = DB_FILE) -> RepeaterResponse:
    """Resend a request from the history database"""
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    cur.execute(
        "SELECT method, url, request_headers, request_body FROM history WHERE id = ?",
        (history_id,)
    )
    row = cur.fetchone()
    conn.close()
    
    if not row:
        return RepeaterResponse(
            status_code=0, headers={}, body="",
            elapsed_time=0, size=0,
            error=f"Request ID {history_id} not found"
        )
    
    method, url, headers_str, body = row
    
    try:
        headers = json.loads(headers_str) if headers_str else {}
    except:
        headers = {}
    
    repeater = Repeater()
    req = RepeaterRequest(method=method, url=url, headers=headers, body=body or "")
    return repeater.send(req)

# =============================================================================
# INTRUDER MODULE
# =============================================================================
class AttackType(Enum):
    SNIPER = "sniper"
    BATTERING_RAM = "battering_ram"
    PITCHFORK = "pitchfork"
    CLUSTER_BOMB = "cluster_bomb"

@dataclass
class IntruderRequest:
    """Request template for Intruder attacks"""
    method: str
    url: str
    headers: Dict[str, str]
    body: str = ""
    timeout: int = 30
    verify_ssl: bool = False

@dataclass
class IntruderResult:
    """Result of a single Intruder request"""
    payload: str
    payload_position: int
    status_code: int
    response_length: int
    elapsed_time: float
    error: Optional[str] = None
    response_body: str = ""
    response_headers: Dict[str, str] = None
    
    def __post_init__(self):
        if self.response_headers is None:
            self.response_headers = {}

class PayloadGenerator:
    """Generate various types of payloads for attacks"""
    
    @staticmethod
    def from_list(payloads: List[str]) -> List[str]:
        return payloads
    
    @staticmethod
    def from_file(filepath: str) -> List[str]:
        with open(filepath, 'r', encoding='utf-8') as f:
            return [line.strip() for line in f if line.strip()]
    
    @staticmethod
    def numbers(start: int, end: int, step: int = 1) -> List[str]:
        return [str(i) for i in range(start, end + 1, step)]
    
    @staticmethod
    def common_passwords() -> List[str]:
        return [
            "123456", "password", "12345678", "qwerty", "123456789",
            "12345", "1234", "111111", "1234567", "dragon",
            "123123", "baseball", "abc123", "football", "monkey",
            "letmein", "696969", "shadow", "master", "666666",
            "qwertyuiop", "123321", "mustang", "1234567890", "michael",
            "654321", "superman", "1qaz2wsx", "7777777",
            "fuckyou", "121212", "000000", "qazwsx", "123qwe",
            "killer", "trustno1", "jordan", "jennifer", "zxcvbnm",
            "asdfgh", "hunter", "buster", "soccer", "harley",
            "batman", "andrew", "tigger", "sunshine", "iloveyou",
            "2000", "charlie", "robert", "thomas",
            "hockey", "ranger", "daniel", "starwars", "klaster",
            "112233", "george", "asshole", "computer", "michelle",
            "jessica", "pepper", "1111", "zxcvbn", "555555",
            "11111111", "131313", "freedom", "777777", "pass",
            "fuck", "maggie", "159753", "aaaaaa", "ginger",
            "princess", "joshua", "cheese", "amanda", "summer",
            "love", "ashley", "6969", "nicole", "chelsea",
            "biteme", "matthew", "access", "yankees", "987654321",
            "dallas", "austin", "thunder", "taylor", "matrix",
            "admin", "root", "toor", "test", "guest"
        ]
    
    @staticmethod
    def common_usernames() -> List[str]:
        return [
            "admin", "administrator", "root", "user", "test",
            "guest", "info", "adm", "mysql", "oracle",
            "ftp", "pi", "puppet", "ansible", "ec2-user",
            "vagrant", "azureuser", "demo", "ubuntu", "centos",
            "support", "manager", "operator", "backup", "web",
            "www", "www-data", "apache", "nginx", "tomcat"
        ]
    
    @staticmethod
    def sqli_payloads() -> List[str]:
        return [
            "'", "''", "\"", "\"\"",
            "' OR '1'='1", "' OR '1'='1'--", "' OR '1'='1'/*",
            "\" OR \"1\"=\"1", "\" OR \"1\"=\"1\"--",
            "' OR 1=1--", "' OR 1=1#", "' OR 1=1/*",
            "admin'--", "admin'#", "admin'/*",
            "') OR ('1'='1", "') OR ('1'='1'--",
            "1' ORDER BY 1--", "1' ORDER BY 2--", "1' ORDER BY 3--",
            "1' UNION SELECT NULL--", "1' UNION SELECT NULL,NULL--",
            "1; DROP TABLE users--", "1'; DROP TABLE users--",
            "' AND '1'='1", "' AND '1'='2",
            "1 AND 1=1", "1 AND 1=2",
            "' WAITFOR DELAY '0:0:5'--",
            "'; WAITFOR DELAY '0:0:5'--",
            "1; WAITFOR DELAY '0:0:5'--",
            "' AND SLEEP(5)--", "' OR SLEEP(5)--"
        ]
    
    @staticmethod
    def xss_payloads() -> List[str]:
        return [
            "<script>alert('XSS')</script>",
            "<script>alert(1)</script>",
            "<img src=x onerror=alert('XSS')>",
            "<img src=x onerror=alert(1)>",
            "<svg onload=alert('XSS')>",
            "<body onload=alert('XSS')>",
            "javascript:alert('XSS')",
            "<iframe src=\"javascript:alert('XSS')\">",
            "<a href=\"javascript:alert('XSS')\">click</a>",
            "'\"><script>alert('XSS')</script>",
            "'-alert(1)-'",
            "\"-alert(1)-\"",
            "<ScRiPt>alert('XSS')</ScRiPt>",
            "<scr<script>ipt>alert('XSS')</scr</script>ipt>",
            "<<script>alert('XSS');//<</script>",
            "<img src=\"x\" onerror=\"alert('XSS')\">",
            "<div onmouseover=\"alert('XSS')\">hover me</div>",
            "<input onfocus=alert('XSS') autofocus>",
            "<marquee onstart=alert('XSS')>",
            "<video><source onerror=\"alert('XSS')\"></video>"
        ]
    
    @staticmethod
    def path_traversal_payloads() -> List[str]:
        return [
            "../", "..\\", "....//", "....\\\\",
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\config\\sam",
            "....//....//....//etc/passwd",
            "%2e%2e%2f", "%2e%2e/", "..%2f",
            "%2e%2e%5c", "%2e%2e\\", "..%5c",
            "..%252f", "..%255c",
            "/etc/passwd", "/etc/shadow",
            "C:\\Windows\\System32\\config\\SAM",
            "file:///etc/passwd",
            "....//....//....//....//etc/passwd"
        ]

class Intruder:
    """Automated HTTP attack tool - like Burp Intruder"""
    
    POSITION_MARKER = "§"
    
    def __init__(self, threads: int = 10):
        self.threads = threads
        self.results: List[IntruderResult] = []
        self.session = requests.Session()
        self.stop_flag = False
        self.progress_callback = None
    
    def find_positions(self, template: str) -> List[tuple]:
        """Find injection positions marked with §"""
        positions = []
        pattern = re.compile(f'{self.POSITION_MARKER}(.*?){self.POSITION_MARKER}')
        for match in pattern.finditer(template):
            positions.append((match.start(), match.end(), match.group(1)))
        return positions
    
    def replace_position(self, template: str, position_index: int, payload: str) -> str:
        """Replace a specific position with payload"""
        positions = self.find_positions(template)
        if position_index >= len(positions):
            return template
        
        result = template
        for i, (start, end, _) in enumerate(reversed(positions)):
            actual_index = len(positions) - 1 - i
            if actual_index == position_index:
                result = result[:start] + payload + result[end:]
            else:
                result = result[:start] + positions[actual_index][2] + result[end:]
        return result
    
    def replace_all_positions(self, template: str, payload: str) -> str:
        """Replace all positions with the same payload"""
        pattern = re.compile(f'{self.POSITION_MARKER}(.*?){self.POSITION_MARKER}')
        return pattern.sub(payload, template)
    
    def _send_request(self, req: IntruderRequest, payload: str, position: int) -> IntruderResult:
        """Send a single request"""
        start_time = time.time()
        
        try:
            response = self.session.request(
                method=req.method.upper(),
                url=req.url,
                headers=req.headers,
                data=req.body if req.body else None,
                timeout=req.timeout,
                verify=req.verify_ssl
            )
            
            elapsed = time.time() - start_time
            
            return IntruderResult(
                payload=payload,
                payload_position=position,
                status_code=response.status_code,
                response_length=len(response.content),
                elapsed_time=round(elapsed, 3),
                response_body=response.text,
                response_headers=dict(response.headers)
            )
            
        except Exception as e:
            return IntruderResult(
                payload=payload,
                payload_position=position,
                status_code=0,
                response_length=0,
                elapsed_time=time.time() - start_time,
                error=str(e)
            )
    
    def attack_sniper(self, template: IntruderRequest, payloads: List[str]) -> List[IntruderResult]:
        """Sniper attack - one payload at one position at a time"""
        self.results = []
        self.stop_flag = False
        
        all_text = f"{template.url}\n{json.dumps(template.headers)}\n{template.body}"
        positions = self.find_positions(all_text)
        
        total = len(payloads) * len(positions) if positions else len(payloads)
        current = 0
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = []
            
            if positions:
                for pos_index in range(len(positions)):
                    for payload in payloads:
                        if self.stop_flag:
                            break
                        
                        new_url = self.replace_position(template.url, pos_index, payload)
                        new_headers = {k: self.replace_position(v, pos_index, payload) 
                                       for k, v in template.headers.items()}
                        new_body = self.replace_position(template.body, pos_index, payload)
                        
                        req = IntruderRequest(
                            method=template.method,
                            url=new_url,
                            headers=new_headers,
                            body=new_body,
                            timeout=template.timeout,
                            verify_ssl=template.verify_ssl
                        )
                        
                        futures.append(executor.submit(self._send_request, req, payload, pos_index))
            else:
                # No positions found, just send payloads as query params
                for payload in payloads:
                    if self.stop_flag:
                        break
                    req = IntruderRequest(
                        method=template.method,
                        url=template.url,
                        headers=template.headers,
                        body=template.body,
                        timeout=template.timeout,
                        verify_ssl=template.verify_ssl
                    )
                    futures.append(executor.submit(self._send_request, req, payload, 0))
            
            for future in as_completed(futures):
                if self.stop_flag:
                    break
                result = future.result()
                self.results.append(result)
                current += 1
        
        return self.results
    
    def attack_battering_ram(self, template: IntruderRequest, payloads: List[str]) -> List[IntruderResult]:
        """Battering Ram - same payload in all positions"""
        self.results = []
        self.stop_flag = False
        
        total = len(payloads)
        current = 0
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = []
            
            for payload in payloads:
                if self.stop_flag:
                    break
                
                new_url = self.replace_all_positions(template.url, payload)
                new_headers = {k: self.replace_all_positions(v, payload) 
                               for k, v in template.headers.items()}
                new_body = self.replace_all_positions(template.body, payload)
                
                req = IntruderRequest(
                    method=template.method,
                    url=new_url,
                    headers=new_headers,
                    body=new_body,
                    timeout=template.timeout,
                    verify_ssl=template.verify_ssl
                )
                
                futures.append(executor.submit(self._send_request, req, payload, -1))
            
            for future in as_completed(futures):
                if self.stop_flag:
                    break
                result = future.result()
                self.results.append(result)
                current += 1
        
        return self.results
    
    def attack_pitchfork(self, template: IntruderRequest, payload_sets: List[List[str]]) -> List[IntruderResult]:
        """Pitchfork - parallel payloads"""
        self.results = []
        self.stop_flag = False
        
        min_len = min(len(ps) for ps in payload_sets)
        total = min_len
        current = 0
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = []
            
            for i in range(min_len):
                if self.stop_flag:
                    break
                
                new_url = template.url
                new_body = template.body
                new_headers = dict(template.headers)
                
                for pos_index, payload_set in enumerate(payload_sets):
                    payload = payload_set[i]
                    new_url = self.replace_position(new_url, pos_index, payload)
                    new_body = self.replace_position(new_body, pos_index, payload)
                    new_headers = {k: self.replace_position(v, pos_index, payload) 
                                   for k, v in new_headers.items()}
                
                combined_payload = " | ".join(ps[i] for ps in payload_sets)
                
                req = IntruderRequest(
                    method=template.method,
                    url=new_url,
                    headers=new_headers,
                    body=new_body,
                    timeout=template.timeout,
                    verify_ssl=template.verify_ssl
                )
                
                futures.append(executor.submit(self._send_request, req, combined_payload, -1))
            
            for future in as_completed(futures):
                if self.stop_flag:
                    break
                result = future.result()
                self.results.append(result)
                current += 1
        
        return self.results
    
    def attack_cluster_bomb(self, template: IntruderRequest, payload_sets: List[List[str]]) -> List[IntruderResult]:
        """Cluster Bomb - all combinations"""
        self.results = []
        self.stop_flag = False
        
        combinations = list(product(*payload_sets))
        total = len(combinations)
        current = 0
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = []
            
            for combo in combinations:
                if self.stop_flag:
                    break
                
                new_url = template.url
                new_body = template.body
                new_headers = dict(template.headers)
                
                for pos_index, payload in enumerate(combo):
                    new_url = self.replace_position(new_url, pos_index, payload)
                    new_body = self.replace_position(new_body, pos_index, payload)
                    new_headers = {k: self.replace_position(v, pos_index, payload) 
                                   for k, v in new_headers.items()}
                
                combined_payload = " | ".join(combo)
                
                req = IntruderRequest(
                    method=template.method,
                    url=new_url,
                    headers=new_headers,
                    body=new_body,
                    timeout=template.timeout,
                    verify_ssl=template.verify_ssl
                )
                
                futures.append(executor.submit(self._send_request, req, combined_payload, -1))
            
            for future in as_completed(futures):
                if self.stop_flag:
                    break
                result = future.result()
                self.results.append(result)
                current += 1
        
        return self.results
    
    def stop(self):
        """Stop the attack"""
        self.stop_flag = True
    
    def get_results(self) -> List[IntruderResult]:
        return self.results
    
    def get_results_summary(self) -> Dict[str, Any]:
        """Get summary of results"""
        if not self.results:
            return {}
        
        status_codes = {}
        lengths = []
        times = []
        errors = 0
        
        for r in self.results:
            if r.error:
                errors += 1
            else:
                status_codes[r.status_code] = status_codes.get(r.status_code, 0) + 1
                lengths.append(r.response_length)
                times.append(r.elapsed_time)
        
        return {
            "total_requests": len(self.results),
            "errors": errors,
            "status_codes": status_codes,
            "avg_length": sum(lengths) / len(lengths) if lengths else 0,
            "avg_time": sum(times) / len(times) if times else 0,
            "min_length": min(lengths) if lengths else 0,
            "max_length": max(lengths) if lengths else 0
        }
    
    def filter_results(self, status_code: int = None, min_length: int = None, 
                       max_length: int = None, contains: str = None) -> List[IntruderResult]:
        """Filter results"""
        filtered = self.results
        
        if status_code:
            filtered = [r for r in filtered if r.status_code == status_code]
        if min_length:
            filtered = [r for r in filtered if r.response_length >= min_length]
        if max_length:
            filtered = [r for r in filtered if r.response_length <= max_length]
        if contains:
            filtered = [r for r in filtered if contains in r.response_body]
        
        return filtered

# =============================================================================
# MITMPROXY ADDONS
# =============================================================================
if MITMPROXY_AVAILABLE:
    class InterceptModeAddon:
        """Interactive intercept mode - allows Allow/Drop/Edit from terminal"""
        
        def __init__(self):
            self.enabled = True
            self.excluded_hosts = [
                "127.0.0.1",
                "localhost",
                "0.0.0.0",
            ]
            self.excluded_ports = [
                5050,  # Dashboard port
            ]
            self.excluded_patterns = [
                r"/api/traffic",
                r"/api/request/",
                r"/api/response/",
                r"/api/clear-requests",
                r"/api/repeater/",
                r"/api/intruder/",
                r"/ws/terminal",
                r"/ws/intruder",
            ]
        
        def should_intercept(self, flow: http.HTTPFlow) -> bool:
            host = flow.request.host
            port = flow.request.port
            path = flow.request.path
            
            if host in self.excluded_hosts:
                return False
            if port in self.excluded_ports:
                return False
            for pattern in self.excluded_patterns:
                if re.search(pattern, path):
                    return False
            return True
        
        def request(self, flow: http.HTTPFlow):
            if not self.enabled:
                return
            
            if not self.should_intercept(flow):
                return
            
            print("\n" + "=" * 50)
            print(" INTERCEPTED REQUEST ")
            print("=" * 50)
            print(f"URL     : {flow.request.url}")
            print(f"METHOD  : {flow.request.method}")
            print("HEADERS :")
            for k, v in flow.request.headers.items():
                print(f"   {k}: {v}")
            
            if flow.request.text:
                print("\nBODY:")
                print(flow.request.text)
            
            print("\n" + "=" * 50)
            print("[A] Allow")
            print("[D] Drop")
            print("[E] Edit request")
            print("[S] Skip (auto-allow all from this host)")
            print("=" * 50)
            
            try:
                choice = input("Your action: ").strip().lower()
                
                if choice == "a":
                    print("Request forwarded.")
                    return
                elif choice == "d":
                    print("Request dropped.")
                    flow.response = http.Response.make(403, b"Request Dropped by Proxy")
                    return
                elif choice == "e":
                    print("\n--- Edit Mode ---")
                    new_url = input("New URL (press Enter to keep): ").strip()
                    if new_url:
                        flow.request.url = new_url
                    new_body = input("New Body (press Enter to keep): ").strip()
                    if new_body:
                        flow.request.text = new_body
                    print("Request after editing will be forwarded.")
                    return
                elif choice == "s":
                    self.excluded_hosts.append(flow.request.host)
                    print(f"Added {flow.request.host} to excluded hosts.")
                    return
                else:
                    print("Invalid choice - auto forward.")
                    return
            except EOFError:
                # Handle non-interactive mode
                print("Running in non-interactive mode - auto forwarding.")
                return
    
    class ProxyLoggerAddon:
        """Logs all traffic to SQLite database"""
        
        def __init__(self):
            self.method = None
            self.url = None
            self.req_headers = None
            self.req_body = None
        
        def request(self, flow: http.HTTPFlow):
            self.method = flow.request.method
            self.url = flow.request.url
            self.req_headers = json.dumps(dict(flow.request.headers), ensure_ascii=False)
            self.req_body = flow.request.text if flow.request.text else ""
        
        def response(self, flow: http.HTTPFlow):
            conn = sqlite3.connect(DB_FILE)
            c = conn.cursor()
            c.execute("""
                INSERT INTO history (method, url, status_code, request_headers, 
                                     request_body, response_headers, response_body, time)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
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
    
    class InterceptAddon:
        """Basic request/response interceptor"""
        
        def request(self, flow: http.HTTPFlow):
            print(f"[REQUEST] {flow.request.method} {flow.request.url}")
            flow.request.headers["X-Proxy-Intercept"] = "RedKit-Proxy"
        
        def response(self, flow: http.HTTPFlow):
            print(f"[RESPONSE] {flow.response.status_code} from {flow.request.url}")
    
    class RewriteEngineAddon:
        """URL/Header/Body rewrite engine"""
        
        def __init__(self):
            self.rules = []
            self._load_rules()
        
        def _load_rules(self):
            try:
                with open("rewrite_rules.json", "r") as f:
                    self.rules = json.load(f)
            except FileNotFoundError:
                self.rules = []
        
        def request(self, flow: http.HTTPFlow):
            url = flow.request.url
            
            for rule in self.rules:
                if rule.get("match", "") in url:
                    if "replace_url" in rule:
                        print(f"[Rewrite] URL → {rule['replace_url']}")
                        flow.request.url = rule["replace_url"]
                    
                    if "replace_header" in rule:
                        for k, v in rule["replace_header"].items():
                            print(f"[Rewrite] Header {k} → {v}")
                            flow.request.headers[k] = v
                    
                    if "replace_body" in rule:
                        print("[Rewrite] Body replaced")
                        flow.request.text = rule["replace_body"]
        
        def response(self, flow: http.HTTPFlow):
            url = flow.request.url
            
            for rule in self.rules:
                if rule.get("match", "") in url:
                    if "replace_response_body" in rule:
                        print("[Rewrite] Response Body replaced")
                        flow.response.text = rule["replace_response_body"]
    
    # Expose addons for mitmproxy
    addons = [
        InterceptModeAddon(),  # Interactive intercept (Allow/Drop/Edit)
        ProxyLoggerAddon(),     # Log to database
        InterceptAddon(),       # Basic logging
        RewriteEngineAddon()    # URL/Header/Body rewrite rules
    ]

# =============================================================================
# FASTAPI APPLICATION
# =============================================================================
app = FastAPI(title="RedKit Proxy Dashboard", version="3.0")

# Enable CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global instances
repeater_instance = Repeater()
intruder_instance = Intruder(threads=10)

# =============================================================================
# PYDANTIC MODELS
# =============================================================================
class RepeaterSendRequest(BaseModel):
    method: str
    url: str
    headers: Dict[str, str] = {}
    body: str = ""
    timeout: int = 30
    follow_redirects: bool = True
    verify_ssl: bool = False

class RepeaterFromHistoryRequest(BaseModel):
    history_id: int

class RepeaterRawRequest(BaseModel):
    raw_request: str
    target_host: str
    use_https: bool = True

class IntruderAttackRequest(BaseModel):
    method: str
    url: str
    headers: Dict[str, str] = {}
    body: str = ""
    attack_type: str = "sniper"
    payloads: List[str] = []
    payload_sets: List[List[str]] = []
    threads: int = 10
    timeout: int = 30

class IntruderPayloadRequest(BaseModel):
    payload_type: str
    start: int = 0
    end: int = 100
    step: int = 1
    filepath: str = ""

# =============================================================================
# DATABASE HELPERS
# =============================================================================
def fetch_all_requests():
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    cur.execute("SELECT id, method, url, status_code, time FROM history ORDER BY id DESC")
    rows = cur.fetchall()
    conn.close()
    return rows

def fetch_request(req_id: int):
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    cur.execute("SELECT method, url, request_headers, request_body, time FROM history WHERE id = ?", (req_id,))
    row = cur.fetchone()
    conn.close()
    return row

def fetch_response(req_id: int):
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    cur.execute("SELECT status_code, response_headers, response_body FROM history WHERE id = ?", (req_id,))
    row = cur.fetchone()
    conn.close()
    return row

# =============================================================================
# TRAFFIC ENDPOINTS
# =============================================================================
@app.get("/api/traffic")
def api_traffic():
    return JSONResponse({"data": fetch_all_requests()})

@app.get("/api/request/{req_id}")
def api_request(req_id: int):
    data = fetch_request(req_id)
    return JSONResponse({"data": data})

@app.get("/api/response/{req_id}")
def api_response(req_id: int):
    data = fetch_response(req_id)
    return JSONResponse({"data": data})

@app.delete("/api/clear-requests")
def clear_requests():
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    cur.execute("DELETE FROM history")
    conn.commit()
    conn.close()
    return JSONResponse({"message": "All requests cleared"})

# =============================================================================
# REPEATER ENDPOINTS
# =============================================================================
@app.post("/api/repeater/send")
def repeater_send(req: RepeaterSendRequest):
    try:
        print(f"[Repeater] Sending {req.method} to {req.url}")
        
        repeater_req = RepeaterRequest(
            method=req.method,
            url=req.url,
            headers=req.headers,
            body=req.body,
            timeout=req.timeout,
            follow_redirects=req.follow_redirects,
            verify_ssl=req.verify_ssl
        )
        
        response = repeater_instance.send(repeater_req)
        
        print(f"[Repeater] Response: {response.status_code}, Error: {response.error}")
        
        return JSONResponse({
            "success": response.error is None,
            "data": {
                "status_code": response.status_code,
                "headers": response.headers,
                "body": response.body,
                "elapsed_time": response.elapsed_time,
                "size": response.size,
                "error": response.error
            }
        })
    except Exception as e:
        print(f"[Repeater] Exception: {str(e)}")
        return JSONResponse({
            "success": False,
            "data": {
                "status_code": 0,
                "headers": {},
                "body": "",
                "elapsed_time": 0,
                "size": 0,
                "error": str(e)
            }
        })

@app.post("/api/repeater/send-from-history")
def repeater_send_from_history(req: RepeaterFromHistoryRequest):
    response = send_from_history(req.history_id, DB_FILE)
    
    return JSONResponse({
        "success": response.error is None,
        "data": {
            "status_code": response.status_code,
            "headers": response.headers,
            "body": response.body,
            "elapsed_time": response.elapsed_time,
            "size": response.size,
            "error": response.error
        }
    })

@app.post("/api/repeater/send-raw")
def repeater_send_raw(req: RepeaterRawRequest):
    response = repeater_instance.send_raw(req.raw_request, req.target_host, req.use_https)
    
    return JSONResponse({
        "success": response.error is None,
        "data": {
            "status_code": response.status_code,
            "headers": response.headers,
            "body": response.body,
            "elapsed_time": response.elapsed_time,
            "size": response.size,
            "error": response.error
        }
    })

@app.get("/api/repeater/history")
def repeater_history():
    return JSONResponse({"data": repeater_instance.get_history()})

@app.delete("/api/repeater/clear-history")
def repeater_clear_history():
    repeater_instance.clear_history()
    return JSONResponse({"message": "Repeater history cleared"})

# =============================================================================
# INTRUDER ENDPOINTS
# =============================================================================
@app.post("/api/intruder/attack")
async def intruder_attack(req: IntruderAttackRequest, background_tasks: BackgroundTasks):
    global intruder_instance
    intruder_instance = Intruder(threads=req.threads)
    
    template = IntruderRequest(
        method=req.method,
        url=req.url,
        headers=req.headers,
        body=req.body,
        timeout=req.timeout
    )
    
    attack_type = req.attack_type.lower()
    
    if attack_type == "sniper":
        results = intruder_instance.attack_sniper(template, req.payloads)
    elif attack_type == "battering_ram":
        results = intruder_instance.attack_battering_ram(template, req.payloads)
    elif attack_type == "pitchfork":
        results = intruder_instance.attack_pitchfork(template, req.payload_sets)
    elif attack_type == "cluster_bomb":
        results = intruder_instance.attack_cluster_bomb(template, req.payload_sets)
    else:
        return JSONResponse({"error": f"Unknown attack type: {attack_type}"}, status_code=400)
    
    results_data = []
    for r in results:
        results_data.append({
            "payload": r.payload,
            "position": r.payload_position,
            "status_code": r.status_code,
            "length": r.response_length,
            "time": r.elapsed_time,
            "error": r.error
        })
    
    summary = intruder_instance.get_results_summary()
    
    return JSONResponse({
        "success": True,
        "total_requests": len(results),
        "summary": summary,
        "results": results_data
    })

@app.get("/api/intruder/results")
def intruder_results():
    results = intruder_instance.get_results()
    
    results_data = []
    for r in results:
        results_data.append({
            "payload": r.payload,
            "position": r.payload_position,
            "status_code": r.status_code,
            "length": r.response_length,
            "time": r.elapsed_time,
            "error": r.error,
            "response_body": r.response_body[:500] if r.response_body else ""
        })
    
    return JSONResponse({
        "total": len(results),
        "summary": intruder_instance.get_results_summary(),
        "results": results_data
    })

@app.get("/api/intruder/result/{index}")
def intruder_result_detail(index: int):
    results = intruder_instance.get_results()
    
    if index < 0 or index >= len(results):
        return JSONResponse({"error": "Index out of range"}, status_code=404)
    
    r = results[index]
    return JSONResponse({
        "payload": r.payload,
        "position": r.payload_position,
        "status_code": r.status_code,
        "length": r.response_length,
        "time": r.elapsed_time,
        "error": r.error,
        "response_body": r.response_body,
        "response_headers": r.response_headers
    })

@app.post("/api/intruder/stop")
def intruder_stop():
    intruder_instance.stop()
    return JSONResponse({"message": "Attack stopped"})

@app.post("/api/intruder/payloads/generate")
def intruder_generate_payloads(req: IntruderPayloadRequest):
    payload_type = req.payload_type.lower()
    
    if payload_type == "passwords":
        payloads = PayloadGenerator.common_passwords()
    elif payload_type == "usernames":
        payloads = PayloadGenerator.common_usernames()
    elif payload_type == "sqli":
        payloads = PayloadGenerator.sqli_payloads()
    elif payload_type == "xss":
        payloads = PayloadGenerator.xss_payloads()
    elif payload_type == "path_traversal":
        payloads = PayloadGenerator.path_traversal_payloads()
    elif payload_type == "numbers":
        payloads = PayloadGenerator.numbers(req.start, req.end, req.step)
    elif payload_type == "file":
        try:
            payloads = PayloadGenerator.from_file(req.filepath)
        except Exception as e:
            return JSONResponse({"error": str(e)}, status_code=400)
    else:
        return JSONResponse({"error": f"Unknown payload type: {payload_type}"}, status_code=400)
    
    return JSONResponse({
        "type": payload_type,
        "count": len(payloads),
        "payloads": payloads
    })

@app.get("/api/intruder/payloads/types")
def intruder_payload_types():
    return JSONResponse({
        "types": [
            {"id": "passwords", "name": "Common Passwords", "count": len(PayloadGenerator.common_passwords())},
            {"id": "usernames", "name": "Common Usernames", "count": len(PayloadGenerator.common_usernames())},
            {"id": "sqli", "name": "SQL Injection", "count": len(PayloadGenerator.sqli_payloads())},
            {"id": "xss", "name": "XSS Payloads", "count": len(PayloadGenerator.xss_payloads())},
            {"id": "path_traversal", "name": "Path Traversal", "count": len(PayloadGenerator.path_traversal_payloads())},
            {"id": "numbers", "name": "Number Range", "count": "dynamic"},
            {"id": "file", "name": "From File", "count": "dynamic"}
        ]
    })

@app.post("/api/intruder/filter")
def intruder_filter_results(
    status_code: int = None,
    min_length: int = None,
    max_length: int = None,
    contains: str = None
):
    filtered = intruder_instance.filter_results(
        status_code=status_code,
        min_length=min_length,
        max_length=max_length,
        contains=contains
    )
    
    results_data = []
    for r in filtered:
        results_data.append({
            "payload": r.payload,
            "status_code": r.status_code,
            "length": r.response_length,
            "time": r.elapsed_time
        })
    
    return JSONResponse({
        "filtered_count": len(filtered),
        "results": results_data
    })

# =============================================================================
# WEBSOCKET ENDPOINTS
# =============================================================================
@app.websocket("/ws/intruder")
async def websocket_intruder(ws: WebSocket):
    await ws.accept()
    
    try:
        while True:
            results = intruder_instance.get_results()
            summary = intruder_instance.get_results_summary()
            
            await ws.send_json({
                "total": len(results),
                "summary": summary,
                "latest": [
                    {
                        "payload": r.payload,
                        "status_code": r.status_code,
                        "length": r.response_length
                    } for r in results[-10:]
                ]
            })
            
            await asyncio.sleep(1)
            
    except Exception:
        pass

@app.websocket("/ws/terminal")
async def websocket_terminal(ws: WebSocket):
    await ws.accept()
    await ws.send_text("Connected to RedKit Terminal\n$ ")
    
    try:
        while True:
            cmd = await ws.receive_text()
            cmd = cmd.strip()
            
            if cmd == "":
                await ws.send_text("$ ")
                continue
            
            try:
                process = subprocess.Popen(
                    shlex.split(cmd),
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True
                )
                stdout, stderr = process.communicate()
                
                output = stdout
                if stderr:
                    output += "\n" + stderr
                
            except Exception as e:
                output = f"Error executing command: {str(e)}"
            
            await ws.send_text(output + "\n$ ")
            
    except Exception:
        pass

# =============================================================================
# FRONTEND ROUTE
# =============================================================================
@app.get("/", response_class=HTMLResponse)
def dashboard():
    try:
        with open("index.html", "r", encoding="utf-8") as f:
            return f.read()
    except FileNotFoundError:
        return """
        <html>
        <head><title>RedKit Proxy</title></head>
        <body style="background:#0f0f0f;color:#e5e5e5;font-family:monospace;padding:40px;">
            <h1>RedKit Proxy Dashboard</h1>
            <p style="color:#ef4444;">index.html not found!</p>
            <p>Please make sure index.html is in the same directory as backend.py</p>
            <h2>API is still running. Available Endpoints:</h2>
            <ul>
                <li><a href="/docs" style="color:#3b82f6;">/docs</a> - API Documentation</li>
                <li>/api/traffic - Get all traffic</li>
                <li>/api/repeater/send - Send request via Repeater</li>
                <li>/api/intruder/attack - Start Intruder attack</li>
            </ul>
        </body>
        </html>
        """

# =============================================================================
# MAIN
# =============================================================================
if __name__ == "__main__":
    print("=" * 60)
    print("  RedKit Proxy Dashboard v3.0")
    print("=" * 60)
    print("\n[+] Starting API server on http://0.0.0.0:5050")
    print("[+] Features: Proxy, Repeater, Intruder, Terminal")
    print("[+] Database: proxy_history.db")
    print("\n[!] To capture traffic, run mitmproxy with:")
    print("    mitmdump -s backend.py -p 8080")
    print("\n[*] Dashboard available at: http://localhost:5050")
    print("=" * 60 + "\n")
    
    uvicorn.run(app, host="0.0.0.0", port=5050)
