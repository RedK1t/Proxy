"""
Repeater Module - مثل Burp Suite Repeater
يسمح بإعادة إرسال الـ requests مع التعديل عليها
"""

import requests
import json
import urllib3
from typing import Optional, Dict, Any
from dataclasses import dataclass, asdict
import time

# تعطيل تحذيرات SSL
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


@dataclass
class RepeaterRequest:
    """كلاس لتمثيل الـ Request"""
    method: str
    url: str
    headers: Dict[str, str]
    body: str = ""
    timeout: int = 30
    follow_redirects: bool = True
    verify_ssl: bool = False


@dataclass
class RepeaterResponse:
    """كلاس لتمثيل الـ Response"""
    status_code: int
    headers: Dict[str, str]
    body: str
    elapsed_time: float  # بالثواني
    size: int  # حجم الـ response بالبايت
    error: Optional[str] = None


class Repeater:
    """
    Repeater Class
    يسمح بإعادة إرسال HTTP requests مع إمكانية التعديل
    """
    
    def __init__(self):
        self.history: list = []
        self.session = requests.Session()
    
    def send(self, req: RepeaterRequest) -> RepeaterResponse:
        """
        إرسال request وإرجاع الـ response
        """
        start_time = time.time()
        
        try:
            # تحضير الـ headers
            headers = req.headers.copy() if req.headers else {}
            
            # إرسال الـ request
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
            
            # بناء الـ response object
            resp = RepeaterResponse(
                status_code=response.status_code,
                headers=dict(response.headers),
                body=response.text,
                elapsed_time=round(elapsed, 3),
                size=len(response.content)
            )
            
            # حفظ في الـ history
            self._save_to_history(req, resp)
            
            return resp
            
        except requests.exceptions.Timeout:
            return RepeaterResponse(
                status_code=0,
                headers={},
                body="",
                elapsed_time=time.time() - start_time,
                size=0,
                error="Request Timeout"
            )
        except requests.exceptions.ConnectionError as e:
            return RepeaterResponse(
                status_code=0,
                headers={},
                body="",
                elapsed_time=time.time() - start_time,
                size=0,
                error=f"Connection Error: {str(e)}"
            )
        except Exception as e:
            return RepeaterResponse(
                status_code=0,
                headers={},
                body="",
                elapsed_time=time.time() - start_time,
                size=0,
                error=f"Error: {str(e)}"
            )
    
    def send_raw(self, raw_request: str, target_host: str, use_https: bool = True) -> RepeaterResponse:
        """
        إرسال raw HTTP request
        مفيد لما تنسخ request من الـ proxy مباشرة
        """
        try:
            parsed = self._parse_raw_request(raw_request, target_host, use_https)
            return self.send(parsed)
        except Exception as e:
            return RepeaterResponse(
                status_code=0,
                headers={},
                body="",
                elapsed_time=0,
                size=0,
                error=f"Parse Error: {str(e)}"
            )
    
    def _parse_raw_request(self, raw: str, host: str, use_https: bool) -> RepeaterRequest:
        """
        تحويل raw HTTP request إلى RepeaterRequest object
        """
        lines = raw.strip().split('\n')
        
        # أول سطر فيه الـ method و path
        first_line = lines[0].strip()
        parts = first_line.split(' ')
        method = parts[0]
        path = parts[1] if len(parts) > 1 else '/'
        
        # الـ headers
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
        
        # الـ body
        body = '\n'.join(lines[body_start:]) if body_start > 0 and body_start < len(lines) else ''
        
        # بناء الـ URL
        protocol = 'https' if use_https else 'http'
        url = f"{protocol}://{host}{path}"
        
        return RepeaterRequest(
            method=method,
            url=url,
            headers=headers,
            body=body
        )
    
    def _save_to_history(self, req: RepeaterRequest, resp: RepeaterResponse):
        """حفظ الـ request/response في الـ history"""
        entry = {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "request": asdict(req),
            "response": asdict(resp)
        }
        self.history.append(entry)
    
    def get_history(self) -> list:
        """إرجاع الـ history"""
        return self.history
    
    def clear_history(self):
        """مسح الـ history"""
        self.history = []
    
    def export_history(self, filename: str):
        """تصدير الـ history لملف JSON"""
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(self.history, f, ensure_ascii=False, indent=2)
    
    def compare_responses(self, resp1: RepeaterResponse, resp2: RepeaterResponse) -> Dict[str, Any]:
        """
        مقارنة بين response اتنين
        مفيد لاكتشاف الفروقات
        """
        return {
            "status_code_match": resp1.status_code == resp2.status_code,
            "size_diff": resp2.size - resp1.size,
            "time_diff": round(resp2.elapsed_time - resp1.elapsed_time, 3),
            "body_match": resp1.body == resp2.body,
            "headers_diff": {
                "only_in_first": set(resp1.headers.keys()) - set(resp2.headers.keys()),
                "only_in_second": set(resp2.headers.keys()) - set(resp1.headers.keys())
            }
        }


# ============ Helper Functions للاستخدام السريع ============

def quick_send(method: str, url: str, headers: dict = None, body: str = "") -> RepeaterResponse:
    """
    إرسال سريع لـ request
    """
    repeater = Repeater()
    req = RepeaterRequest(
        method=method,
        url=url,
        headers=headers or {},
        body=body
    )
    return repeater.send(req)


def send_from_history(history_id: int, db_path: str = "proxy_history.db") -> RepeaterResponse:
    """
    إرسال request من الـ history database
    """
    import sqlite3
    
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
            status_code=0,
            headers={},
            body="",
            elapsed_time=0,
            size=0,
            error=f"Request ID {history_id} not found"
        )
    
    method, url, headers_str, body = row
    
    # تحويل الـ headers من string لـ dict
    try:
        headers = json.loads(headers_str) if headers_str else {}
    except:
        headers = {}
    
    repeater = Repeater()
    req = RepeaterRequest(
        method=method,
        url=url,
        headers=headers,
        body=body or ""
    )
    return repeater.send(req)


# ============ CLI Interface ============

if __name__ == "__main__":
    print("=" * 50)
    print("  RedKit Repeater - Manual Request Sender")
    print("=" * 50)
    
    repeater = Repeater()
    
    while True:
        print("\n[1] Send new request")
        print("[2] Send from history DB")
        print("[3] Send raw request")
        print("[4] View repeater history")
        print("[5] Exit")
        
        choice = input("\nChoice: ").strip()
        
        if choice == "1":
            method = input("Method (GET/POST/PUT/DELETE): ").strip().upper()
            url = input("URL: ").strip()
            
            headers = {}
            print("Headers (empty line to finish):")
            while True:
                h = input("  Header (Key: Value): ").strip()
                if not h:
                    break
                if ':' in h:
                    k, v = h.split(':', 1)
                    headers[k.strip()] = v.strip()
            
            body = ""
            if method in ["POST", "PUT", "PATCH"]:
                body = input("Body: ").strip()
            
            req = RepeaterRequest(method=method, url=url, headers=headers, body=body)
            print("\n⏳ Sending...")
            resp = repeater.send(req)
            
            print(f"\n✅ Status: {resp.status_code}")
            print(f"⏱️  Time: {resp.elapsed_time}s")
            print(f"📦 Size: {resp.size} bytes")
            if resp.error:
                print(f"❌ Error: {resp.error}")
            else:
                print(f"\n--- Response Body ---\n{resp.body[:500]}...")
        
        elif choice == "2":
            req_id = input("Request ID from history: ").strip()
            if req_id.isdigit():
                print("\n⏳ Sending...")
                resp = send_from_history(int(req_id))
                print(f"\n✅ Status: {resp.status_code}")
                print(f"⏱️  Time: {resp.elapsed_time}s")
                if resp.error:
                    print(f"❌ Error: {resp.error}")
        
        elif choice == "3":
            host = input("Target Host (e.g., example.com): ").strip()
            use_https = input("Use HTTPS? (y/n): ").strip().lower() == 'y'
            print("Paste raw request (empty line to finish):")
            lines = []
            while True:
                line = input()
                if line == "":
                    break
                lines.append(line)
            raw = '\n'.join(lines)
            
            print("\n⏳ Sending...")
            resp = repeater.send_raw(raw, host, use_https)
            print(f"\n✅ Status: {resp.status_code}")
            print(f"⏱️  Time: {resp.elapsed_time}s")
        
        elif choice == "4":
            history = repeater.get_history()
            print(f"\n📜 History ({len(history)} entries):")
            for i, entry in enumerate(history):
                req = entry['request']
                resp = entry['response']
                print(f"  [{i}] {req['method']} {req['url'][:50]} → {resp['status_code']}")
        
        elif choice == "5":
            print("👋 Bye!")
            break
