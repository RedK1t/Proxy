from fastapi import FastAPI, WebSocket, BackgroundTasks
from fastapi.responses import JSONResponse, HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional, List, Dict, Any
import sqlite3
import subprocess
import shlex
import uvicorn
import json
import asyncio

# استيراد الـ Repeater و Intruder
try:
    from repeater import Repeater, RepeaterRequest, RepeaterResponse, send_from_history
    from intruder import Intruder, IntruderRequest, PayloadGenerator, AttackType
    print("[OK] Repeater and Intruder modules loaded successfully")
except ImportError as e:
    print(f"[ERROR] Failed to import modules: {e}")
    print("[INFO] Make sure repeater.py and intruder.py are in the same directory")
    raise

app = FastAPI(title="RedKit Proxy Dashboard", version="3.0")

# ------------ Enable CORS ------------
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

DB = "proxy_history.db"

# ------------ Global Instances ------------
repeater_instance = Repeater()
intruder_instance = Intruder(threads=10)

# ------------ Pydantic Models ------------

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
    attack_type: str = "sniper"  # sniper, battering_ram, pitchfork, cluster_bomb
    payloads: List[str] = []
    payload_sets: List[List[str]] = []  # للـ pitchfork و cluster_bomb
    threads: int = 10
    timeout: int = 30


class IntruderPayloadRequest(BaseModel):
    payload_type: str  # passwords, usernames, sqli, xss, path_traversal, numbers, file
    # للـ numbers
    start: int = 0
    end: int = 100
    step: int = 1
    # للـ file
    filepath: str = ""


# ------------ Database Helpers ------------

def fetch_all_requests():
    conn = sqlite3.connect(DB)
    cur = conn.cursor()
    cur.execute("SELECT id, method, url, status_code, time FROM history ORDER BY id DESC")
    rows = cur.fetchall()
    conn.close()
    return rows


def fetch_request(req_id: int):
    conn = sqlite3.connect(DB)
    cur = conn.cursor()
    cur.execute("SELECT method, url, request_headers, request_body, time FROM history WHERE id = ?", (req_id,))
    row = cur.fetchone()
    conn.close()
    return row


def fetch_response(req_id: int):
    conn = sqlite3.connect(DB)
    cur = conn.cursor()
    cur.execute("SELECT status_code, response_headers, response_body FROM history WHERE id = ?", (req_id,))
    row = cur.fetchone()
    conn.close()
    return row


# ------------ Original API ENDPOINTS ------------

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
    conn = sqlite3.connect(DB)
    cur = conn.cursor()
    cur.execute("DELETE FROM history")
    conn.commit()
    conn.close()
    return JSONResponse({"message": "All requests cleared"})


# ============================================================
#                    REPEATER ENDPOINTS
# ============================================================

@app.post("/api/repeater/send")
def repeater_send(req: RepeaterSendRequest):
    """
    إرسال request جديد عبر الـ Repeater
    """
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
    """
    إرسال request من الـ history
    """
    response = send_from_history(req.history_id, DB)
    
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
    """
    إرسال raw HTTP request
    """
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
    """
    الحصول على history الـ Repeater
    """
    return JSONResponse({
        "data": repeater_instance.get_history()
    })


@app.delete("/api/repeater/clear-history")
def repeater_clear_history():
    """
    مسح history الـ Repeater
    """
    repeater_instance.clear_history()
    return JSONResponse({"message": "Repeater history cleared"})


# ============================================================
#                    INTRUDER ENDPOINTS
# ============================================================

@app.post("/api/intruder/attack")
async def intruder_attack(req: IntruderAttackRequest, background_tasks: BackgroundTasks):
    """
    بدء هجوم Intruder
    """
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
    
    # تحويل النتائج
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


@app.post("/api/intruder/attack-async")
async def intruder_attack_async(req: IntruderAttackRequest):
    """
    بدء هجوم Intruder بشكل async (للهجمات الكبيرة)
    يرجع task_id للمتابعة
    """
    global intruder_instance
    intruder_instance = Intruder(threads=req.threads)
    
    # TODO: implement async attack with task tracking
    return JSONResponse({
        "message": "Async attack started",
        "task_id": "task_001"
    })


@app.get("/api/intruder/results")
def intruder_results():
    """
    الحصول على نتائج آخر هجوم
    """
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
    """
    تفاصيل نتيجة معينة
    """
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
    """
    إيقاف الهجوم الحالي
    """
    intruder_instance.stop()
    return JSONResponse({"message": "Attack stopped"})


@app.post("/api/intruder/payloads/generate")
def intruder_generate_payloads(req: IntruderPayloadRequest):
    """
    توليد payloads جاهزة
    """
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
    """
    قائمة أنواع الـ payloads المتاحة
    """
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
    """
    فلترة نتائج الهجوم
    """
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


# ------------ WebSocket for Real-time Intruder Updates ------------

@app.websocket("/ws/intruder")
async def websocket_intruder(ws: WebSocket):
    """
    WebSocket للحصول على تحديثات الهجوم في الوقت الفعلي
    """
    await ws.accept()
    
    try:
        while True:
            # إرسال آخر النتائج كل ثانية
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
                    } for r in results[-10:]  # آخر 10 نتائج
                ]
            })
            
            await asyncio.sleep(1)
            
    except Exception:
        pass


# ------------ WebSocket Terminal ------------

@app.websocket("/ws/terminal")
async def websocket_terminal(ws: WebSocket):
    await ws.accept()
    await ws.send_text("Connected to RedKit Terminal\n$ ")

    try:
        while True:
            cmd = await ws.receive_text()
            cmd = cmd.strip()

            # Empty command
            if cmd == "":
                await ws.send_text("$ ")
                continue

            # Execute system command
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


# ------------ Serve Modern UI ------------

@app.get("/", response_class=HTMLResponse)
def dashboard():
    try:
        with open("index.html", "r", encoding="utf-8") as f:
            return f.read()
    except FileNotFoundError:
        return """
        <html>
        <head><title>RedKit Proxy</title></head>
        <body>
            <h1>RedKit Proxy Dashboard</h1>
            <p>index.html not found. API is running.</p>
            <h2>Available Endpoints:</h2>
            <ul>
                <li><a href="/docs">/docs</a> - API Documentation</li>
                <li>/api/traffic - Get all traffic</li>
                <li>/api/repeater/send - Send request via Repeater</li>
                <li>/api/intruder/attack - Start Intruder attack</li>
            </ul>
        </body>
        </html>
        """


# ------------ Run Server ------------

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=5050)
