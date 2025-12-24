from fastapi import FastAPI, WebSocket
from fastapi.responses import JSONResponse, HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
import sqlite3
import subprocess
import shlex
import uvicorn

app = FastAPI(title="MITM Proxy Dashboard", version="2.0")

# ------------ Enable CORS ------------
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

DB = "proxy_history.db"

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


# ------------ API ENDPOINTS ------------

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


# ------------ NEW: WebSocket Terminal ------------

@app.websocket("/ws/terminal")
async def websocket_terminal(ws: WebSocket):
    await ws.accept()
    await ws.send_text("Connected to Python Web Terminal\n$ ")

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
    with open("index.html", "r", encoding="utf-8") as f:
        return f.read()


# ------------ Run Server ------------

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=5050)

