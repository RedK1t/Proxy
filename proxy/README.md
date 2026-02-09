# RedKit Proxy

Lightweight mitmproxy-based proxy addons + FastAPI dashboard with **Repeater** and **Intruder** tools (Burp Suite style).

## Features

### Core Proxy Addons
| Addon | Description |
|-------|-------------|
| `intercept_proxy.py` | Request/Response interception with header/body modifications |
| `proxy_logger.py` | Logs all traffic to SQLite database |
| `rewrite_engine.py` | URL/Header/Body rewrite rules from JSON config |
| `intercept_mode.py` | Interactive CLI for Allow/Drop/Edit requests |
| `logging_addon.py` | JSON log file output |
| `history_addon.py` | Lightweight SQLite history inserter |

### New Tools

#### Repeater
Manual request sender - resend and modify HTTP requests on the fly.

**Features:**
- Send custom HTTP requests with full control
- Resend requests from proxy history
- Parse and send raw HTTP requests
- Compare responses
- Export history to JSON

#### Intruder
Automated attack tool for fuzzing and brute-forcing.

**Attack Types:**
| Type | Description |
|------|-------------|
| **Sniper** | Single payload in one position at a time |
| **Battering Ram** | Same payload in all positions |
| **Pitchfork** | Parallel payloads (1st with 1st, 2nd with 2nd, etc.) |
| **Cluster Bomb** | All possible payload combinations |

**Built-in Payloads:**
- Common passwords
- Common usernames
- SQL Injection payloads
- XSS payloads
- Path Traversal payloads
- Number ranges
- Custom file-based payloads

---

## Quick Setup

### 1. Create virtualenv and install dependencies
```bash
python -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

### 2. Run the Dashboard API
```bash
python gui_api.py
# or
uvicorn gui_api:app --host 0.0.0.0 --port 5050
```

### 3. Run mitmproxy with addons
```bash
mitmdump -s intercept_proxy.py -s proxy_logger.py -s intercept_mode.py -p 8080
mitmdump -s backend.py -p 8080
```

---

## API Endpoints

### Traffic History
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/traffic` | Get all captured requests |
| GET | `/api/request/{id}` | Get request details |
| GET | `/api/response/{id}` | Get response details |
| DELETE | `/api/clear-requests` | Clear all history |

### Repeater
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/repeater/send` | Send a new request |
| POST | `/api/repeater/send-from-history` | Resend from history |
| POST | `/api/repeater/send-raw` | Send raw HTTP request |
| GET | `/api/repeater/history` | Get repeater history |
| DELETE | `/api/repeater/clear-history` | Clear repeater history |

### Intruder
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/intruder/attack` | Start an attack |
| GET | `/api/intruder/results` | Get attack results |
| GET | `/api/intruder/result/{index}` | Get specific result |
| POST | `/api/intruder/stop` | Stop current attack |
| POST | `/api/intruder/payloads/generate` | Generate payloads |
| GET | `/api/intruder/payloads/types` | List payload types |
| POST | `/api/intruder/filter` | Filter results |

### WebSocket
| Endpoint | Description |
|----------|-------------|
| `/ws/terminal` | Interactive terminal |
| `/ws/intruder` | Real-time attack updates |

---

## Usage Examples

### Repeater - Send Request
```bash
curl -X POST http://localhost:5050/api/repeater/send \
  -H "Content-Type: application/json" \
  -d '{
    "method": "GET",
    "url": "https://httpbin.org/get",
    "headers": {"User-Agent": "RedKit/1.0"},
    "body": ""
  }'
```

### Repeater - Resend from History
```bash
curl -X POST http://localhost:5050/api/repeater/send-from-history \
  -H "Content-Type: application/json" \
  -d '{"history_id": 1}'
```

### Intruder - Sniper Attack
```bash
curl -X POST http://localhost:5050/api/intruder/attack \
  -H "Content-Type: application/json" \
  -d '{
    "method": "POST",
    "url": "https://target.com/login",
    "headers": {"Content-Type": "application/x-www-form-urlencoded"},
    "body": "username=admin&password=§test§",
    "attack_type": "sniper",
    "payloads": ["123456", "password", "admin123"],
    "threads": 10
  }'
```

### Intruder - Cluster Bomb Attack
```bash
curl -X POST http://localhost:5050/api/intruder/attack \
  -H "Content-Type: application/json" \
  -d '{
    "method": "POST",
    "url": "https://target.com/login",
    "body": "username=§user§&password=§pass§",
    "attack_type": "cluster_bomb",
    "payload_sets": [
      ["admin", "root", "user"],
      ["123456", "password", "admin"]
    ],
    "threads": 10
  }'
```

### Generate Payloads
```bash
# Get SQL Injection payloads
curl -X POST http://localhost:5050/api/intruder/payloads/generate \
  -H "Content-Type: application/json" \
  -d '{"payload_type": "sqli"}'

# Get number range
curl -X POST http://localhost:5050/api/intruder/payloads/generate \
  -H "Content-Type: application/json" \
  -d '{"payload_type": "numbers", "start": 1, "end": 100}'
```

---

## CLI Tools

### Repeater CLI
```bash
python repeater.py
```

### Intruder CLI
```bash
python intruder.py
```

---

## Position Markers

Use `§` (section sign) to mark injection points in URLs, headers, or body:

```
# URL position
https://target.com/user/§1§/profile

# Body positions
username=§admin§&password=§pass123§

# Header position
Authorization: Bearer §token§
```

---

## Project Structure
```
redkit_proxy/
├── gui_api.py           # FastAPI Dashboard + API
├── repeater.py          # Repeater module
├── intruder.py          # Intruder module
├── intercept_proxy.py   # Basic interception addon
├── proxy_logger.py      # SQLite logger addon
├── rewrite_engine.py    # Rewrite rules engine
├── intercept_mode.py    # Interactive intercept mode
├── logging_addon.py     # JSON file logger
├── history_addon.py     # Lightweight history addon
├── requirements.txt     # Python dependencies
├── .gitignore          # Git ignore rules
└── README.md           # This file
```

---

## License

MIT License
