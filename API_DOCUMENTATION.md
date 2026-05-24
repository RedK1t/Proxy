# RedKit Proxy WebSocket API Documentation

## Overview

This is a proxy tool that sits between your browser and the internet. Think of it like a mail interception service - it catches letters (HTTP requests) before they reach their destination, lets you look at them and modify them, then sends them on their way.

**Base URL:** `ws://localhost:5050/ws`

---

## Quick Concepts for Frontend Devs

### What is a Proxy?
A proxy is like a middleman. When you visit a website:
1. Your browser sends a **Request** (like "give me google.com")
2. The proxy catches it
3. The proxy can show it to you, modify it, or block it
4. The proxy forwards it to the real destination
5. The destination sends back a **Response**
6. The proxy can catch the response too, show/modify it
7. Finally, the response reaches your browser

### Key Terms
- **Request**: What your browser sends TO a website (URL, headers, body)
- **Response**: What the website sends BACK (status code, headers, body)
- **Intercept**: To catch and hold a request/response for review
- **Forward**: To let a request/response continue to its destination
- **Drop**: To block a request/response (it never reaches destination)

---

## Connection

### Connecting to WebSocket
```javascript
const ws = new WebSocket('ws://localhost:5050/ws');

ws.onopen = () => console.log('Connected!');
ws.onmessage = (event) => {
    const msg = JSON.parse(event.data);
    handleMessage(msg);
};
ws.onclose = () => console.log('Disconnected');
```

---

## INTERCEPTOR FEATURE

The interceptor catches HTTP requests before they go to the server. You can:
- See what data is being sent
- Modify the request
- Block the request
- Mark specific requests to intercept their responses

### 1. Toggle Interception

**Purpose:** Turn interception ON/OFF globally

**Send to Backend:**
```javascript
{
    "action": "toggle_intercept",
    "enabled": true  // or false
}
```

**Receive from Backend:**
```javascript
{
    "type": "intercept_status",
    "enabled": true
}
```

**Explanation:** When `enabled: true`, the proxy will catch ALL requests. When `enabled: false`, requests flow through normally.

---

### 2. Mark Request for Response Interception

**Purpose:** Tell the proxy "when this request gets a response, catch that response too"

**Send to Backend:**
```javascript
{
    "action": "mark_for_response_intercept",
    "id": "uuid-of-the-request"
}
```

**Receive from Backend:**
```javascript
{
    "type": "marked_for_response_intercept",
    "id": "uuid-of-the-request"
}
```

**Explanation:** Normally, only requests are intercepted. This tells the proxy to also catch the response for THIS specific request.

---

### 3. Unmark Request for Response Interception

**Purpose:** Cancel the "intercept response" marking

**Send to Backend:**
```javascript
{
    "action": "unmark_for_response_intercept",
    "id": "uuid-of-the-request"
}
```

**Receive from Backend:**
```javascript
{
    "type": "unmarked_for_response_intercept",
    "id": "uuid-of-the-request"
}
```

---

### 4. Receive Intercepted Request

**Purpose:** The backend sends you a request that was caught

**Receive from Backend:**
```javascript
{
    "type": "intercepted_request",
    "id": "uuid-of-request",
    "method": "GET",
    "url": "https://example.com/api/users",
    "host": "example.com",
    "headers": "Host: example.com\nUser-Agent: Mozilla/5.0\nAccept: application/json\nAuthorization: Bearer token123",
    "body": "{\"name\": \"John\"}",
    "raw": "GET /api/users HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Mozilla/5.0\r\nAccept: application/json\r\nAuthorization: Bearer token123\r\n\r\n{\"name\": \"John\"}"
}
```

**Fields Explained:**
- `id`: Unique identifier for this request (you need this to forward/drop it)
- `method`: HTTP method (GET, POST, PUT, DELETE, etc.)
- `url`: Full URL the request is going to
- `host`: The domain name
- `headers`: HTTP headers as a string with proper capitalization (Host, User-Agent, Content-Type, etc.)
- `body`: The request body (for POST/PUT requests)
- `raw`: The complete HTTP request as it would appear on the wire with proper formatting

---

### 5. Receive Intercepted Response

**Purpose:** The backend sends you a response that was caught

**Receive from Backend:**
```javascript
{
    "type": "intercepted_response",
    "id": "uuid-of-response",
    "parent_id": "uuid-of-original-request",
    "method": "GET",
    "url": "https://example.com/api/users",
    "host": "example.com",
    "status_code": 200,
    "response_headers": "Date: Thu, 12 Feb 2026 13:41:00 GMT\nServer: nginx\nContent-Type: application/json\nContent-Length: 42",
    "response_body": "{\"users\": [{\"id\": 1, \"name\": \"John\"}]}",
    "raw_response": "HTTP/1.1 200 OK\r\nDate: Thu, 12 Feb 2026 13:41:00 GMT\r\nServer: nginx\r\nContent-Type: application/json\r\nContent-Length: 42\r\n\r\n{\"users\": [{\"id\": 1, \"name\": \"John\"}]}",
    "parent_request": {
        "method": "GET",
        "url": "https://example.com/api/users",
        "host": "example.com",
        "headers": "Host: example.com\nUser-Agent: Mozilla/5.0\nAccept: application/json",
        "body": "",
        "raw": "GET /api/users HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Mozilla/5.0\r\nAccept: application/json"
    }
}
```

**Fields Explained:**
- `id`: Unique identifier for this response
- `parent_id`: The ID of the request that caused this response
- `status_code`: HTTP status (200 = OK, 404 = Not Found, 500 = Server Error, etc.)
- `response_headers`: Response headers as a string with proper capitalization
- `response_body`: The response body (HTML, JSON, etc.)
- `raw_response`: Complete HTTP response as it appears on the wire with proper formatting
- `parent_request`: The original request data (useful for showing both side-by-side)

---

### 6. Forward Request

**Purpose:** Let a caught request continue to its destination

**Send to Backend:**
```javascript
{
    "action": "forward_request",
    "id": "uuid-of-request",
    "request": "GET / HTTP/1.1\nHost: ma-quiz.pages.dev\nUser-Agent: Mozilla/5.0\nAccept: text/html\n\n"
}
```

**Note:** The request line should use the path format (`GET / HTTP/1.1`) not the full URL format (`GET https://host/ HTTP/1.1`). The Host header determines the destination.

**Receive from Backend:**
```javascript
{
    "type": "forwarded",
    "id": "uuid-of-request"
}
```

**Explanation:** You can modify the request before forwarding! The request is sent as a single raw HTTP string. The backend parses it automatically.

---

### 7. Forward Response

**Purpose:** Let a caught response continue to the browser

**Send to Backend:**
```javascript
{
    "action": "forward_response",
    "id": "uuid-of-response",
    "response": "HTTP/1.1 200 OK\nContent-Type: application/json\n\n{\"modified\": \"data\"}"
}
```

**Receive from Backend:**
```javascript
{
    "type": "forwarded",
    "id": "uuid-of-response"
}
```

**Explanation:** Modify the response before sending it to the browser. The response is sent as a single raw HTTP string. The backend parses it automatically.

---

### 8. Drop Request

**Purpose:** Block a request (it never reaches the server)

**Send to Backend:**
```javascript
{
    "action": "drop_request",
    "id": "uuid-of-request"
}
```

**Receive from Backend:**
```javascript
{
    "type": "dropped",
    "id": "uuid-of-request"
}
```

**Explanation:** The browser will receive a 403 error instead of the actual response.

---

### 9. Drop Response

**Purpose:** Block a response (it never reaches the browser)

**Send to Backend:**
```javascript
{
    "action": "drop_response",
    "id": "uuid-of-response"
}
```

**Receive from Backend:**
```javascript
{
    "type": "dropped",
    "id": "uuid-of-response"
}
```

---

### 10. Forward All

**Purpose:** Forward all pending items (requests and responses) at once

**Send to Backend:**
```javascript
{
    "action": "forward_all",
    "items": [
        {
            "id": "uuid-1",
            "type": "request",
            "raw": "GET /page1 HTTP/1.1\nHost: example.com\n\n"
        },
        {
            "id": "uuid-2",
            "type": "response",
            "raw": "HTTP/1.1 200 OK\nContent-Type: text/html\n\n<html>Body</html>"
        }
    ]
}
```

**Receive from Backend:**
```javascript
{
    "type": "queue_cleared"
}
```

**Explanation:** Each item in the array includes its ID, type ('request' or 'response'), and the raw HTTP content. The backend parses each item based on its type automatically.

---

### 11. Drop All

**Purpose:** Drop all pending requests at once

**Send to Backend:**
```javascript
{
    "action": "drop_all",
    "ids": ["uuid-1", "uuid-2", "uuid-3"]
}
```

**Receive from Backend:**
```javascript
{
    "type": "queue_cleared"
}
```

---

## HTTP HISTORY FEATURE

The proxy saves all requests/responses that pass through it. You can view them later.

### 1. Get History List

**Purpose:** Get a list of all past requests

**Send to Backend:**
```javascript
{
    "action": "get_history"
}
```

**Receive from Backend:**
```javascript
{
    "type": "history",
    "data": [
        [1, "GET", "https://google.com", 200, "2024-01-15 10:30:00"],
        [2, "POST", "https://api.example.com/login", 200, "2024-01-15 10:31:00"],
        [3, "GET", "https://example.com/page", 404, "2024-01-15 10:32:00"]
    ]
}
```

**Data Format:** Each array is `[id, method, url, status_code, timestamp]`

---

### 2. Get History Detail

**Purpose:** Get full details of a specific history item

**Send to Backend:**
```javascript
{
    "action": "get_history_detail",
    "id": 1
}
```

**Receive from Backend:**
```javascript
{
    "type": "history_detail",
    "request_headers": "GET / HTTP/1.1\nHost: google.com\nUser-Agent: Mozilla/5.0",
    "request_body": "",
    "response_headers": "HTTP/1.1 200 OK\nContent-Type: text/html\nServer: gws",
    "response_body": "<!DOCTYPE html><html>...</html>"
}
```

---

### 3. Clear History

**Purpose:** Delete all history records

**Send to Backend:**
```javascript
{
    "action": "clear_history"
}
```

**Receive from Backend:**
```javascript
{
    "type": "history_cleared"
}
```

---

### 4. Real-Time History Updates (push)

**Purpose:** The backend pushes each newly logged request/response to all connected
clients as it happens — no polling or re-opening the tab required.

**Receive from Backend (unsolicited):**
```javascript
{
    "type": "history_new",
    "row": [42, "GET", "https://example.com/api", 200, "2026-05-24 10:31:00"]
}
```

**`row` format:** `[id, method, url, status_code, timestamp]` — the same shape as one
entry in the `history` message's `data` array. Prepend it to your list (newest first).

---

## REPEATER FEATURE (Burp-style)

The Repeater lets you edit a **raw HTTP request** and resend it, viewing the **raw HTTP
response**. The UI supports multiple independent tabs; each tab tags its request with a
client-generated `req_id` so the matching response is routed back to it.

### Send a Request

**Send to Backend:**
```javascript
{
    "action": "repeater_send",
    "req_id": "rq_1716542400_ab12c",   // optional; echoed back to match the tab
    "raw": "GET /api/users HTTP/1.1\nHost: example.com\nUser-Agent: Mozilla/5.0\n\n",
    "target": "https://example.com",    // optional; scheme/host override (else inferred from Host header)
    "follow_redirects": false,
    "timeout": 30
}
```

**Notes:**
- `raw` is a full raw HTTP request. The request line should use the path form
  (`GET /api/users HTTP/1.1`); the destination is the `target` (if given) or the
  `Host` header, defaulting to `https`.
- `Content-Length` is recomputed automatically, so you can freely edit the body.

**Receive from Backend (success):**
```javascript
{
    "type": "repeater_response",
    "req_id": "rq_1716542400_ab12c",
    "success": true,
    "data": {
        "status_code": 200,
        "reason": "OK",
        "url": "https://example.com/api/users",
        "raw_response": "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{...}",
        "headers": { "Content-Type": "application/json" },
        "body": "{...}",
        "elapsed_time": 0.184,
        "size": 1024
    }
}
```

**Receive from Backend (error):**
```javascript
{
    "type": "repeater_response",
    "req_id": "rq_1716542400_ab12c",
    "success": false,
    "error": "Connection refused"
}
```

---

## INTRUDER FEATURE (Burp-style)

The Intruder fuzzes a **raw HTTP request template** in which payload positions are marked
with the `§` character (e.g. `GET /user/§1§ HTTP/1.1`). Results stream back one row at a
time, and full responses can be fetched on demand.

### Attack Types
| Type | Payload sets | Behaviour |
|------|--------------|-----------|
| `sniper` | 1 | One position at a time; others keep their default (text between the markers) |
| `battering_ram` | 1 | Same payload placed in every position |
| `pitchfork` | 1 per position | Sets advance in parallel (stops at the shortest) |
| `cluster_bomb` | 1 per position | Every combination across the sets |

### Start an Attack

**Send to Backend:**
```javascript
{
    "action": "intruder_attack",
    "raw": "POST /login HTTP/1.1\nHost: example.com\nContent-Type: application/x-www-form-urlencoded\n\nuser=§admin§&pass=§x§",
    "target": "https://example.com",          // optional
    "attack_type": "cluster_bomb",
    "payload_sets": [["admin", "root"], ["123456", "password"]],  // one list per position
    "grep": "Welcome",                          // optional: counts substring matches per response
    "threads": 10,
    "timeout": 30,
    "follow_redirects": false
}
```

**Receive from Backend:**
```javascript
// 1) Acknowledgement
{ "type": "intruder_started" }

// 2) One message per completed request (streamed)
{
    "type": "intruder_result",
    "result": {
        "request": 1,            // request number (use to fetch the full response)
        "payload": "admin, 123456",
        "status_code": 200,
        "length": 1024,
        "time": 0.153,
        "grep": 1,               // substring match count, or null if no grep
        "error": null
    }
}

// 3) Completion summary
{
    "type": "intruder_complete",
    "total": 4,
    "errors": 0,
    "stopped": false             // true if the user stopped it early
}
```

### Fetch a Full Response

**Purpose:** Responses are kept server-side; request one when a result row is clicked.

**Send to Backend:**
```javascript
{
    "action": "intruder_get_response",
    "index": 1                   // the result's "request" number
}
```

**Receive from Backend:**
```javascript
{
    "type": "intruder_response",
    "index": 1,
    "payload": "admin, 123456",
    "status_code": 200,
    "response": "HTTP/1.1 200 OK\r\n...\r\n\r\n<body>"
}
```

### Stop an Attack

**Send to Backend:**
```javascript
{ "action": "intruder_stop" }
```

**Receive from Backend:**
```javascript
{ "type": "intruder_stopped" }
```
An `intruder_complete` message with `"stopped": true` follows once the in-flight
requests finish.

### Load Payload Presets

**Send to Backend:**
```javascript
{
    "action": "get_payloads",
    "payload_type": "passwords",   // passwords | usernames | sqli | xss | path_traversal | directories | fuzz | http_methods | numbers
    "set_index": 0,                // which payload set the result is for (echoed back)
    "start": 0, "end": 100, "step": 1   // only for "numbers"
}
```

**Receive from Backend:**
```javascript
{
    "type": "payloads",
    "payload_type": "passwords",
    "set_index": 0,
    "payloads": ["123456", "password", "..."]
}
```

---

## SCOPE FEATURE

Scope decides which traffic the proxy actually **intercepts and logs**. It has two
independent parts, each with its own on/off toggle:

1. **Target Scope** — `include` / `exclude` URL rules. Each rule is tried as a **RegEx**
   first; if it isn't valid regex it falls back to **glob wildcards** (`*`). When Target
   Scope is ON: a request must match at least one `include` rule (an empty include list
   means "everything") and must not match any `exclude` rule.
2. **Extension Exclude** — a list of file extensions (e.g. `js`, `css`, `png`). When ON,
   any request whose path ends in one of these extensions is skipped. A default set is
   seeded on first run and can be edited.

Out-of-scope flows are **neither intercepted nor written to HTTP History**.

### 1. Get Scope

**Send to Backend:**
```javascript
{ "action": "get_scope" }
```

**Receive from Backend:**
```javascript
{
    "type": "scope",
    "enabled": false,            // Target Scope toggle
    "extension_enabled": true,   // Extension Exclude toggle
    "include":    [ { "id": 1, "pattern": ".*fawry\\.com" } ],
    "exclude":    [ { "id": 2, "pattern": ".*google\\.com" } ],
    "extensions": [ { "id": 3, "pattern": "js" }, { "id": 4, "pattern": "css" } ]
}
```
The same `scope` message is **broadcast to all clients** whenever scope changes, so every
open dashboard stays in sync.

### 2. Toggle Target Scope

**Send to Backend:**
```javascript
{ "action": "toggle_scope", "enabled": true }
```
**Receive:** a fresh `scope` message (broadcast).

### 3. Toggle Extension Exclude

**Send to Backend:**
```javascript
{ "action": "toggle_extension_exclude", "enabled": true }
```
**Receive:** a fresh `scope` message (broadcast).

### 4. Add a Scope Rule

**Send to Backend:**
```javascript
{
    "action": "add_scope_rule",
    "rule_type": "include",      // "include" | "exclude" | "extension"
    "pattern": ".*paypal\\.com"  // for "extension", just the extension e.g. "woff2"
}
```
**Receive:** a fresh `scope` message (broadcast). Duplicate (rule_type, pattern) pairs are
ignored.

### 5. Remove a Scope Rule

**Send to Backend:**
```javascript
{ "action": "remove_scope_rule", "id": 2 }
```
**Receive:** a fresh `scope` message (broadcast).

---

## COMPLETE WORKFLOW EXAMPLES

### Example 1: Basic Request Interception

```javascript
// 1. Turn on interception
ws.send(JSON.stringify({
    action: 'toggle_intercept',
    enabled: true
}));

// 2. Receive intercepted request
ws.onmessage = (event) => {
    const msg = JSON.parse(event.data);
    
    if (msg.type === 'intercepted_request') {
        console.log('Caught request to:', msg.url);
        console.log('Request body:', msg.body);
        
        // 3. Forward it (let it go through)
        ws.send(JSON.stringify({
            action: 'forward_request',
            id: msg.id,
            request: msg.raw
        }));
    }
};
```

### Example 2: Response Interception Flow

```javascript
// 1. Turn on interception
ws.send(JSON.stringify({
    action: 'toggle_intercept',
    enabled: true
}));

let selectedRequestId = null;

ws.onmessage = (event) => {
    const msg = JSON.parse(event.data);
    
    if (msg.type === 'intercepted_request') {
        console.log('Request:', msg.url);
        selectedRequestId = msg.id;
        
        // 2. Mark this request to intercept its response
        ws.send(JSON.stringify({
            action: 'mark_for_response_intercept',
            id: msg.id
        }));
        
        // 3. Forward the request
        ws.send(JSON.stringify({
            action: 'forward_request',
            id: msg.id,
            request: msg.raw
        }));
    }
    
    if (msg.type === 'intercepted_response') {
        console.log('Response for:', msg.url);
        console.log('Status:', msg.status_code);
        console.log('Original Request:', msg.parent_request);
        console.log('Response Body:', msg.response_body);
        
        // 4. Modify and forward the response
        let modifiedResponse = msg.raw_response;
        modifiedResponse = modifiedResponse.replace('John', 'Jane');
        
        ws.send(JSON.stringify({
            action: 'forward_response',
            id: msg.id,
            response: modifiedResponse
        }));
    }
};
```

### Example 3: Viewing History

```javascript
// 1. Request history list
ws.send(JSON.stringify({
    action: 'get_history'
}));

ws.onmessage = (event) => {
    const msg = JSON.parse(event.data);
    
    if (msg.type === 'history') {
        // Display list: id, method, url, status_code, time
        msg.data.forEach(item => {
            console.log(`${item[1]} ${item[2]} - Status: ${item[3]}`);
        });
    }
};

// 2. Click on history item to get details
function viewHistoryDetails(historyId) {
    ws.send(JSON.stringify({
        action: 'get_history_detail',
        id: historyId
    }));
}

ws.onmessage = (event) => {
    const msg = JSON.parse(event.data);
    
    if (msg.type === 'history_detail') {
        console.log('Request:', msg.request_headers);
        console.log('Response:', msg.response_headers);
    }
};
```

---

## ERROR HANDLING

**Error Message from Backend:**
```javascript
{
    "type": "error",
    "message": "Unknown action: invalid_action"
}
```

Always check for `type: 'error'` in your message handler!

---

## TIPS FOR FRONTEND DEVELOPMENT

1. **Queue Management**: Requests come in real-time. Store them in an array and display in a table.

2. **Auto-Select**: When a new request arrives and nothing is selected, automatically select it.

3. **Visual Indicators**: 
   - Highlight requests marked for response interception (purple background)
   - Show "RESPONSE" label on response items
   - Show status codes with color coding (green=2xx, yellow=4xx, red=5xx)

4. **Split Pane**: When viewing a response, show:
   - LEFT: Original request (read-only, gray background)
   - RIGHT: Response (editable, normal background)

5. **Raw Format**: Both requests and responses are shown in raw HTTP format:
   ```
   GET /path HTTP/1.1
   Host: example.com
   Header: Value
   
   Body content
   ```

6. **Persistence**: The backend stores everything in SQLite database. History persists between restarts.

7. **Connection Status**: Show if WebSocket is connected/disconnected. Auto-reconnect if disconnected.

---

## STATUS CODE QUICK REFERENCE

| Code | Meaning | Color |
|------|---------|-------|
| 200 | OK - Success | Green |
| 301 | Moved Permanently | Blue |
| 302 | Found (Redirect) | Blue |
| 400 | Bad Request | Yellow |
| 401 | Unauthorized | Yellow |
| 403 | Forbidden | Yellow |
| 404 | Not Found | Yellow |
| 500 | Server Error | Red |
| 502 | Bad Gateway | Red |
| 503 | Service Unavailable | Red |

---

## COMMON HTTP METHODS

| Method | Purpose | Typical Use |
|--------|---------|-------------|
| GET | Retrieve data | Loading a page |
| POST | Create data | Submitting a form |
| PUT | Update data | Saving changes |
| DELETE | Remove data | Deleting something |
| PATCH | Partial update | Editing a field |
| HEAD | Get headers only | Checking if page exists |
| OPTIONS | Get capabilities | CORS preflight |

---

That's it! You now have everything you need to build the frontend for the RedKit Proxy: Interceptor, HTTP History (with real-time updates), Repeater, Intruder, and Scope.