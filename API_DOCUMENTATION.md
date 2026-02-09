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
    "headers": "Content-Type: application/json\nAuthorization: Bearer token123",
    "body": "{\"name\": \"John\"}",
    "raw": "GET /api/users HTTP/1.1\nHost: example.com\nContent-Type: application/json\n\n{\"name\": \"John\"}"
}
```

**Fields Explained:**
- `id`: Unique identifier for this request (you need this to forward/drop it)
- `method`: HTTP method (GET, POST, PUT, DELETE, etc.)
- `url`: Full URL the request is going to
- `host`: The domain name
- `headers`: HTTP headers as a string
- `body`: The request body (for POST/PUT requests)
- `raw`: The complete HTTP request as it would appear on the wire

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
    "response_headers": "Content-Type: application/json\nServer: nginx",
    "response_body": "{\"users\": [{\"id\": 1, \"name\": \"John\"}]}",
    "raw_response": "HTTP/1.1 200 OK\nContent-Type: application/json\n\n{\"users\": [{\"id\": 1, \"name\": \"John\"}]}",
    "parent_request": {
        "method": "GET",
        "url": "https://example.com/api/users",
        "host": "example.com",
        "headers": "Accept: application/json",
        "body": "",
        "raw": "GET /api/users HTTP/1.1\nHost: example.com\nAccept: application/json"
    }
}
```

**Fields Explained:**
- `id`: Unique identifier for this response
- `parent_id`: The ID of the request that caused this response
- `status_code`: HTTP status (200 = OK, 404 = Not Found, 500 = Server Error, etc.)
- `response_headers`: Response headers as a string
- `response_body`: The response body (HTML, JSON, etc.)
- `raw_response`: Complete HTTP response as it appears on the wire
- `parent_request`: The original request data (useful for showing both side-by-side)

---

### 6. Forward Request

**Purpose:** Let a caught request continue to its destination

**Send to Backend:**
```javascript
{
    "action": "forward_request",
    "id": "uuid-of-request",
    "request": {
        "method": "POST",
        "url": "https://example.com/api/users",
        "headers": "Content-Type: application/json\nAuthorization: Bearer token",
        "body": "{\"name\": \"Modified Name\"}"
    }
}
```

**Receive from Backend:**
```javascript
{
    "type": "forwarded",
    "id": "uuid-of-request"
}
```

**Explanation:** You can modify the request before forwarding! Change the URL, headers, or body.

---

### 7. Forward Response

**Purpose:** Let a caught response continue to the browser

**Send to Backend:**
```javascript
{
    "action": "forward_response",
    "id": "uuid-of-response",
    "response": {
        "status_code": 200,
        "headers": "Content-Type: application/json",
        "body": "{\"modified\": \"data\"}"
    }
}
```

**Receive from Backend:**
```javascript
{
    "type": "forwarded",
    "id": "uuid-of-response"
}
```

**Explanation:** Modify the response before sending it to the browser. You can change status codes, headers, and body.

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

**Purpose:** Forward all pending requests at once

**Send to Backend:**
```javascript
{
    "action": "forward_all",
    "requests": [
        {
            "id": "uuid-1",
            "method": "GET",
            "url": "https://example.com/page1",
            "headers": "...",
            "body": "..."
        },
        {
            "id": "uuid-2",
            "method": "POST",
            "url": "https://example.com/page2",
            "headers": "...",
            "body": "..."
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
            request: {
                method: msg.method,
                url: msg.url,
                headers: msg.headers,
                body: msg.body
            }
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
            request: {
                method: msg.method,
                url: msg.url,
                headers: msg.headers,
                body: msg.body
            }
        }));
    }
    
    if (msg.type === 'intercepted_response') {
        console.log('Response for:', msg.url);
        console.log('Status:', msg.status_code);
        console.log('Original Request:', msg.parent_request);
        console.log('Response Body:', msg.response_body);
        
        // 4. Modify and forward the response
        const modifiedBody = msg.response_body.replace('John', 'Jane');
        
        ws.send(JSON.stringify({
            action: 'forward_response',
            id: msg.id,
            response: {
                status_code: msg.status_code,
                headers: msg.response_headers,
                body: modifiedBody
            }
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

That's it! You now have everything you need to build the frontend for the RedKit Proxy interceptor and history features.