from mitmproxy import http

class InterceptAddon:
    def request(self, flow: http.HTTPFlow):
        # هيتنادى عند كل Request
        print(f"[REQUEST] {flow.request.method} {flow.request.url}")

        # مثال تعديل الهيدر
        flow.request.headers["X-Proxy-Intercept"] = "Ziad-Proxy"

        # مثال عمل Intercept يدوي (تقدر توقف هنا)
        # flow.intercept()

    def response(self, flow: http.HTTPFlow):
        # هيتنادى عند كل Response
        print(f"[RESPONSE] {flow.response.status_code} from {flow.request.url}")

        # مثال تعديل الكونتنت للـ Response
        if "text" in flow.response.headers.get("content-type", ""):
            original_body = flow.response.text
            modified_body = original_body.replace("Hello", "Hello from Ziad Proxy!")
            flow.response.text = modified_body

addons = [
    InterceptAddon()
]
