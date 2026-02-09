from mitmproxy import http
import re

class InterceptMode:
    def __init__(self):
        self.enabled = True  # تقدر تعمل ON/OFF بعدين
        
        # قائمة الـ hosts/URLs اللي هيتم تجاهلها (مش هيتعمللها intercept)
        self.excluded_hosts = [
            "127.0.0.1",
            "localhost",
            "0.0.0.0",
        ]
        
        # قائمة الـ ports اللي هيتم تجاهلها
        self.excluded_ports = [
            5050,  # Dashboard port
        ]
        
        # قائمة patterns للـ URLs اللي هيتم تجاهلها
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
        """
        تحديد هل الـ request ده يتعمله intercept ولا لا
        """
        host = flow.request.host
        port = flow.request.port
        path = flow.request.path
        
        # تجاهل الـ hosts المستثناة
        if host in self.excluded_hosts:
            return False
        
        # تجاهل الـ ports المستثناة
        if port in self.excluded_ports:
            return False
        
        # تجاهل الـ URL patterns المستثناة
        for pattern in self.excluded_patterns:
            if re.search(pattern, path):
                return False
        
        return True

    def request(self, flow: http.HTTPFlow):
        if not self.enabled:
            return
        
        # تحقق هل نعمل intercept ولا لا
        if not self.should_intercept(flow):
            return

        print("\n==========================")
        print(" 🔥 INTERCEPTED REQUEST 🔥 ")
        print("==========================")

        print(f"URL     : {flow.request.url}")
        print(f"METHOD  : {flow.request.method}")
        print("HEADERS :")
        for k, v in flow.request.headers.items():
            print(f"   {k}: {v}")

        if flow.request.text:
            print("\nBODY:")
            print(flow.request.text)

        print("\n==========================")
        print("[A] Allow")
        print("[D] Drop")
        print("[E] Edit request")
        print("[S] Skip (auto-allow all from this host)")
        print("==========================")

        choice = input("Your action: ").strip().lower()

        # --- Allow ---
        if choice == "a":
            print("✔ Request forwarded.")
            return

        # --- Drop ---
        elif choice == "d":
            print("✖ Request dropped.")
            flow.response = http.Response.make(403, b"Request Dropped")
            return

        # --- Edit ---
        elif choice == "e":
            print("\n--- Edit Mode ---")
            new_url = input(f"New URL (press Enter to keep): ").strip()
            if new_url:
                flow.request.url = new_url

            new_body = input("New Body (press Enter to keep): ").strip()
            if new_body:
                flow.request.text = new_body

            print("\n✔ Request after editing will be forwarded.")
            return

        # --- Skip (add host to excluded) ---
        elif choice == "s":
            self.excluded_hosts.append(flow.request.host)
            print(f"✔ Added {flow.request.host} to excluded hosts. Future requests will be auto-allowed.")
            return

        else:
            print("Invalid choice → auto forward.")
            return

addons = [
    InterceptMode()
]
