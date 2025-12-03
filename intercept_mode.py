from mitmproxy import http

class InterceptMode:
    def __init__(self):
        self.enabled = True  # تقدر تعمل ON/OFF بعدين

    def request(self, flow: http.HTTPFlow):
        if not self.enabled:
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

        else:
            print("Invalid choice → auto forward.")
            return

addons = [
    InterceptMode()
]
