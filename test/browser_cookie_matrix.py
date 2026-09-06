"""Optional real-browser checks for Vestibule's cookie contract."""

import http.server
import json
import os
import shutil
import ssl
import subprocess
import threading
import urllib.request

import websocket


ROOT = os.path.dirname(__file__)
PROFILE = os.path.join(ROOT, "browser-cookie-profile")
CERT = os.path.join(ROOT, "browser-cookie-cert.pem")
KEY = os.path.join(ROOT, "browser-cookie-key.pem")
seen = {}
events = {
    name: threading.Event()
    for name in ("set", "fix", "check", "callback", "expire", "check_after")
}


class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def do_GET(self):
        host = self.headers.get("host", "").split(":")[0]
        if host == "app.example.test" and self.path == "/set":
            self.send_response(200)
            self.send_header(
                "Set-Cookie",
                "__Host-vestibule_session=good; Secure; Path=/; HttpOnly; SameSite=Lax",
            )
            self.send_header(
                "Set-Cookie", "lax_cookie=lax; Secure; Path=/; SameSite=Lax"
            )
            self.send_header(
                "Set-Cookie", "none_cookie=none; Secure; Path=/; SameSite=None"
            )
            self.end_headers()
            events["set"].set()
        elif host == "evil.example.test" and self.path == "/fix":
            self.send_response(200)
            self.send_header(
                "Set-Cookie",
                "__Host-vestibule_session=evil; Secure; Path=/; Domain=example.test",
            )
            self.send_header(
                "Set-Cookie",
                "vestibule_session=evil; Secure; Path=/; Domain=example.test",
            )
            self.end_headers()
            events["fix"].set()
        elif host == "app.example.test" and self.path == "/check":
            seen["check"] = self.headers.get("cookie", "")
            self.send_response(200)
            self.end_headers()
            events["check"].set()
        elif host == "app.example.test" and self.path == "/expire":
            self.send_response(200)
            self.send_header(
                "Set-Cookie",
                "__Host-vestibule_session=; Max-Age=0; Secure; Path=/; HttpOnly; SameSite=Lax",
            )
            self.end_headers()
            events["expire"].set()
        elif host == "app.example.test" and self.path == "/check-after":
            seen["check_after"] = self.headers.get("cookie", "")
            self.send_response(200)
            self.end_headers()
            events["check_after"].set()
        elif host == "idp.attacker.test" and self.path == "/post":
            body = b"""<form id=f method=post action=https://app.example.test:8443/callback>
<input name=state value=state><input name=code value=code></form>
<script>f.submit()</script>"""
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        seen["callback"] = self.headers.get("cookie", "")
        self.send_response(200)
        self.end_headers()
        events["callback"].set()


def serve(port):
    server = http.server.ThreadingHTTPServer(("127.0.0.1", port), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(CERT, KEY)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def cdp(ws, method, params=None):
    cdp.counter += 1
    ws.send(json.dumps({"id": cdp.counter, "method": method, "params": params or {}}))
    while True:
        message = json.loads(ws.recv())
        if message.get("id") == cdp.counter:
            return message


cdp.counter = 0


def navigate(ws, url, event):
    result = cdp(ws, "Page.navigate", {"url": url})
    if not event.wait(8):
        raise AssertionError(f"navigation did not reach {url}: {result}")


def main():
    chromium = shutil.which("chromium") or shutil.which("chromium-browser")
    if not chromium:
        raise SystemExit("Chromium is required")
    subprocess.run(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            KEY,
            "-out",
            CERT,
            "-days",
            "1",
            "-subj",
            "/CN=app.example.test",
        ],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    servers = [serve(port) for port in (8443, 8444, 8445)]
    chrome = subprocess.Popen(
        [
            chromium,
            "--headless",
            "--no-sandbox",
            "--disable-gpu",
            "--disable-dev-shm-usage",
            "--ignore-certificate-errors",
            "--remote-debugging-port=9223",
            "--remote-allow-origins=*",
            f"--user-data-dir={PROFILE}",
            "--host-resolver-rules=MAP *.example.test 127.0.0.1, MAP *.attacker.test 127.0.0.1",
            "about:blank",
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        for _ in range(80):
            try:
                urllib.request.urlopen("http://127.0.0.1:9223/json/version")
                break
            except Exception:
                threading.Event().wait(0.1)
        else:
            raise AssertionError("Chromium DevTools did not start")
        page = json.load(
            urllib.request.urlopen(
                urllib.request.Request(
                    "http://127.0.0.1:9223/json/new?about:blank", method="PUT"
                )
            )
        )
        ws = websocket.create_connection(page["webSocketDebuggerUrl"])
        cdp(ws, "Page.enable")
        navigate(ws, "https://app.example.test:8443/set", events["set"])
        navigate(ws, "https://evil.example.test:8444/fix", events["fix"])
        navigate(ws, "https://app.example.test:8443/check", events["check"])
        navigate(ws, "https://idp.attacker.test:8445/post", events["callback"])
        navigate(ws, "https://app.example.test:8443/expire", events["expire"])
        navigate(ws, "https://app.example.test:8443/check-after", events["check_after"])
        ws.close()

        assert seen["check"].count("__Host-vestibule_session=") == 1
        assert "__Host-vestibule_session=good" in seen["check"]
        assert "vestibule_session=evil" in seen["check"]
        assert "none_cookie=none" in seen["callback"]
        assert "lax_cookie=lax" not in seen["callback"]
        assert "__Host-vestibule_session=good" not in seen["callback"]
        assert "__Host-vestibule_session=" not in seen["check_after"]
        print("browser cookie matrix passed")
    finally:
        chrome.terminate()
        chrome.wait(timeout=5)
        for server in servers:
            server.shutdown()
        shutil.rmtree(PROFILE, ignore_errors=True)
        for path in (CERT, KEY):
            if os.path.exists(path):
                os.remove(path)


if __name__ == "__main__":
    main()
