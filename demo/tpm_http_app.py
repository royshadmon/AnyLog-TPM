#!/usr/bin/env python3
import json
import os
from http.server import BaseHTTPRequestHandler, HTTPServer


class DemoHandler(BaseHTTPRequestHandler):
    def _request_context(self):
        return {
            "forwarded_proto": self.headers.get("X-Forwarded-Proto"),
            "forwarded_host": self.headers.get("X-Forwarded-Host"),
            "forwarded_port": self.headers.get("X-Forwarded-Port"),
            "forwarded_for": self.headers.get("X-Forwarded-For"),
            "forwarded_uri": self.headers.get("X-Forwarded-Uri"),
            "host": self.headers.get("Host"),
            "client_address": self.client_address[0],
        }

    def _send_json(self, status, payload):
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/":
            self._send_json(200, {
                "message": "HTTP app container is running behind the TPM HTTPS gateway",
            })
        elif self.path == "/health":
            self._send_json(200, {"status": "ok", "service": "app"})
        elif self.path == "/request-info":
            self._send_json(200, {
                "status": "ok",
                "request_context": self._request_context(),
            })
        else:
            self._send_json(404, {"error": "not found", "path": self.path})

    def do_POST(self):
        content_length = int(self.headers.get("Content-Length", "0"))
        raw_body = self.rfile.read(content_length) if content_length else b""
        try:
            payload = json.loads(raw_body.decode("utf-8")) if raw_body else None
        except json.JSONDecodeError:
            self._send_json(400, {"error": "invalid json"})
            return

        if self.path == "/echo":
            self._send_json(200, {
                "received": payload,
                "request_context": self._request_context(),
            })
        else:
            self._send_json(404, {"error": "not found", "path": self.path})

    def log_message(self, fmt, *args):
        print(f"{self.client_address[0]} - {fmt % args}")


if __name__ == "__main__":
    host = os.environ.get("APP_HOST", "0.0.0.0")
    port = int(os.environ.get("APP_PORT", "8080"))
    print(f"HTTP app listening on http://{host}:{port}")
    HTTPServer((host, port), DemoHandler).serve_forever()
