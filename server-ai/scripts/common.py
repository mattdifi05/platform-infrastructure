"""Shared bounded HTTP primitives for the private Server AI project readers."""

from __future__ import annotations

import hmac
import json
import os
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable


MAX_REQUEST_BYTES = 16 * 1024
MAX_RESPONSE_BYTES = 256 * 1024
TOKEN_PATH = Path("/run/secrets/server_ai_project_readers_token")


class ReaderError(Exception):
    def __init__(self, code: str, status: int = 400):
        super().__init__(code)
        self.code = code
        self.status = status


class BoundedThreadingHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = 8

    def __init__(self, server_address, handler):
        self._admission = threading.BoundedSemaphore(8)
        super().__init__(server_address, handler)

    def process_request(self, request, client_address):
        request.settimeout(5)
        if not self._admission.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self._admission.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._admission.release()


def load_token(path: Path = TOKEN_PATH) -> bytes:
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        value = os.read(descriptor, 513)
    finally:
        os.close(descriptor)
    value = value.strip()
    if not 32 <= len(value) <= 512 or any(byte <= 0x20 or byte >= 0x7F for byte in value):
        raise RuntimeError("project reader token is invalid")
    return value


def exact_object(value: Any, allowed: set[str], required: set[str]) -> dict[str, Any]:
    if not isinstance(value, dict) or not required.issubset(value) or not set(value).issubset(allowed):
        raise ReaderError("INPUT_LIMIT")
    return value


def json_bytes(value: Any) -> bytes:
    payload = json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8")
    if len(payload) > MAX_RESPONSE_BYTES:
        raise ReaderError("RESULT_LIMIT", 413)
    return payload


def make_handler(token: bytes, routes: dict[str, Callable[[dict[str, Any]], dict[str, Any]]]):
    concurrency = threading.BoundedSemaphore(4)
    class Handler(BaseHTTPRequestHandler):
        server_version = "ServerAIProjectReader/1"
        sys_version = ""

        def log_message(self, _format: str, *_args: object) -> None:
            # Request bodies, SQL, project paths and credentials never enter logs.
            return

        def _send(self, status: int, value: dict[str, Any]) -> None:
            try:
                payload = json_bytes(value)
            except ReaderError:
                status, payload = 413, b'{"available":false,"code":"RESULT_LIMIT"}'
            self.send_response(status)
            self.send_header("content-type", "application/json; charset=utf-8")
            self.send_header("cache-control", "no-store")
            self.send_header("content-length", str(len(payload)))
            self.send_header("x-content-type-options", "nosniff")
            self.end_headers()
            self.wfile.write(payload)

        def do_GET(self) -> None:  # noqa: N802
            if self.path == "/healthz":
                self._send(200, {"status": "ok"})
            else:
                self._send(404, {"available": False, "code": "NOT_FOUND"})

        def do_POST(self) -> None:  # noqa: N802
            if not concurrency.acquire(blocking=False):
                self._send(429, {"available": False, "code": "PROJECT_UNAVAILABLE"})
                return
            try:
                self._bounded_post()
            finally:
                concurrency.release()

        def _bounded_post(self) -> None:
            route = routes.get(self.path)
            if route is None:
                self._send(404, {"available": False, "code": "NOT_FOUND"})
                return
            supplied = self.headers.get("authorization", "")
            expected = "Bearer " + token.decode("ascii")
            if not hmac.compare_digest(supplied, expected):
                self._send(403, {"available": False, "code": "PROJECT_UNAVAILABLE"})
                return
            if self.headers.get_content_type() != "application/json":
                self._send(415, {"available": False, "code": "INPUT_LIMIT"})
                return
            try:
                length = int(self.headers.get("content-length", "-1"))
            except ValueError:
                length = -1
            if length < 2 or length > MAX_REQUEST_BYTES:
                self._send(413, {"available": False, "code": "INPUT_LIMIT"})
                return
            self.connection.settimeout(5)
            try:
                raw = self.rfile.read(length)
                if len(raw) != length:
                    raise ReaderError("INPUT_LIMIT")
                value = json.loads(raw)
                result = route(value)
                self._send(200, result)
            except ReaderError as error:
                self._send(error.status, {"available": False, "code": error.code})
            except (UnicodeDecodeError, json.JSONDecodeError, TimeoutError, ValueError):
                self._send(400, {"available": False, "code": "INPUT_LIMIT"})
            except Exception:
                self._send(503, {"available": False, "code": "PROJECT_UNAVAILABLE"})

    return Handler


def serve(port: int, token: bytes, routes: dict[str, Callable[[dict[str, Any]], dict[str, Any]]]) -> None:
    server = BoundedThreadingHTTPServer(("0.0.0.0", port), make_handler(token, routes))
    server.serve_forever(poll_interval=0.5)
