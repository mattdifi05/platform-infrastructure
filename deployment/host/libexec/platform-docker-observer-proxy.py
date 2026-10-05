#!/usr/bin/python3
"""Bounded, read-only Docker API for the infrastructure observer."""
import http.client
import http.server
import json
import os
import re
import socket
import socketserver
import threading
import time
import urllib.parse

SOCKET = os.environ.get('OBSERVER_PROXY_SOCKET', '/run/platform-docker-observer/docker.sock')
UPSTREAM = os.environ.get('OBSERVER_PROXY_UPSTREAM', '/run/docker.sock')
MAX_BODY = 8 * 1024 * 1024


class DockerConnection(http.client.HTTPConnection):
    def connect(self):
        remaining = getattr(self, 'absolute_deadline', time.monotonic() + 2) - time.monotonic()
        if remaining <= 0:
            raise TimeoutError('Request deadline elapsed')
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.raw_sock = self.sock
        self.sock.settimeout(min(2, remaining))
        self.sock.connect(UPSTREAM)


def admitted_path(path):
    parsed = urllib.parse.urlsplit(path)
    if parsed.scheme or parsed.netloc or parsed.fragment or '%' in parsed.path:
        return None
    route = re.sub(r'^/v1\.[0-9]{1,3}/', '/', parsed.path)
    try:
        pairs = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True, strict_parsing=True) if parsed.query else []
    except ValueError:
        return None
    query = dict(pairs)
    if len(query) != len(pairs):
        return None
    if route == '/containers/json':
        if query != {'all': '1', 'limit': '100'}:
            return None
    else:
        match = re.fullmatch(r'/containers/[a-f0-9]{64}/(json|stats|logs)', route)
        if not match:
            return None
        kind = match.group(1)
        if kind == 'json' and query:
            return None
        if kind == 'stats' and query != {'stream': 'false', 'one-shot': 'true'}:
            return None
        if kind == 'logs':
            if set(query) != {'stdout', 'stderr', 'tail', 'timestamps', 'since'}:
                return None
            if any(query[k] != 'true' for k in ['stdout', 'stderr', 'timestamps']) or query['tail'] != '200':
                return None
            if not query['since'].isdigit() or not time.time() - 90000 <= int(query['since']) <= time.time() + 60:
                return None
    return route + ('?' + urllib.parse.urlencode(query) if query else '')


def limited_inspect(data):
    state = data.get('State') or {}
    host = data.get('HostConfig') or {}
    config = data.get('Config') or {}
    health = state.get('Health') or {}
    allowed_state = {k: state[k] for k in ['Status', 'Running', 'Paused', 'Restarting', 'ExitCode', 'StartedAt', 'FinishedAt'] if k in state}
    if health:
        allowed_state['Health'] = {k: health[k] for k in ['Status', 'FailingStreak'] if k in health}
        allowed_state['Health']['Log'] = (health.get('Log') or [])[-3:]
    return {
        'Id': data.get('Id'), 'Name': data.get('Name'), 'Image': data.get('Image'),
        'Config': {'Image': config.get('Image')}, 'State': allowed_state,
        'RestartCount': data.get('RestartCount', 0),
        'HostConfig': {k: host[k] for k in ['Memory', 'NanoCpus', 'PidsLimit'] if k in host},
        'Mounts': [{k: m[k] for k in ['Type', 'Destination'] if k in m} for m in data.get('Mounts') or []],
    }


class Handler(http.server.BaseHTTPRequestHandler):
    server_version = 'PlatformObserverProxy/1'
    protocol_version = 'HTTP/1.0'

    def setup(self):
        super().setup()
        self.connection.settimeout(2)
        self.upstream = None
        self.expired = threading.Event()
        self.absolute_deadline = time.monotonic() + 2.5
        self.deadline = threading.Timer(2.5, self.expire)
        self.deadline.daemon = True
        self.deadline.start()

    def expire(self):
        self.expired.set()
        for sock in [self.connection, getattr(self.upstream, 'raw_sock', None)]:
            if sock is not None:
                try:
                    sock.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass

    def finish(self):
        self.deadline.cancel()
        super().finish()

    def log_message(self, *_):
        pass

    def reply(self, code, body, content_type='application/json'):
        if self.expired.is_set():
            return
        try:
            self.send_response(code)
            self.send_header('Content-Type', content_type)
            self.send_header('Content-Length', str(len(body)))
            self.send_header('Connection', 'close')
            self.end_headers()
            self.wfile.write(body)
        except OSError:
            pass

    def deny(self):
        self.reply(403, b'{"error":"Docker operation not admitted"}')

    do_POST = do_PUT = do_PATCH = do_DELETE = do_HEAD = do_OPTIONS = do_CONNECT = do_TRACE = deny

    def do_GET(self):
        if self.expired.is_set():
            return
        if self.headers.get_all('Transfer-Encoding') or self.headers.get_all('Content-Length') not in (None, ['0']):
            return self.deny()
        path = admitted_path(self.path)
        if path is None:
            return self.deny()
        connection = DockerConnection('localhost', timeout=2)
        connection.absolute_deadline = self.absolute_deadline
        self.upstream = connection
        try:
            if self.expired.is_set():
                return
            connection.request('GET', path, headers={'Connection': 'close'})
            response = connection.getresponse()
            body = response.read(MAX_BODY + 1)
            if len(body) > MAX_BODY:
                return self.reply(502, b'{"error":"Docker response exceeds bound"}')
            if response.status == 200 and re.fullmatch(r'/containers/[a-f0-9]{64}/json', path):
                body = json.dumps(limited_inspect(json.loads(body))).encode()
            elif response.status == 200 and path.startswith('/containers/json?'):
                rows = json.loads(body)
                for row in rows:
                    row.pop('Labels', None)
                    row.pop('Command', None)
                    row['Mounts'] = [{k: m[k] for k in ['Type', 'Destination'] if k in m} for m in row.get('Mounts') or []]
                body = json.dumps(rows).encode()
            self.reply(response.status, body, response.getheader('Content-Type', 'application/json'))
        except (OSError, ValueError, http.client.HTTPException):
            self.reply(502, b'{"error":"Docker request failed"}')
        finally:
            connection.close()


class Server(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    # Keep both concurrency and total request lifetime bounded.
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, *args, **kwargs):
        self.slots = threading.BoundedSemaphore(4)
        super().__init__(*args, **kwargs)

    def process_request(self, request, client_address):
        if not self.slots.acquire(blocking=False):
            try:
                request.settimeout(0.1)
                request.sendall(b'HTTP/1.0 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n')
            finally:
                self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self.slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.slots.release()


if __name__ == '__main__':
    if os.path.exists(SOCKET):
        os.unlink(SOCKET)
    with Server(SOCKET, Handler) as server:
        os.chmod(SOCKET, 0o660)
        server.serve_forever()
