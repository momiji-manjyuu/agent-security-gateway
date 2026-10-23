"""Loopback-only ASG inspector relay to the operator-selected LAN model.

Concurrent but bounded: a thread per connection, at most RELAY_CONCURRENCY upstream calls at once, a per-request
deadline that covers queueing and one retry on a transient upstream failure.  Any failure is a non-200 reply, so the
gateway's llm_inspector fail_closed policy still applies.  The relay logs metadata only (timing, status, error class,
sizes); never prompts, snippets or model output.
"""
from http.server import BaseHTTPRequestHandler, HTTPServer
from socketserver import ThreadingMixIn
import http.client
import json
import os
import socket
import threading
import time
import uuid

from contract import BoundaryError, encode, exact_keys, limited_text, load_json, require
import model_broker
from model_broker import INSPECTOR_MODEL


def _env_int(name, default, low, high):
    raw = os.environ.get(name, '').strip()
    value = int(raw) if raw.isdigit() else default
    return max(low, min(high, value))


CONCURRENCY = _env_int('RELAY_CONCURRENCY', 4, 1, 16)        # simultaneous upstream model calls
DEADLINE_SECONDS = _env_int('RELAY_DEADLINE_SECONDS', 45, 5, 120)  # queue wait + attempts; keep below the gateway timeout
ATTEMPT_SECONDS = _env_int('RELAY_ATTEMPT_SECONDS', 30, 3, 120)    # one upstream attempt
MIN_RETRY_SECONDS = _env_int('RELAY_MIN_RETRY_SECONDS', 8, 1, 60)  # retry only if this much budget is left
READ_TIMEOUT_SECONDS = _env_int('RELAY_READ_TIMEOUT_SECONDS', 10, 1, 60)
LOG_PATH = os.environ.get('RELAY_LOG', os.path.join(os.path.dirname(os.path.abspath(__file__)), 'inspector_relay.log'))
LOG_MAX_BYTES = 5 * 1024 * 1024
TRANSIENT = (OSError, TimeoutError, socket.timeout, http.client.HTTPException, BoundaryError)

_slots = threading.BoundedSemaphore(CONCURRENCY)
_log_lock = threading.Lock()


def log_event(**fields):
    """Metadata only. Callers must never pass request or response content."""
    fields['ts'] = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
    line = json.dumps(fields, sort_keys=True) + '\n'
    with _log_lock:
        try:
            if os.path.exists(LOG_PATH) and os.path.getsize(LOG_PATH) > LOG_MAX_BYTES:
                os.replace(LOG_PATH, LOG_PATH + '.1')
            with open(LOG_PATH, 'a', encoding='utf-8') as handle:
                handle.write(line)
        except OSError:
            pass


def upstream(messages, max_tokens, deadline):
    """At most two attempts (one retry on a transient failure) within the deadline. Returns (content, attempts)."""
    attempts = 0
    while True:
        remaining = deadline - time.monotonic()
        attempts += 1
        try:
            return model_broker.complete(INSPECTOR_MODEL, messages, max_tokens, timeout=max(1.0, min(ATTEMPT_SECONDS, remaining))), attempts
        except TRANSIENT as exc:
            exc.relay_attempts = attempts
            if attempts >= 2 or deadline - time.monotonic() < MIN_RETRY_SECONDS:
                raise


class Server(ThreadingMixIn, HTTPServer):
    daemon_threads = True
    request_queue_size = 32
    completed_requests = 0
    _count_lock = threading.Lock()

    def get_request(self):
        connection, address = super().get_request()
        connection.settimeout(READ_TIMEOUT_SECONDS)
        return connection, address


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def reply(self, code, body):
        raw = encode(body)
        self.send_response(code)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):
        self.reply(200 if self.path == '/healthz' else 404, {'service': 'asg-inspector-relay', 'model': INSPECTOR_MODEL,
                   'completed_requests': self.server.completed_requests, 'concurrency': CONCURRENCY})

    def do_POST(self):
        started = time.monotonic()
        deadline = started + DEADLINE_SECONDS
        meta = {'event': 'inspect', 'req': uuid.uuid4().hex[:12], 'phase': 'validate', 'attempts': 0}
        status, body = 502, {'error': {'code': 'inspector_unavailable'}}
        try:
            require(self.path == '/v1/chat/completions')
            require(not self.headers.get('Transfer-Encoding'))
            require(len(self.headers.get_all('Content-Length', [])) == 1)
            size = int(self.headers['Content-Length'])
            require(0 < size <= 32768)
            meta['request_bytes'] = size
            payload = load_json(self.rfile.read(size), 32768)
            exact_keys(payload, {'model', 'messages', 'max_tokens', 'temperature', 'stream'})
            require(payload['model'] == INSPECTOR_MODEL and payload['stream'] is False and payload['temperature'] == 0)
            require(type(payload['max_tokens']) is int and 1 <= payload['max_tokens'] <= 2048)
            require(type(payload['messages']) is list and len(payload['messages']) == 2)
            for message, role in zip(payload['messages'], ['system', 'user']):
                exact_keys(message, {'role', 'content'})
                require(message['role'] == role)
                limited_text(message['content'], 12000, True)
        except Exception as exc:  # noqa: BLE001 - malformed request: refuse, log the class only
            status, body = 400, {'error': {'code': 'invalid_request'}}
            meta['error_class'] = type(exc).__name__
            self._finish(status, body, meta, started)
            return
        meta['phase'] = 'queue'
        if not _slots.acquire(timeout=max(0.0, deadline - time.monotonic() - MIN_RETRY_SECONDS)):
            status, body = 503, {'error': {'code': 'inspector_busy'}}
            meta['error_class'] = 'QueueTimeout'
            self._finish(status, body, meta, started)
            return
        try:
            meta['queue_ms'] = int((time.monotonic() - started) * 1000)
            meta['phase'] = 'upstream'
            content, meta['attempts'] = upstream(payload['messages'], payload['max_tokens'], deadline)
            with self.server._count_lock:
                self.server.completed_requests += 1
            status, body = 200, {'model': INSPECTOR_MODEL, 'choices': [{'finish_reason': 'stop',
                                 'message': {'role': 'assistant', 'content': content}}]}
            meta['response_chars'] = len(content)
        except Exception as exc:  # noqa: BLE001 - containment boundary; the gateway fails closed on non-200
            meta['error_class'] = type(exc).__name__
            meta['attempts'] = getattr(exc, 'relay_attempts', meta['attempts'] or 1)
        finally:
            _slots.release()
        self._finish(status, body, meta, started)

    def _finish(self, status, body, meta, started):
        meta['status'] = status
        meta['ms'] = int((time.monotonic() - started) * 1000)
        log_event(**meta)
        try:
            self.reply(status, body)
        except OSError:
            pass


if __name__ == '__main__':
    log_event(event='start', concurrency=CONCURRENCY, deadline_s=DEADLINE_SECONDS, attempt_s=ATTEMPT_SECONDS)
    Server(('127.0.0.1', int(os.environ.get('RELAY_PORT', '14000'))), Handler).serve_forever()
