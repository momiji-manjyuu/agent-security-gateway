"""Loopback-only ASG inspector relay to the operator-selected LAN model."""
from http.server import BaseHTTPRequestHandler, HTTPServer
import json

from contract import encode, exact_keys, limited_text, load_json, require
from model_broker import INSPECTOR_MODEL, complete


class Server(HTTPServer):
    request_queue_size = 4
    completed_requests = 0

    def get_request(self):
        connection, address = super().get_request()
        connection.settimeout(5)
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
        self.reply(200 if self.path == '/healthz' else 404, {'service': 'asg-inspector-relay',
                   'model': INSPECTOR_MODEL, 'completed_requests': self.server.completed_requests})

    def do_POST(self):
        try:
            require(self.path == '/v1/chat/completions')
            require(not self.headers.get('Transfer-Encoding'))
            require(len(self.headers.get_all('Content-Length', [])) == 1)
            size = int(self.headers['Content-Length'])
            require(0 < size <= 32768)
            body = load_json(self.rfile.read(size), 32768)
            exact_keys(body, {'model', 'messages', 'max_tokens', 'temperature', 'stream'})
            require(body['model'] == INSPECTOR_MODEL and body['stream'] is False and body['temperature'] == 0)
            require(type(body['max_tokens']) is int and 1 <= body['max_tokens'] <= 2048)
            require(type(body['messages']) is list and len(body['messages']) == 2)
            for message, role in zip(body['messages'], ['system', 'user']):
                exact_keys(message, {'role', 'content'})
                require(message['role'] == role)
                limited_text(message['content'], 12000, True)
            content = complete(INSPECTOR_MODEL, body['messages'], body['max_tokens'], timeout=45)
            self.server.completed_requests += 1
            self.reply(200, {'model': INSPECTOR_MODEL, 'choices': [{'finish_reason': 'stop',
                       'message': {'role': 'assistant', 'content': content}}]})
        except Exception:
            self.reply(502, {'error': {'code': 'inspector_unavailable'}})


if __name__ == '__main__':
    Server(('127.0.0.1', 14000), Handler).serve_forever()
