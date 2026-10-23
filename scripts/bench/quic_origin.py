#!/usr/bin/env python3
"""Loopback-only HTTPS origin for quic_transport.py. Prints its bound port."""

import argparse
import hashlib
import http.server
import json
import re
import ssl
from urllib.parse import urlsplit

BLOCK = bytes(range(256)) * 4096
MAX_BYTES = 256 * 1024 * 1024


class Origin(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *_):
        pass

    def do_GET(self):
        match = re.fullmatch(r"/bytes/(\d+)", urlsplit(self.path).path)
        if not match or not 0 <= int(match[1]) <= MAX_BYTES:
            self.send_error(400)
            return
        remaining = int(match[1])
        self.send_response(200)
        self.send_header("Content-Length", str(remaining))
        self.end_headers()
        while remaining:
            block = BLOCK[:min(remaining, len(BLOCK))]
            self.wfile.write(block)
            remaining -= len(block)

    def do_POST(self):
        try:
            remaining = int(self.headers.get("Content-Length", "-1"))
        except ValueError:
            remaining = -1
        if not 0 <= remaining <= MAX_BYTES:
            self.send_error(400)
            return
        digest = hashlib.sha256()
        while remaining:
            data = self.rfile.read(min(remaining, len(BLOCK)))
            if not data:
                self.send_error(400)
                return
            digest.update(data)
            remaining -= len(data)
        result = digest.hexdigest().encode("ascii")
        self.send_response(200)
        self.send_header("Content-Length", str(len(result)))
        self.end_headers()
        self.wfile.write(result)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cert", required=True)
    parser.add_argument("--key", required=True)
    parser.add_argument("--port", type=int, default=0)
    args = parser.parse_args()
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(args.cert, args.key)
    with http.server.ThreadingHTTPServer(("127.0.0.1", args.port), Origin) as server:
        server.socket = context.wrap_socket(server.socket, server_side=True)
        print(json.dumps({"port": server.server_port}), flush=True)
        server.serve_forever()


if __name__ == "__main__":
    main()
