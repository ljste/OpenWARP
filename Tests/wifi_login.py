"""Exercise the macOS sign-in window against a simulated captive Wi-Fi network."""
import json
import secrets
import socket
import socketserver
import subprocess
import tempfile
import threading
from pathlib import Path
from typing import BinaryIO, cast

ROOT = Path(__file__).resolve().parents[1]


def read_exact(stream: BinaryIO, size: int) -> bytes:
    data = stream.read(size)
    if len(data) != size:
        raise EOFError
    return data


class PortalServer(socketserver.ThreadingTCPServer):
    daemon_threads = True
    key: str
    signed_in: threading.Event


class Portal(socketserver.StreamRequestHandler):
    def handle(self) -> None:
        try:
            self.serve()
        except (EOFError, ConnectionError):
            pass

    def serve(self) -> None:
        server = cast(PortalServer, self.server)
        version, count = read_exact(self.rfile, 2)
        methods = read_exact(self.rfile, count)
        assert version == 5 and 2 in methods, methods
        self.wfile.write(bytes([5, 2]))
        assert read_exact(self.rfile, 1) == bytes([1])
        user = read_exact(self.rfile, read_exact(self.rfile, 1)[0])
        password = read_exact(self.rfile, read_exact(self.rfile, 1)[0])
        assert user == b'openwarp' and password == server.key.encode()
        self.wfile.write(bytes([1, 0]))
        assert read_exact(self.rfile, 4) == bytes([5, 1, 0, 3])
        host = read_exact(self.rfile, read_exact(self.rfile, 1)[0])
        assert int.from_bytes(read_exact(self.rfile, 2), 'big') == 80
        self.wfile.write(bytes([5, 0, 0, 1, 0, 0, 0, 0, 0, 0]))
        line = self.rfile.readline(8192)
        while self.rfile.readline(8192) not in (b'\r\n', b'\n', b''):
            pass
        status = b'200 OK'
        headers = b''
        if host == b'captive.apple.com':
            if server.signed_in.is_set():
                body = b'<HTML><HEAD><TITLE>Success</TITLE></HEAD><BODY>Success</BODY></HTML>'
            else:
                status, headers, body = b'302 Found', b'Location: http://portal.example.test/login\r\n', b''
        elif host == b'portal.example.test' and line.startswith(b'GET /login '):
            body = b'<form method="POST" action="/accept"></form><script>document.forms[0].submit()</script>'
        elif host == b'portal.example.test' and line.startswith(b'POST /accept '):
            server.signed_in.set()
            body = b'Signed in'
        else:
            status, body = b'404 Not Found', b''
        self.wfile.write(b'HTTP/1.1 ' + status + b'\r\n' + headers + b'Content-Type: text/html\r\nConnection: close\r\nContent-Length: ' + str(len(body)).encode() + b'\r\n\r\n' + body)


def main() -> None:
    with tempfile.TemporaryDirectory(dir='/tmp') as directory, socket.socket(socket.AF_UNIX) as control:
        work = Path(directory)
        endpoint = str(work / 'portal.sock')
        control.bind(endpoint)
        control.listen(1)
        control.settimeout(8)
        source = (ROOT / 'WiFiLogin/main.swift').read_text().replace('/var/run/io.github.ljste.openwarp.portal.sock', endpoint)
        (work / 'main.swift').write_text(source)
        bundle = work / 'WiFiLogin.app' / 'Contents'
        (bundle / 'MacOS').mkdir(parents=True)
        (bundle / 'Info.plist').write_bytes((ROOT / 'WiFiLogin/Info.plist').read_bytes())
        executable = bundle / 'MacOS/WiFiLogin'
        subprocess.run(['xcrun', 'swiftc', str(work / 'main.swift'), '-o', str(executable)], check=True)
        subprocess.run(['codesign', '-s', '-', str(bundle.parent)], check=True)
        with PortalServer(('127.0.0.1', 0), Portal) as proxy:
            proxy.signed_in = threading.Event()
            proxy.key = secrets.token_hex(32)
            threading.Thread(target=proxy.serve_forever, daemon=True).start()
            with subprocess.Popen([str(executable)], stdin=subprocess.PIPE) as child:
                try:
                    with control.accept()[0] as channel:
                        channel.sendall(json.dumps({'port': proxy.server_address[1], 'secret': proxy.key, 'api': ''}).encode() + b'\n')
                        assert child.wait(timeout=35) == 0
                        assert proxy.signed_in.is_set(), 'WebKit did not complete the sign-in form'
                finally:
                    if child.poll() is None:
                        child.kill()
                    proxy.shutdown()
    print('Verified authenticated proxy, captive redirect, WebKit form POST and automatic completion.')


if __name__ == '__main__':
    main()
