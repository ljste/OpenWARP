"""Check an installed OpenWARP on unrestricted Wi-Fi with its kill switch armed."""
import json
import socket
import struct
import subprocess
import time
from pathlib import Path
from typing import BinaryIO


ROOT = Path(__file__).resolve().parents[1]
CONTROL = '/var/run/io.github.ljste.openwarp.portal.sock'


def read(stream: BinaryIO, size: int) -> bytes:
    data = bytearray()
    while len(data) < size:
        chunk = stream.read(size - len(data))
        if not chunk:
            raise EOFError('The Wi-Fi relay closed the connection')
        data.extend(chunk)
    return bytes(data)


def request(stream: BinaryIO, secret: str, host: str, port: int) -> int:
    stream.write(bytes([5, 1, 2]))
    assert read(stream, 2) == bytes([5, 2])
    password = secret.encode()
    stream.write(bytes([1, 8]) + b'openwarp' + bytes([len(password)]) + password)
    assert read(stream, 2) == bytes([1, 0])
    name = host.encode()
    stream.write(bytes([5, 1, 0, 3, len(name)]) + name + struct.pack('!H', port))
    return read(stream, 10)[1]


def check() -> None:
    assert Path('/var/db/io.github.ljste.openwarp.kill-switch').read_text() == 'armed'
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as channel:
        channel.settimeout(8)
        channel.connect(CONTROL)
        with channel.makefile('rb') as control:
            config = json.loads(control.readline(8192))
        if 'error' in config:
            raise RuntimeError(config['error'])
        listener = ('127.0.0.1', config['port'])
        with socket.create_connection(listener, timeout=5) as peer:
            time.sleep(.1)
            peer.sendall(bytes([5, 1, 0]))
            with peer.makefile('rb') as stream:
                assert read(stream, 2) == bytes([5, 255])
        for host, port in [('127.0.0.1', 80), ('captive.apple.com', 22), ('captive.apple.com', 80)]:
            with socket.create_connection(listener, timeout=15) as peer, peer.makefile('rwb', buffering=0) as stream:
                result = request(stream, config['secret'], host, port)
                if (host, port) == ('captive.apple.com', 80):
                    assert result == 0, 'Wi-Fi DNS or TCP failed'
                    stream.write(b'GET /hotspot-detect.html HTTP/1.0\r\nHost: captive.apple.com\r\n\r\n')
                    assert b'<title>success</title>' in stream.read().lower()
                else:
                    assert result != 0
        devices = subprocess.check_output(['/usr/sbin/networksetup', '-listallhardwareports'], text=True)
        wifi = devices.split('Hardware Port: Wi-Fi\nDevice: ', 1)[1].splitlines()[0]
        for option, ip in [('-4', '1.1.1.1'), ('-6', '[2606:4700:4700::1111]')]:
            attempt = subprocess.run(['/usr/bin/curl', '-q', option, '--noproxy', '*', '--interface', wifi,
                                      '--max-time', '3', '--silent', '--output', '/dev/null', '--resolve',
                                      f'one.one.one.one:443:{ip}', 'https://one.one.one.one/cdn-cgi/trace'])
            assert attempt.returncode != 0, 'An ordinary process connected directly over Wi-Fi'
        subprocess.run([str(ROOT / 'script/verify_connection.sh')], check=True)
    for _ in range(30):
        try:
            with socket.create_connection(listener, timeout=.2):
                time.sleep(.1)
        except ConnectionRefusedError:
            break
    else:
        raise AssertionError('Relay remained open after session end')
    print('Verified isolated Wi-Fi DNS and HTTP, ordinary IPv4/IPv6 blocking, and relay shutdown.')


if __name__ == '__main__':
    check()
