"""Bounded two-person TLS relay. Inner TLS records remain opaque to the relay."""
#ver 2.0 sig @michael_n72
import argparse
import json
import re
import socket
import ssl
import struct
import threading

MAX_FRAME = 65536


def receive_exact(sock, size):
    data = bytearray()
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise EOFError('Connection closed')
        data.extend(chunk)
    return bytes(data)


def receive_frame(sock):
    size = struct.unpack('!I', receive_exact(sock, 4))[0]
    if not 0 < size <= MAX_FRAME:
        raise ValueError('Invalid frame size')
    return receive_exact(sock, size)


def send_frame(sock, payload):
    if not 0 < len(payload) <= MAX_FRAME:
        raise ValueError('Invalid frame size')
    sock.sendall(struct.pack('!I', len(payload)) + payload)


def shutdown(sock):
    try:
        sock.shutdown(socket.SHUT_RDWR)
    except OSError:
        pass


class Pair:
    def __init__(self):
        self.peers = {}
        self.writers = {}
        self.matched = threading.Event()
        self.ready = threading.Event()
        self.ready_count = 0
        self.closed = False


class Relay:
    def __init__(self, context, max_clients=32):
        self.context = context
        self.slots = threading.BoundedSemaphore(max_clients)
        self.lock = threading.Lock()
        self.rooms = {}
        self.sockets = set()

    def accept(self, raw):
        if not self.slots.acquire(blocking=False):
            raw.close()
            return
        threading.Thread(target=self.handle, args=(raw,), daemon=True).start()

    def handle(self, raw):
        peer, pair, room = None, None, None
        try:
            raw.settimeout(10)
            peer = self.context.wrap_socket(raw, server_side=True)
            with self.lock:
                self.sockets.add(peer)
            hello = json.loads(receive_frame(peer))
            if not isinstance(hello, dict):
                raise ValueError('Invalid hello')
            room, role = hello.get('room'), hello.get('role')
            if not isinstance(room, str) or not re.fullmatch('[a-f0-9]{64}', room):
                raise ValueError('Invalid room')
            if type(role) is not int or role not in (0, 1):
                raise ValueError('Invalid role')
            with self.lock:
                candidate = self.rooms.setdefault(room, Pair())
                if role in candidate.peers or candidate.closed:
                    raise ValueError('Role occupied')
                pair = candidate
                pair.peers[role] = peer
                pair.writers[role] = threading.Lock()
                if len(pair.peers) == 2:
                    pair.matched.set()
            if not pair.matched.wait(120):
                raise TimeoutError('Partner not online')
            with self.lock:
                if pair.closed:
                    raise EOFError('Pair closed')
                target = pair.peers[1 - role]
                target_lock = pair.writers[1 - role]
            with pair.writers[role]:
                send_frame(peer, b'READY')
            with self.lock:
                pair.ready_count += 1
                if pair.ready_count == 2:
                    pair.ready.set()
            if not pair.ready.wait(10):
                raise TimeoutError('Pair startup timed out')
            peer.settimeout(30)
            while True:
                payload = receive_frame(peer)
                with target_lock:
                    send_frame(target, payload)
        except (OSError, EOFError, ValueError, TypeError, UnicodeError):
            pass
        finally:
            victims = []
            with self.lock:
                if pair is not None:
                    pair.closed = True
                    pair.matched.set()
                    pair.ready.set()
                    victims = list(pair.peers.values())
                    if self.rooms.get(room) is pair:
                        del self.rooms[room]
                if peer is not None:
                    self.sockets.discard(peer)
            for victim in victims:
                shutdown(victim)
            if peer is not None:
                peer.close()
            else:
                raw.close()
            self.slots.release()

    def close(self):
        with self.lock:
            peers = list(self.sockets)
            for pair in self.rooms.values():
                pair.closed = True
                pair.matched.set()
                pair.ready.set()
        for peer in peers:
            shutdown(peer)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--host', default='127.0.0.1')
    parser.add_argument('--port', type=int, default=5000)
    parser.add_argument('--cert', default='cert.pem')
    parser.add_argument('--key', default='key.pem')
    args = parser.parse_args()
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    try:
        context.load_cert_chain(args.cert, args.key)
    except OSError as exc:
        parser.exit(1, f'Cannot load relay certificate: {exc}\nSee README.md for setup.\n')
    relay = Relay(context)
    with socket.socket() as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((args.host, args.port))
        listener.listen(32)
        listener.settimeout(1)
        print(f'Relay listening on {args.host}:{args.port}. Ctrl+C to stop.')
        try:
            while True:
                try:
                    raw, _ = listener.accept()
                except socket.timeout:
                    continue
                relay.accept(raw)
        except KeyboardInterrupt:
            pass
        finally:
            relay.close()


if __name__ == '__main__':
    main()
