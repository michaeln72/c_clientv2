"""Pinned-identity, end-to-end TLS 1.3 terminal messenger."""
#ver 2.0 sig @michael_n72
import argparse
import curses
import datetime
import getpass
import hashlib
import hmac
import json
import math
import os
from pathlib import Path
import select
import socket
import ssl
import textwrap
import threading
import time
import uuid
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from server import receive_frame, send_frame, shutdown

MAX_CHARACTERS = 2000


def message_lifetime(text, minimum=10):
    return min(60, max(minimum, math.ceil(len(text) / 25)))


def decode_message(token, now):
    message = json.loads(token)
    if not isinstance(message, dict):
        raise ValueError('Invalid message')
    sender, text = message.get('sender'), message.get('text')
    sent, lifetime = message.get('sent_at'), message.get('expires_after')
    ident = message.get('id')
    if not isinstance(sender, str) or not 1 <= len(sender) <= 32:
        raise ValueError('Invalid sender')
    if not isinstance(text, str) or not 1 <= len(text) <= MAX_CHARACTERS:
        raise ValueError('Invalid text')
    if not isinstance(ident, str) or len(ident) != 32:
        raise ValueError('Invalid ID')
    if any(type(v) not in (int, float) or not math.isfinite(v) for v in (sent, lifetime)):
        raise ValueError('Invalid time')
    if not 1 <= lifetime <= 60 or sent > now + 5:
        raise ValueError('Invalid lifetime or timestamp')
    return message if sent + lifetime > now else None


def safe_text(value):
    return ''.join(c if c.isprintable() else ' ' for c in value)


def certificate(path):
    return x509.load_pem_x509_certificate(Path(path).read_bytes())


def fingerprint(cert):
    return cert.fingerprint(hashes.SHA256()).hex()


def make_identity(directory, name, password):
    directory = Path(directory)
    directory.mkdir(mode=0o700, parents=True, exist_ok=False)
    key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(minutes=5))
            .not_valid_after(now + datetime.timedelta(days=365))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False,
                           key_encipherment=False, data_encipherment=False, key_agreement=False,
                           key_cert_sign=False, crl_sign=False, encipher_only=False,
                           decipher_only=False), critical=True)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH,
                                                 ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
            .sign(key, hashes.SHA256()))
    for filename, data in [('identity-key.pem', key.private_bytes(serialization.Encoding.PEM,
                              serialization.PrivateFormat.PKCS8,
                              serialization.BestAvailableEncryption(password.encode()))),
                           ('identity.pem', cert.public_bytes(serialization.Encoding.PEM))]:
        fd = os.open(directory / filename, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(data)
    return cert


def trust_contact(directory, source, expected):
    cert = certificate(source)
    expected = expected.lower().replace(':', '').replace(' ', '')
    if not hmac.compare_digest(fingerprint(cert), expected):
        raise ValueError('Fingerprint does not match. Contact was not trusted.')
    names = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    if len(names) != 1 or not 1 <= len(names[0].value) <= 32 or not names[0].value.isprintable():
        raise ValueError('Contact certificate needs one printable name of 1–32 characters')
    destination = Path(directory) / 'peer.pem'
    # Never silently replace an already trusted identity.
    fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(cert.public_bytes(serialization.Encoding.PEM))
    return cert


def peer_context(directory, password):
    directory = Path(directory)
    own = certificate(directory / 'identity.pem')
    peer = certificate(directory / 'peer.pem')
    own_pin, peer_pin = fingerprint(own), fingerprint(peer)
    if own_pin == peer_pin:
        raise ValueError('Your contact must have a different identity')
    role = 0 if own_pin < peer_pin else 1
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT if role == 0 else ssl.PROTOCOL_TLS_SERVER)
    if role == 0:
        # Identity is an exact pinned certificate, not a DNS hostname.
        context.check_hostname = False
    context.verify_mode = ssl.CERT_REQUIRED
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.maximum_version = ssl.TLSVersion.TLSv1_3
    context.load_verify_locations(cafile=str(directory / 'peer.pem'))
    context.load_cert_chain(str(directory / 'identity.pem'), str(directory / 'identity-key.pem'), password)
    if role == 1:
        context.num_tickets = 0
    room = hashlib.sha256(('messenger-v2:' + ':'.join(sorted([own_pin, peer_pin]))).encode()).hexdigest()
    peer_name = peer.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    return context, role, room, peer_pin, peer_name


class Tunnel:
    """Bridge opaque TLS records to framed relay transport; never handles chat plaintext."""
    def __init__(self, outer):
        self.outer = outer
        self.endpoint, self.bridge = socket.socketpair()
        self.bridge.settimeout(10)
        self.threads = []
        for handler in (self.upload, self.download):
            thread = threading.Thread(target=self.pump, args=(handler,), daemon=True)
            self.threads.append(thread)
            thread.start()

    def pump(self, handler):
        try:
            handler()
        except (OSError, EOFError, ValueError):
            pass
        finally:
            shutdown(self.bridge)
            shutdown(self.outer)

    def upload(self):
        while True:
            # Idle reads do not interrupt a healthy session.
            try:
                data = self.bridge.recv(16384)
            except socket.timeout:
                continue
            if not data:
                return
            send_frame(self.outer, data)

    def download(self):
        while True:
            self.bridge.sendall(receive_frame(self.outer))

    def close(self):
        shutdown(self.bridge)
        shutdown(self.outer)
        self.bridge.close()
        self.endpoint.close()
        for thread in self.threads:
            thread.join(timeout=1)


class Connection:
    """Authenticated end-to-end TLS connection, with fresh handshakes on reconnect."""
    def __init__(self, host, port, relay_context, inner_context, role, room,
                 peer_pin, peer_name, on_message):
        self.host, self.port, self.relay_context = host, port, relay_context
        self.inner_context, self.role, self.room = inner_context, role, room
        self.peer_pin, self.peer_name = peer_pin, peer_name
        self.on_message = on_message
        self.lock = threading.Lock()
        self.stop = threading.Event()
        self.sock = None
        self.transport = None
        self.status = 'Connecting…'
        self.thread = threading.Thread(target=self.run, daemon=True)

    def start(self):
        self.thread.start()

    def send(self, payload):
        with self.lock:
            if self.sock is None:
                raise ConnectionError('Disconnected; draft kept. Try after reconnecting.')
            try:
                send_frame(self.sock, payload)
            except OSError:
                shutdown(self.sock)
                raise ConnectionError('Send uncertain; draft kept. Check with your contact before retrying.')

    def run(self):
        delay = 1
        while not self.stop.is_set():
            outer, tunnel, inner = None, None, None
            try:
                self.status = 'Connecting to relay…'
                with socket.create_connection((self.host, self.port), timeout=5) as raw:
                    outer = self.relay_context.wrap_socket(raw, server_hostname=self.host)
                with self.lock:
                    self.transport = outer
                if self.stop.is_set():
                    return
                outer.settimeout(125)
                send_frame(outer, json.dumps(dict(room=self.room, role=self.role)).encode())
                self.status = 'Waiting for your verified contact…'
                if receive_frame(outer) != b'READY':
                    raise ValueError('Invalid relay reply')
                outer.settimeout(30)
                tunnel = Tunnel(outer)
                tunnel.endpoint.settimeout(10)
                self.status = 'Authenticating contact…'
                inner = self.inner_context.wrap_socket(tunnel.endpoint, server_side=self.role == 1)
                actual = hashlib.sha256(inner.getpeercert(binary_form=True)).hexdigest()
                if not hmac.compare_digest(actual, self.peer_pin):
                    raise ssl.SSLCertVerificationError('Peer certificate changed')
                inner.settimeout(5)
                with self.lock:
                    if self.stop.is_set():
                        return
                    self.sock = inner
                self.status = f'Verified: {safe_text(self.peer_name)} | end-to-end TLS 1.3'
                delay = 1
                last_ping = last_reply = time.monotonic()
                while not self.stop.is_set():
                    now = time.monotonic()
                    if now - last_ping >= 5:
                        self.send(b'PING')
                        last_ping = now
                    if now - last_reply > 15:
                        raise ConnectionError('Contact heartbeat timed out')
                    readable, _, _ = select.select([inner], [], [], 0.2)
                    if readable or inner.pending():
                        token = receive_frame(inner)
                        if token == b'PING':
                            self.send(b'PONG')
                        elif token == b'PONG':
                            last_reply = time.monotonic()
                        else:
                            # Names supplied in JSON are not trusted: bind display to verified identity.
                            message = json.loads(token)
                            if not isinstance(message, dict):
                                raise ValueError('Invalid message')
                            message['sender'] = self.peer_name
                            self.on_message(json.dumps(message).encode())
            except ssl.SSLCertVerificationError:
                self.status = 'SECURITY: certificate verification failed. Sending blocked; restart after checking pins.'
                return
            except ssl.SSLError:
                self.status = 'SECURITY: TLS handshake or integrity check failed. Sending blocked; restart to retry.'
                return
            except (OSError, EOFError, ValueError, UnicodeError):
                self.status = f'Disconnected. Retrying in {delay}s…'
            finally:
                with self.lock:
                    self.sock = None
                    self.transport = None
                if inner is not None:
                    inner.close()
                if tunnel is not None:
                    tunnel.close()
                if outer is not None:
                    outer.close()
            if self.stop.wait(delay):
                break
            delay = min(delay * 2, 15)

    def close(self):
        self.stop.set()
        with self.lock:
            for peer in (self.sock, self.transport):
                if peer is not None:
                    shutdown(peer)
        self.thread.join(timeout=6)


def run_ui(screen, connection_args, username, lifetime):
    messages, seen = [], {}
    lock = threading.Lock()
    notice = ['Enter to send | PgUp/PgDn scroll | /help | /quit']

    def receive(token):
        try:
            now = time.time()
            message = decode_message(token, now)
            with lock:
                for ident in list(seen):
                    if seen[ident] < now:
                        del seen[ident]
                if message and message['id'] not in seen:
                    seen[message['id']] = now + 65
                    messages.append(message)
                    del messages[:-200]
        except (ValueError, TypeError, UnicodeError):
            with lock:
                notice[0] = 'Ignored an invalid or expired message.'

    connection = Connection(*connection_args, receive)
    connection.start()
    scroll = 0
    screen.timeout(100)
    screen.keypad(True)
    typed = ''
    try:
        while True:
            height, width = screen.getmaxyx()
            screen.erase()
            with lock:
                now = time.time()
                messages[:] = [m for m in messages if m['sent_at'] + m['expires_after'] > now]
                lines = []
                for message in messages:
                    remaining = math.ceil(message['sent_at'] + message['expires_after'] - now)
                    label = f"{safe_text(message['sender'])} [{remaining}s]: "
                    lines.extend(textwrap.wrap(label + safe_text(message['text']),
                                               width=max(1, width - 1)))
                current_status = connection.status + ' | ' + notice[0]
            def write(row, value):
                if 0 <= row < height and width > 1:
                    try:
                        screen.addnstr(row, 0, value, width - 1)
                    except curses.error:
                        pass
            write(0, f'Encrypted chat | {username} | {MAX_CHARACTERS - len(typed)} chars left | {message_lifetime(typed, lifetime)}s')
            available = max(0, height - 4)
            scroll = min(scroll, max(0, len(lines) - available))
            end = len(lines) - scroll
            visible = lines[max(0, end - available):end] if available else []
            for row, line in enumerate(visible, 1):
                write(row, line)
            write(height - 2, current_status)
            write(height - 1, '> ' + typed[-max(1, width - 4):])
            screen.refresh()
            try:
                key = screen.get_wch()
            except curses.error:
                continue
            if key in ('\n', '\r', curses.KEY_ENTER):
                if typed.strip() == '/quit':
                    break
                if typed.strip() == '/help':
                    with lock:
                        notice[0] = 'Enter sends; PgUp/PgDn scroll; /clear clears history; /quit exits.'
                    typed = ''
                elif typed.strip() == '/clear':
                    with lock:
                        messages.clear()
                    typed = ''
                    scroll = 0
                elif typed.strip():
                    message = dict(id=uuid.uuid4().hex, sender=username, text=typed,
                                   sent_at=time.time(), expires_after=message_lifetime(typed, lifetime))
                    try:
                        connection.send(json.dumps(message).encode())
                        receive(json.dumps(message).encode())
                        typed = ''
                        scroll = 0
                        with lock:
                            notice[0] = 'Sent through authenticated session; receipt is not confirmed.'
                    except OSError as exc:
                        with lock:
                            notice[0] = str(exc)
            elif key == curses.KEY_PPAGE:
                scroll += max(1, height - 4)
            elif key == curses.KEY_NPAGE:
                scroll = max(0, scroll - max(1, height - 4))
            elif key in ('\b', '\x7f', curses.KEY_BACKSPACE):
                typed = typed[:-1]
            elif isinstance(key, str) and key.isprintable() and len(typed) < MAX_CHARACTERS:
                typed += key
    finally:
        connection.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--host', default='localhost')
    parser.add_argument('--port', type=int, default=5000)
    parser.add_argument('--ca', default='cert.pem', help='Trusted relay certificate')
    parser.add_argument('--identity-dir', default='identity')
    parser.add_argument('--init', action='store_true', help='Create a password-protected identity')
    parser.add_argument('--name', help='Name for a new identity')
    parser.add_argument('--fingerprint', metavar='CERT', help='Display certificate fingerprint and exit')
    parser.add_argument('--trust', metavar='CERT', help='Import a contact certificate after fingerprint comparison')
    parser.add_argument('--expect-fingerprint', help='Fingerprint received through a trusted channel')
    parser.add_argument('--lifetime', type=int, choices=range(10, 61), default=10)
    args = parser.parse_args()
    try:
        if args.fingerprint:
            cert = certificate(args.fingerprint)
            print('SHA-256:', fingerprint(cert))
            return
        if args.init:
            name = args.name or input('Your name: ').strip()
            if not 1 <= len(name) <= 32 or not name.isprintable():
                parser.error('Name must be 1–32 printable characters')
            password = getpass.getpass('New identity password (12+ characters): ')
            if len(password) < 12 or password != getpass.getpass('Confirm password: '):
                parser.error('Passwords must match and have at least 12 characters')
            cert = make_identity(args.identity_dir, name, password)
            print('Identity created. Share only identity.pem, never identity-key.pem.')
            print('SHA-256:', fingerprint(cert))
            return
        if args.trust:
            if not args.expect_fingerprint:
                parser.error('--trust requires --expect-fingerprint from a trusted channel')
            trust_contact(args.identity_dir, args.trust, args.expect_fingerprint)
            print('Contact pinned. A replacement cannot be imported silently.')
            return
        password = getpass.getpass('Identity password: ')
        context, role, room, pin, peer_name = peer_context(args.identity_dir, password)
        del password
        relay_context = ssl.create_default_context(cafile=args.ca)
        relay_context.minimum_version = ssl.TLSVersion.TLSv1_3
        own = certificate(Path(args.identity_dir) / 'identity.pem')
        username = own.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        connection_args = (args.host, args.port, relay_context, context, role, room, pin, peer_name)
        curses.wrapper(run_ui, connection_args, username, args.lifetime)
    except KeyboardInterrupt:
        pass
    except (OSError, ValueError, curses.error) as exc:
        parser.exit(1, f'Unable to start: {exc}\nSee README.md for identity and certificate setup.\n')


if __name__ == '__main__':
    main()
