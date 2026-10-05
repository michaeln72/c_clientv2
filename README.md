# c_clientv2
# Authenticated disappearing messenger — version 2.0

A two-person terminal messenger using **mutually authenticated end-to-end TLS 1.3**, tunneled through a TLS relay. The relay transports opaque inner TLS records, only the participant clients terminate the inner session. This replaces the old shared Fernet key design.

This application has not received an independent security audit. It uses the standardized TLS 1.3 handshake and record protocol through Python/OpenSSL rather than inventing a cryptographic handshake. It is not an implementation of Signal, PQXDH, or Double Ratchet.

## Four source files

- `server.py`: two-participant routing, bounded connections, and frame helpers.
- `client.py`: password-protected identities, verified contact pins, end-to-end TLS, automatic reconnect, heartbeats, and curses UI.
- `requirements.txt`: dependencies.
- `README.md`: setup and security model.

Keep the Python files together. Certificates, identity keys, and the virtual environment are generated locally; never commit private keys.

The old client and server are incompatible with this version. `CHAT_KEY` is no longer used. Please make sure you completely update client side file prior to attempting a connection. **if you are a first-time user, this last part doesn't apply**

## 1. Install (each client and relay)

Requires Python 3.10+ and an OpenSSL build supporting TLS 1.3.

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
```

On Windows, use `.venv\Scripts\Activate.ps1` in PowerShell. The Windows-only requirement supplies curses. Restrict access to identity folders with Windows file permissions; Unix mode bits alone do not enforce Windows ACLs.

## 2. Create a relay certificate (once, relay computer)

For localhost testing:

```bash
openssl req -x509 -newkey rsa:3072 -sha256 -nodes \
  -keyout key.pem -out cert.pem -days 365 \
  -subj '/CN=localhost' \
  -addext 'subjectAltName=DNS:localhost,IP:127.0.0.1'
chmod 600 key.pem
python server.py
```

For another machine, the certificate must contain the actual relay hostname in its subject alternative name. Start with `python server.py --host 0.0.0.0` to listen beyond localhost, and use `--host relay.example` on the clients. Distribute the public relay `cert.pem` through a trusted channel. Use `--ca path/to/cert.pem` if needed. Never share the relay's `key.pem`.

## 3. Create your personal identity (once, each participant)

First user runs:

```bash
python client.py --init --name user1
```

Another user runs the same command with `--name user2` on the other computer. Each chooses a unique strong password with at least 12 characters; it is entered using a hidden prompt. This creates:

- `identity/identity.pem`: public identity certificate, safe to share.
- `identity/identity-key.pem`: encrypted private identity key; keep private.

The identity lasts one year. Back up the encrypted private key securely if needed; losing it requires a new identity and contact verification. A running client has access to its private key in memory. Password protection helps with stolen files, not a compromised running device.

For two clients on one computer, choose separate directories, e.g. `--identity-dir user1` and `--identity-dir user2`, on every identity, trust, and chat command.

## 4. Exchange and verify identity certificates (once, both people)

the first user sends **only** (yes only) their public `identity.pem` to the second user, saved as `user1.pem`. The second user sends their public certificate to the first user, saved as `user1.pem`. Separately compare the full SHA-256 fingerprints in person or through a trusted channel whose identity you already know(something like facetime is recommended if in-person is not realistic, but remembering the purpose of this program is security, what could really be more secure than a face to face conversation...). Receiving a certificate and its fingerprint together from an untrusted source does not verify the person(i know it's not widely used, just adding a little bit of necessary precaution).

Display your own fingerprint when needed:

```bash
python client.py --fingerprint identity/identity.pem
```

user1 imports user2's public certificate using the fingerprint they independently confirmed:

```bash
python client.py --trust user2.pem --expect-fingerprint FULL_USER2_FINGERPRINT
```

user2 imports user1's certificate using their independently confirmed fingerprint:

```bash
python client.py --trust user1.pem --expect-fingerprint FULL_USER1_FINGERPRINT
```

Replace the uppercase placeholders with the 64 hexadecimal characters displayed by the fingerprint command. Colons and spaces are accepted if the fingerprint is quoted.

The imported certificate is copied into `identity/peer.pem`; the original downloaded file is not used during chat. Import refuses mismatches and refuses overwriting an existing trusted contact. Each identity directory supports one contact. For deliberate replacement or certificate renewal, stop the client, remove the old `peer.pem`, repeat the trusted-channel verification, then import the new certificate. Do not remove a pin merely to dismiss an unexpected security warning.

## 5. Chat

Start the relay first:

```bash
python server.py
```

Both participants run:

```bash
python client.py
```

Enter the identity password. Names come from the certificates, so username impersonation via message JSON is blocked. The client derives the room and handshake role automatically from both certificate fingerprints. When both clients are present it authenticates the contact, then displays `Verified: NAME | end-to-end TLS 1.3`.

The name itself is self-chosen; the trusted fingerprint is what binds that identity to the person you verified. Do not interpret a self-chosen certificate name as proof of a legal identity.

## Controls and polish

- Enter sends; `/quit` or Ctrl+C exits.
- Page Up / Page Down scroll through currently unexpired history.
- `/clear` clears local display history without changing identity or contact trust.
- `/help` displays controls.
- The draft shows remaining characters and predicted display time; messages show expiry countdowns.
- Up to 250 characters gets 10 seconds, 500 gets 20, 1,000 gets 40, and 1,500–2,000 gets 60. The hard limit is 2,000 characters. `--lifetime` raises the minimum to 10–60 seconds.

## Reconnection and delivery

The client opens even while the relay is offline. Failed connections retry after 1, 2, 4, 8, then 15 seconds. It may wait up to two minutes for the partner before retrying. Connected peers exchange encrypted heartbeats every five seconds; missing replies for about 15 seconds trigger reconnect. Each reconnection uses a fresh full end-to-end TLS handshake, checks the pinned identity again, and avoids session resumption.

Sending is blocked until the authenticated session is established. Offline drafts are preserved; messages are not queued or automatically resent. A failed send may have an uncertain outcome, so confirm with your contact before retrying. Local sent history indicates transmission into the secure session, not confirmed delivery or reading.

There is no offline delivery or backlog. Both people **must** be online, and missed messages cannot be recovered from the relay. Certificate verification or TLS integrity/handshake errors stop automatic retries and block sending; check the issue and restart. This deliberately fails closed rather than accepting a different identity.

## Security model and limits

- Outer TLS verifies the relay hostname and certificate. Inner TLS authenticates both participant certificates, requires TLS 1.3, and additionally checks the exact peer certificate fingerprint before exposing the connection to the chat UI. No public CA can silently replace the pinned contact.
- The relay cannot decrypt inner chat traffic without participant secrets. It can observe routing identifiers, IP addresses, timing, and traffic size; block or drop traffic; occupy a room slot; or cause disconnects. Transport availability is not guaranteed by encryption.
- TLS 1.3 supplies authenticated key agreement, record integrity, and forward-secret full handshakes. This is not a Double Ratchet: there is no claim of per-message ratcheting or post-compromise recovery within a live session. TLS is not post-quantum key agreement here.
- Certificates persist; conversation sessions do not. A reconnect establishes new ephemeral session keys, so no application ratchet state is stored or rolled back. Plaintext histories and drafts are not intentionally written to disk.
- Message expiry is an authenticated application instruction, not secure erasure. Recipients can copy messages; operating systems can retain memory, swap, or crash dumps. Encrypted records can also be recorded. Keep clocks synchronized; expiry uses the sending timestamp.
- The relay limits concurrent clients to 32 and bounds frames to 64 KiB. Waiting pairs time out; socket operations have timeouts. This is not full public-service hardening: no account authorization, comprehensive rate limiting, traffic analysis protection, multi-device support, or group messaging.
- Keep Python, OpenSSL, and dependencies patched. Before deployment for sensitive real-world communication, arrange an independent application security review. Using a reviewed protocol does not certify the surrounding application.

## Checks performed

Integration checks covered encrypted identity passwords, fingerprint mismatch and replacement rejection, mutual TLS 1.3, sender binding to the verified certificate, expiry, heartbeat operation, relay restart/reconnection, fresh sessions, impostor rejection, and relay tampering detection. Terminal interaction has not been exhaustively tested across operating systems.

## Protocol references

- TLS 1.3: https://www.rfc-editor.org/rfc/rfc8446
- Python TLS API: https://docs.python.org/3/library/ssl.html
- Certificate/key generation: https://cryptography.io/en/latest/x509/tutorial/

## Ending Remarks
- The setup is lengthy when compared to something such as an iOS/Android application, but for a crude end-to-end messenger such as this one with limited user accessibility features, it is difficult to avoid
- Files are constantly changing! Regularly check to ensure you are running the most up to date version!
