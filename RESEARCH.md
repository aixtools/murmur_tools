# Research Briefing: mumble + murmur_tools

This document is a context primer for a fresh agent. It summarises all research
already performed on two git repositories so the agent can continue work without
re-exploring either codebase.

---

## Repository 1: `/home/michael/prj/mumble`

**Language:** C++ (Qt framework)
**Role in project:** Reference implementation. We read this to understand the
Mumble client–server protocol and the server-side (Murmur) authentication logic.
We do **not** write code here.

### 1.1 Protocol Overview

Mumble uses two transport layers:

| Layer | Purpose | Encryption |
|-------|---------|-----------|
| TCP | Control messages (auth, text, state) | TLS 1.2+ mandatory |
| UDP | Audio (optional) | AES-OCB2 |

Control messages are serialised with **Protocol Buffers** (`.proto` files in
`src/`). All authentication happens over TCP/TLS.

Key proto files:
- `src/Mumble.proto` — TCP message definitions
- `src/MumbleUDP.proto` — UDP audio message definitions
- `src/MumbleProtocol.h` — message type ID constants (0–N)

### 1.2 TCP Message Type IDs (MumbleProtocol.h:24–51)

| ID | Name | Direction |
|----|------|-----------|
| 0 | Version | Client→Server |
| 2 | Authenticate | Client→Server |
| 3 | Ping | Bidirectional |
| 4 | Reject | Server→Client |
| 5 | ServerSync | Server→Client |
| 15 | CryptSetup | Bidirectional |

### 1.3 Authenticate Protobuf (src/Mumble.proto:34–46)

```protobuf
message Authenticate {
    optional string username = 1;
    optional string password = 2;
    repeated string tokens   = 3;
    repeated int32  celt_versions = 4;
    optional bool   opus     = 5 [default = false];
    optional int32  client_type = 6 [default = 0];
}
```

### 1.4 Client-Side Authentication Flow (src/mumble/ServerHandler.cpp)

```
CLIENT                                    SERVER
  |── TLS Handshake ─────────────────────→|
  |←── TLS Complete ──────────────────────|
  |── Version (type 0) ──────────────────→|   (lines 837–838)
  |── Authenticate(username,password) ───→|   (lines 839–849)
  |                              [validate]
  |←── ServerSync (type 5) ───────────────|   success
  |   OR Reject   (type 4) ───────────────|   failure
```

Credentials are stored in `ServerHandler.h:87–89`:
```cpp
QString qsHostName;
QString qsUserName;
QString qsPassword;   // plaintext in memory, sent over TLS
unsigned short usPort;
```

### 1.5 Reject Message Types (src/Mumble.proto:77–101)

| Value | Name | Meaning |
|-------|------|---------|
| 0 | None | Unknown |
| 1 | WrongVersion | Incompatible protocol |
| 2 | InvalidUsername | Bad username format |
| 3 | WrongUserPW | Wrong cert or password for existing user |
| 4 | WrongServerPW | Wrong server password |
| 5 | UsernameInUse | Already connected |
| 6 | ServerFull | Capacity reached |
| 7 | NoCertificate | Cert required, none provided |
| 8 | AuthenticatorFail | External auth system failure |
| 9 | NoNewConnections | Server not accepting connections |

Handled in `src/mumble/Messages.cpp:85–113`.

### 1.6 Server-Side Authentication (src/murmur/Server.cpp:2569–2747)

Function: `int Server::authenticate(name, password, sessionId, emails,
certhash, bStrongCert, groups)`

Return codes:
- `>= 0` — authenticated; value is the user ID
- `-1` (AUTHENTICATION_FAILED) — user exists, wrong cert AND wrong/no password
- `-2` (UNKNOWN_USER) — username not found
- `-3` (TEMPORARY_UNVERIFIABLE) — external authenticator error

**Auth order — password is checked FIRST:**

1. **Password check (lines 2599–2676):**
   If client sent a non-empty password AND it matches the stored PBKDF2 (or
   legacy SHA1) hash → authenticated, cert mismatch is ignored entirely.

2. **Certificate check (lines 2678–2713):**
   Only reached if password check did not succeed.
   - Exact cert hash match (SHA1 hex of DER cert)
   - Fallback: if cert was CA-verified, look up user by email embedded in cert

3. **Failure:** Returns -1 (existing user) or -2 (unknown user).

**Important:** because password is checked before cert, setting a valid password
via ICE allows login from any client regardless of cert mismatch.

### 1.7 Password Storage (src/murmur/DBWrapper.cpp:1274–1303)

Function: `storeRegisteredUserPassword(serverID, userID, password, kdfIterations)`

- Default: PBKDF2 with random salt, server-configured iterations
- Legacy mode (`legacyPasswordHash=true`): SHA1
- Empty password string → no hash stored (user has no password)
- **Passwords are never stored in plaintext**

`getRegistration` via ICE intentionally **omits** `UserPassword` and
`UserKDFIterations` from its response (see DBWrapper.cpp comment:
"those are secret and not handed out").

### 1.8 ICE Interface (src/murmur/MumbleServerIce.cpp)

The Mumble server exposes an administrative RPC interface over ZeroC ICE.

`updateRegistration` handler (lines 1823–1854):
- Accepts a `UserInfoMap` (enum key → string value)
- Converts to `QMap<int,QString>` via `infoToInfo()`
- Calls `server->setUserProperties()` which calls `storeRegisteredUserPassword`
  if `UserProperty::Password` (int 4) is present

The ICE enum values and the server-internal `UserProperty` enum values are
**identical** (both 0–6 in the same order), so no translation errors occur.

### 1.9 Certificate Hash

Computed at TLS connection time (`Server.cpp:1501–1547`):
```cpp
uSource->qsHash = QString::fromLatin1(cert.digest(QCryptographicHash::Sha1).toHex());
```
Self-signed and unverified certs are accepted but `bVerified = false`, which
disables the email-fallback lookup path.

---

## Repository 2: `/home/michael/prj/murmur_tools`

**Language:** Python 3.12+
**Role in project:** Active development target. Python toolkit for monitoring
and administering a Mumble server in an EVE Online gaming community.

### 2.1 Project Structure

```
murmur_tools/
├── CLAUDE.md              ← developer guide (auto-loaded by Claude Code)
├── RESEARCH.md            ← this file
├── NI_certs.py            ← cert monitoring client (uses pymumble)
├── mumble-admin           ← ICE admin CLI (no .py extension, executable)
├── mumble-login           ← password-based login tester (new, our work)
├── evil_ice_admin.py      ← ICE helper functions (imported by mumble-admin)
├── ice/
│   ├── MumbleServer_ice.py        ← generated ZeroC Ice proxy (320 KB)
│   └── MumbleServer/
├── NI_requirements.txt    ← pip dependencies
├── .venv/tools/           ← virtualenv; activate: source .venv/tools/bin/activate
├── ni_cert.pem / ni_key.pem      ← auto-generated TLS cert (git-ignored)
└── ni_data.json           ← output: cert hash → username map (git-ignored)
```

### 2.2 Python Dependencies (NI_requirements.txt)

```
pymumble==1.6.1        # Mumble protocol client (imported as pymumble_py3)
protobuf==3.12.2       # required by pymumble
opuslib==3.0.1         # Opus codec
cryptography==46.0.4   # TLS cert generation
cffi==2.0.0
```
ZeroC Ice is installed separately (used only by `mumble-admin`).

### 2.3 Python 3.12 Compatibility Patch

`ssl.wrap_socket` was removed in Python 3.12. pymumble uses it internally.
**Both** `NI_certs.py` and `mumble-login` include a monkey-patch at the top
that must be applied before `import pymumble_py3`:

```python
if not hasattr(ssl, 'wrap_socket'):
    def wrap_socket(sock, keyfile=None, certfile=None, server_side=False,
                    cert_reqs=ssl.CERT_NONE, ssl_version=None, ...):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT if not server_side
                                 else ssl.PROTOCOL_TLS_SERVER)
        context.check_hostname = False
        context.verify_mode = cert_reqs
        ...
        return context.wrap_socket(sock, ...)
    ssl.wrap_socket = wrap_socket
```

### 2.4 mumble-login (new tool, `/home/michael/prj/murmur_tools/mumble-login`)

Tests password-based Mumble authentication from the CLI.

**Usage:**
```
./mumble-login --username USER [--server HOST] [--port PORT] [--password PASS]
```
Defaults: `--server 127.0.0.1`, `--port 64738`.

**Behaviour:**
1. Connects to server with no password (or `--password` if given).
2. On `WrongUserPW` rejection and no `--password` given: prompts for password
   interactively (via `getpass`) and reconnects. This emulates the Mumble GUI
   client cert-mismatch recovery flow.
3. Exits 0 on success, 1 on failure.

**Key implementation details:**
- Subclasses `pymumble.Mumble` as `DiagnosticMumble` to intercept
  `dispatch_control_message` and capture the full `Reject` protobuf (type enum
  + reason string) before pymumble discards the type.
- Installs a `threading.excepthook` to suppress the `ConnectionRejectedError`
  traceback that pymumble prints from its internal thread.
- After `is_ready()` returns, checks `client.connected` for state:
  - `PYMUMBLE_CONN_STATE_CONNECTED` (2) = success
  - `PYMUMBLE_CONN_STATE_FAILED` (3) = failure

**pymumble connection pattern:**
```python
client = DiagnosticMumble(host, user=username, port=port,
                          password=password, reconnect=False)
client.daemon = True
client.start()
client.is_ready()   # blocks until connected or rejected
# check client.connected, client.reject_info, client.sync_info
```

### 2.5 mumble-admin (`/home/michael/prj/murmur_tools/mumble-admin`)

ICE-based administration CLI.

**Usage:**
```
./mumble-admin --user [NAME]            # list registered users
./mumble-admin --user NAME --debug      # show full registration fields
./mumble-admin --add-user [NAME]        # register new user
./mumble-admin --reset-user [NAME]      # wipe password + cert hash
./mumble-admin --set-password [NAME]    # set new password (prompts)
./mumble-admin --set-password NAME --debug   # show ICE fields before/after
./mumble-admin --remove-user [NAME]     # unregister user
```
Reads ICE secret from `~/mumble-server.ini` → `icesecretwrite`.
Connects to ICE at `127.0.0.1:6502`.

**What `--reset-user` does:**
Calls `updateRegistration(uid, {UserPassword: "", UserHash: ""}, ctx)`.
This clears **both** the stored password hash and the stored certificate hash.
After a reset the user has no credentials — the next cert they connect with
will be stored as their new identity. It does NOT set a new password.

### 2.6 evil_ice_admin.py — ICE Helper Functions

| Function | Signature | Notes |
|----------|-----------|-------|
| `list_servers` | `(meta)` | |
| `list_users` | `(meta, server_id, username, debug=False)` | debug shows `getRegistration` |
| `add_user` | `(meta, name, ice_secret, server_id)` | creates user, clears auth state |
| `reset_user` | `(meta, name, ice_secret, server_id)` | clears password + cert hash |
| `set_password` | `(meta, name, new_password, ice_secret, server_id, debug=False)` | sets password only |
| `remove_user` | `(meta, name, ice_secret, server_id)` | unregisters user |

ICE context (write secret): `ctx = {"secret": ice_secret}` passed as last
positional arg to all write operations.

**UserInfo enum values** (from `ice/MumbleServer_ice.py:1142–1148`):

| Enum | Int | Returned by getRegistration? |
|------|-----|------------------------------|
| UserName | 0 | yes |
| UserEmail | 1 | yes (if set) |
| UserComment | 2 | yes (if set) |
| UserHash | 3 | yes (if set) — SHA1 hex of client cert |
| UserPassword | 4 | **NO** — withheld by server by design |
| UserLastActive | 5 | yes |
| UserKDFIterations | 6 | **NO** — withheld by server by design |

### 2.7 NI_certs.py — Cert Monitoring Client

Connects to a Mumble server and monitors user join/update/leave events to
collect certificate hash → username mappings.

- Uses `pymumble_py3` with cert-based auth (`ni_cert.pem` / `ni_key.pem`)
- Auto-generates self-signed certs on first run (10-year validity)
- Persists data to `ni_data.json`
- Server address is hardcoded near the top of the file (multiple commented
  alternatives: `cube-dev.aixtools.com`, `voice.wintercoalition.space`)
- The `monitor` user (uid=8) is the identity used by this script

### 2.8 Known Servers

| Hostname | Port | Notes |
|----------|------|-------|
| 127.0.0.1 | 64738 | local dev server (default for mumble-login) |
| cube-dev.aixtools.com | 64738 | current in NI_certs.py |
| voice.wintercoalition.space | 64738 | production |

### 2.9 Registered Users (as of last `--user` run)

| UID | Name |
|-----|------|
| 0 | SuperUser |
| 2 | [EVIL. P0NZI] Beli Zmaj |
| 7 | [EVIL. HKNON] Leo Rises |
| 8 | monitor |

### 2.10 Open Issue: `--set-password` Not Accepted by Murmur

**Symptom:** After `./mumble-admin --set-password monitor`, `mumble-login`
still returns `WrongUserPW` even with the correct password.

**What we know:**
- The ICE `updateRegistration` call returns success (`8:monitor`)
- The murmur server PBKDF2-hashes the plaintext password before storing it
- `getRegistration` cannot confirm the password was stored (intentionally excluded)
- Password is checked server-side BEFORE cert hash, so cert mismatch should not block a valid password
- `--debug` flag has been added to `mumble-admin` to show `getRegistration`
  fields before/after `set_password` — run this to get more diagnostic data

**Next steps to diagnose:**
1. Run `./mumble-admin --set-password monitor --debug` and capture output
2. Check `UserHash` field: if non-empty the user has a cert registered
3. Check murmur server logs for auth failures
4. Try `./mumble-admin --reset-user monitor` first, then `--set-password monitor`
   to rule out stale cert hash interaction
5. Try setting a password on a different user (e.g., create a fresh test user)
   to isolate whether the issue is specific to `monitor`

---

## Cross-Repository Summary

| Topic | mumble (C++) | murmur_tools (Python) |
|-------|--------------|-----------------------|
| Protocol | Protobuf over TLS | pymumble handles it |
| Auth flow | TLS → Version → Authenticate → ServerSync/Reject | DiagnosticMumble subclass |
| Cert mismatch recovery | GUI shows password dialog, reconnects | mumble-login prompts + retries |
| Admin interface | Murmur exposes ZeroC ICE | mumble-admin via evil_ice_admin.py |
| Password storage | PBKDF2, server-side, never plaintext | Set via ICE updateRegistration |
| Key proto file | src/Mumble.proto | (consumed via pymumble_pb2) |
