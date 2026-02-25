# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

`murmur_tools` is a Python toolkit for monitoring and administering a Mumble (Murmur) voice server. It is used in an EVE Online gaming community context to track player certificate hashes and manage Mumble server users.

## Setup

```bash
python3 -m venv .venv/tools
source .venv/tools/bin/activate
pip install -r NI_requirements.txt
```

## Running

```bash
# Certificate collector - connects to Mumble server and monitors user sessions
python3 NI_certs.py

# Mumble server admin tool (ICE interface)
./mumble-admin --help
```

## Architecture

### NI_certs.py

Connects to a Mumble server via the `pymumble` library using a self-signed TLS certificate (generated on first run). Registers callbacks for user join/update/leave events to collect certificate hash → username mappings, persisting results to `ni_data.json`.

Key data structures:
- `cert_to_users`: `{cert_hash: [username, ...]}` — maps certificate fingerprint to known usernames
- `user_certs`: `{session_id: user_info}` — tracks currently online users by session

Hardcoded server config at top of file: `SERVER`, `PORT`, `USERNAME`, `PASSWORD`, `CERT_FILE`, `KEY_FILE`, `OUTPUT_FILE`.

**Python 3.12+ compatibility:** The file includes a monkey-patch for `ssl.wrap_socket()` (removed in 3.12) that creates a proper `SSLContext` instead.

### mumble-admin

A CLI tool (no `.py` extension, directly executable) that manages Mumble server users via the ZeroC ICE inter-process communication interface. Reads the Mumble server configuration from `~/mumble-server/mumble-server.ini` to obtain the `icesecretwrite` value. Connects to ICE at `192.168.129.51:6502`.

Commands: `--server`, `--user`, `--add-user`, `--remove-user`, `--reset-user`

## Key Files

| File | Purpose |
|------|---------|
| `NI_certs.py` | Main certificate monitoring script |
| `mumble-admin` | ICE-based user administration CLI |
| `NI_requirements.txt` | Python dependencies |
| `ni_data.json` | Output: cert hash → usernames (git-ignored) |
| `ni_cert.pem` / `ni_key.pem` | Auto-generated TLS credentials (git-ignored) |

## Dependencies

- `pymumble==1.6.1` — Mumble protocol client
- `cryptography==46.0.4` — TLS certificate generation
- `protobuf==3.12.2` — Required by pymumble
- `opuslib==3.0.1` — Opus codec support
- ZeroC Ice — ICE RPC framework (used by `mumble-admin`, installed separately)
