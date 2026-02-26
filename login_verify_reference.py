#!/usr/bin/env python3
"""Extracted login-verification logic from ./mumble-login.

This module is a reference copy of the code path used to verify Mumble login:
1) Connect and block on client.is_ready()
2) Check client.connected state
3) Use captured Reject/ServerSync control messages for diagnostics
"""

import ssl
import threading

# Python 3.12+ compatibility: ssl.wrap_socket was removed
if not hasattr(ssl, "wrap_socket"):
    def wrap_socket(
        sock,
        keyfile=None,
        certfile=None,
        server_side=False,
        cert_reqs=ssl.CERT_NONE,
        ssl_version=None,
        ca_certs=None,
        do_handshake_on_connect=True,
        suppress_ragged_eofs=True,
        ciphers=None,
    ):
        context = ssl.SSLContext(
            ssl.PROTOCOL_TLS_CLIENT if not server_side else ssl.PROTOCOL_TLS_SERVER
        )
        context.check_hostname = False
        context.verify_mode = cert_reqs
        if certfile:
            context.load_cert_chain(certfile, keyfile)
        if ca_certs:
            context.load_verify_locations(ca_certs)
        if ciphers:
            context.set_ciphers(ciphers)
        return context.wrap_socket(
            sock,
            server_side=server_side,
            do_handshake_on_connect=do_handshake_on_connect,
            suppress_ragged_eofs=suppress_ragged_eofs,
        )

    ssl.wrap_socket = wrap_socket

import pymumble_py3 as pymumble
from pymumble_py3 import mumble_pb2
from pymumble_py3.constants import (
    PYMUMBLE_CONN_STATE_CONNECTED,
    PYMUMBLE_CONN_STATE_FAILED,
    PYMUMBLE_MSG_TYPES_REJECT,
    PYMUMBLE_MSG_TYPES_SERVERSYNC,
)

REJECT_TYPE_NAMES = {
    0: "None (unknown reason)",
    1: "WrongVersion (incompatible protocol version)",
    2: "InvalidUsername (username format not accepted)",
    3: "WrongUserPW (wrong user or certificate password)",
    4: "WrongServerPW (wrong server password)",
    5: "UsernameInUse (username already connected)",
    6: "ServerFull (server at capacity)",
    7: "NoCertificate (certificate required but not provided)",
    8: "AuthenticatorFail (external authenticator failure)",
    9: "NoNewConnections (server not accepting connections)",
}


class DiagnosticMumble(pymumble.Mumble):
    """Capture full Reject + ServerSync payloads for auth diagnostics."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.reject_info = None
        self.sync_info = None

    def dispatch_control_message(self, msg_type, message):
        if msg_type == PYMUMBLE_MSG_TYPES_REJECT:
            reject = mumble_pb2.Reject()
            reject.ParseFromString(message)
            rtype = reject.type
            self.reject_info = {
                "type": rtype,
                "type_name": REJECT_TYPE_NAMES.get(rtype, f"Unknown ({rtype})"),
                "reason": reject.reason or "(no reason provided)",
            }
        elif msg_type == PYMUMBLE_MSG_TYPES_SERVERSYNC:
            sync = mumble_pb2.ServerSync()
            sync.ParseFromString(message)
            self.sync_info = {
                "session": sync.session,
                "max_bandwidth": sync.max_bandwidth,
                "welcome_text": sync.welcome_text or None,
                "permissions": sync.permissions,
            }
        super().dispatch_control_message(msg_type, message)


def suppress_rejected_error_tracebacks():
    """Hide expected ConnectionRejectedError tracebacks from pymumble threads."""
    orig = threading.excepthook

    def _hook(args):
        from pymumble_py3.errors import ConnectionRejectedError

        if args.exc_type is ConnectionRejectedError:
            return
        orig(args)

    threading.excepthook = _hook


def try_login(server, port, username, password):
    """Run one auth attempt and block until connected or rejected."""
    client = DiagnosticMumble(
        host=server,
        user=username,
        port=port,
        password=password,
        reconnect=False,
    )
    client.daemon = True
    client.start()
    client.is_ready()
    return client


def classify_login(client):
    """Classify login result based on pymumble connection state + captured messages."""
    if client.connected == PYMUMBLE_CONN_STATE_CONNECTED:
        return {
            "ok": True,
            "state": PYMUMBLE_CONN_STATE_CONNECTED,
            "sync_info": client.sync_info,
            "reject_info": client.reject_info,
        }
    if client.connected == PYMUMBLE_CONN_STATE_FAILED:
        return {
            "ok": False,
            "state": PYMUMBLE_CONN_STATE_FAILED,
            "sync_info": client.sync_info,
            "reject_info": client.reject_info,
        }
    return {
        "ok": False,
        "state": client.connected,
        "sync_info": client.sync_info,
        "reject_info": client.reject_info,
    }

