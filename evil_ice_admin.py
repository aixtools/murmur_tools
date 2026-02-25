# evil_ice_admin.py
import MumbleServer

# ---------- helpers ----------

def iter_servers(meta):
    try:
        return list(meta.getAllServers())
    except Exception:
        return []


def select_servers(meta, server_id):
    servers = iter_servers(meta)
    if not servers:
        return []

    if server_id is None:
        return list(enumerate(servers))

    try:
        sid = int(server_id)
    except ValueError:
        return []

    if sid < 0 or sid >= len(servers):
        return []

    return [(sid, servers[sid])]


# ---------- list servers ----------

def list_servers(meta):
    servers = iter_servers(meta)
    if not servers:
        print("no servers found")
        return

    for sid, srv in enumerate(servers):
        print(f"s/{sid} {srv}")


# ---------- list users ----------

def list_users(meta, server_id=None, username=None):
    servers = select_servers(meta, server_id)
    if not servers:
        print("no servers found")
        return

    multi = len(servers) > 1
    found = False

    for sid, server in servers:
        try:
            users = server.getRegisteredUsers("")
        except Exception:
            continue

        for uid, name in users.items():
            if username and username != "__ALL__" and name != username:
                continue

            found = True
            if multi:
                print(f"{sid}:{uid}:{name}")
            else:
                print(f"{uid}:{name}")

    if username and username != "__ALL__" and not found:
        print(f"user '{username}' not found")


# ---------- add user (IMPLEMENTED) ----------

def add_user(meta, name, ice_secret, server_id=None):
    servers = select_servers(meta, server_id)
    if not servers:
        print("no servers found")
        return

    for sid, server in servers:
        users = server.getRegisteredUsers("")
        if name in users.values():
            print(f"user '{name}' already exists")
            continue

        info = {
            MumbleServer.UserInfo.UserName: name
        }
        ctx = {"secret": ice_secret }
        uid = server.registerUser(info, ctx)

        # clear auth state (cert-first friendly)
        server.updateRegistration(uid, {
            MumbleServer.UserInfo.UserPassword: "",
            MumbleServer.UserInfo.UserHash: ""
        }, ctx)

        if len(servers) > 1:
            print(f"{sid}:{uid}:{name}")
        else:
            print(f"{uid}:{name}")


def reset_user(meta, name, ice_secret, server_id=None):
    servers = select_servers(meta, server_id)
    if not servers:
        print("no servers found")
        return

    for sid, server in servers:
        users = server.getRegisteredUsers("")
        for uid, uname in users.items():
            if uname != name:
                continue

            ctx = {"secret": ice_secret}
            server.updateRegistration(uid, {
                MumbleServer.UserInfo.UserPassword: "",
                MumbleServer.UserInfo.UserHash: ""
            }, ctx)

            if len(servers) > 1:
                print(f"{sid}:{uid}:{name}")
            else:
                print(f"{uid}:{name}")
            return

    print(f"user '{name}' not found")

def remove_user(meta, name, ice_secret, server_id=None):
    servers = select_servers(meta, server_id)
    if not servers:
        print("no servers found")
        return

    for sid, server in servers:
        users = server.getRegisteredUsers("")
        for uid, uname in users.items():
            if uname != name:
                continue

            ctx = {"secret": ice_secret}
            server.unregisterUser(uid, ctx)

            if len(servers) > 1:
                print(f"{sid}:{uid}:{name}")
            else:
                print(f"{uid}:{name}")
            return

    print(f"user '{name}' not found")
