#!/usr/bin/env python3
"""Passkey Demo — test credential creation and authentication via the Credential portal."""

import asyncio
from contextlib import closing
import json
import math
import os
from pathlib import Path
import secrets
import signal
import sqlite3
import sys
import threading
import time
import uuid

from dbus_next.aio import MessageBus, ProxyInterface
from dbus_next.constants import ErrorType
from dbus_next.proxy_object import BaseProxyInterface
from dbus_next import DBusError, MessageType, Variant

import gi
from gi.events import GLibEventLoop

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Gdk, Gio, GLib, GLibUnix, Gtk, Adw

try:
    gi.require_version("GdkWayland", "4.0")
    from gi.repository import GdkWayland
except (ValueError, ImportError):
    GdkWayland = None

import cbor
import webauthn
import util


# ---- dbus-next error handling patches ----

def _dbus_error_from_message(msg):
    assert msg.message_type == MessageType.ERROR
    return DBusError(msg.error_name, msg.body[0] if msg.body else None, reply=msg)


DBusError._from_message = _dbus_error_from_message


@staticmethod
def _check_method_return(msg, signature=None):
    if msg.message_type == MessageType.ERROR:
        raise DBusError._from_message(msg)
    elif msg.message_type != MessageType.METHOD_RETURN:
        raise DBusError(
            ErrorType.CLIENT_ERROR,
            "method call didn't return a method return",
            msg,
        )
    elif signature is not None and msg.signature != signature:
        raise DBusError(
            ErrorType.CLIENT_ERROR,
            f'unexpected signature: "{msg.signature}", expected {signature}',
            msg,
        )


BaseProxyInterface._check_method_return = _check_method_return


# ---- Constants and globals ----

APP_ID = "io.github.swick.CredentialsPortalDemo"
RP_ID = "example.com"
ORIGIN = "https://example.com"
RP_NAME = "Example Org"

LOOP = None
INTERFACE = None

_RESOURCE_DIR = os.path.dirname(os.path.realpath(__file__))
_RESOURCE = Gio.Resource.load(os.path.join(_RESOURCE_DIR, "resources.gresource"))
Gio.resources_register(_RESOURCE)

COSE_ALG_NAMES = {
    -7: "ES256 (ECDSA P-256)",
    -8: "EdDSA (Ed25519)",
    -257: "RS256 (RSA PKCS#1)",
    -35: "ES384 (ECDSA P-384)",
    -36: "ES512 (ECDSA P-521)",
}


# ---- Async bridge ----


def run_async(coro, on_done=None, on_error=None):
    fut = asyncio.run_coroutine_threadsafe(coro, LOOP)

    def callback(_):
        try:
            result = fut.result()
            if on_done:
                GLib.idle_add(on_done, result)
        except Exception as e:
            if on_error:
                GLib.idle_add(on_error, e)
            else:
                print(f"Unhandled async error: {e}", file=sys.stderr)

    fut.add_done_callback(callback)


# ---- Portal connection ----


PORTAL_ERROR = None

CREDENTIAL_IFACE = "org.freedesktop.portal.experimental.Credential"


async def connect_to_portal():
    global INTERFACE, PORTAL_ERROR
    bus = await MessageBus().connect()

    service = "org.freedesktop.portal.Desktop"
    path = "/org/freedesktop/portal/desktop"

    xml_path = os.path.join(
        _RESOURCE_DIR, "org.freedesktop.portal.experimental.Credential.xml"
    )
    with open(xml_path) as f:
        xml = f.read()

    proxy = bus.get_proxy_object(service, path, xml)
    iface = proxy.get_interface(CREDENTIAL_IFACE)

    try:
        await iface.get_version()
    except DBusError:
        PORTAL_ERROR = (
            "This could mean xdg-desktop-portal was started without "
            "experimental support, or that no credential provider "
            "(e.g. credentialsd) is installed.\n\n"
            "Make sure xdg-desktop-portal is running with "
            "the following environment variable set."
        )
        return

    INTERFACE = iface


class PortalRequest:
    def __init__(self, token, future):
        self.token = token
        self._future = future

    async def wait(self):
        return await self._future


def create_portal_request(bus):
    loop = asyncio.get_running_loop()
    future = loop.create_future()
    unique_name = bus.unique_name[1:].replace(".", "_")
    token = secrets.token_hex(16)
    obj_path = f"/org/freedesktop/portal/desktop/request/{unique_name}/{token}"

    def handler(msg):
        if future.done():
            return False
        if not (
            msg.path == obj_path
            and msg.message_type == MessageType.SIGNAL
            and msg.destination == bus.unique_name
            and msg.interface == "org.freedesktop.portal.Request"
            and msg.member == "Response"
        ):
            return False
        code, value = msg.body
        if code == 0:
            future.set_result(value)
        elif code == 1:
            future.set_exception(Exception("Request was cancelled"))
        elif code == 2 and "error" in value:
            future.set_exception(
                Exception(f"Portal error: {value['error'].value}")
            )
        else:
            future.set_exception(Exception("Unknown portal error"))
        return True

    future.add_done_callback(lambda _: bus.remove_message_handler(handler))
    bus.add_message_handler(handler)
    return PortalRequest(token, future)


# ---- Portal operations ----


async def portal_create_credential(interface, window_handle, options):
    request = create_portal_request(interface.bus)
    req = {
        "handle_token": Variant("s", request.token),
        "public_key": Variant("s", json.dumps(options)),
    }
    await interface.call_create_credential(
        window_handle, ORIGIN, "publicKey", req
    )
    result = await request.wait()

    if result["type"].value != "public-key":
        raise Exception(f"Unexpected credential type: {result['type'].value}")

    response = json.loads(
        result["public_key"].value["registration_response_json"].value
    )
    return webauthn.verify_create_response(response, options, ORIGIN)


async def portal_get_credential(interface, window_handle, options, lookup_fn):
    request = create_portal_request(interface.bus)
    req = {
        "handle_token": Variant("s", request.token),
        "public_key": Variant("s", json.dumps(options)),
    }
    await interface.call_get_credential(window_handle, ORIGIN, req)
    result = await request.wait()

    response = json.loads(
        result["public_key"].value["authentication_response_json"].value
    )
    response["rawId"] = util.b64_decode(response["rawId"])
    if uh := response["response"].get("userHandle"):
        response["response"]["userHandle"] = util.b64_decode(uh)

    cred_id = response["rawId"]
    auth_data = webauthn.verify_get_response(response, options, ORIGIN, lookup_fn)
    auth_data.cred_id = cred_id
    return auth_data


# ---- Window handle ----


async def get_window_handle(surface):
    if GdkWayland and isinstance(surface, GdkWayland.WaylandToplevel):
        loop = asyncio.get_running_loop()
        future = loop.create_future()
        surface.export_handle(
            lambda _, h: loop.call_soon_threadsafe(future.set_result, h)
        )
        return f"wayland:{await future}"
    return ""


def drop_window_handle(surface, handle):
    if not handle or not GdkWayland:
        return
    try:
        if isinstance(surface, GdkWayland.WaylandToplevel):
            surface.drop_exported_handle(handle.removeprefix("wayland:"))
    except Exception:
        pass


# ---- Database ----


def _db_path():
    cache = Path(os.environ.get("XDG_CACHE_HOME", Path.home() / ".cache"))
    return cache / APP_ID / "users.db"


def get_db():
    path = _db_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(path)
    db.execute("PRAGMA foreign_keys = ON")
    return db


def setup_db():
    db = get_db()
    db.execute("""
        CREATE TABLE IF NOT EXISTS users (
            user_id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            user_handle BLOB UNIQUE NOT NULL,
            created_time INTEGER NOT NULL
        ) STRICT
    """)
    db.execute("""
        CREATE TABLE IF NOT EXISTS user_passkeys (
            user_handle BLOB,
            cred_id BLOB,
            aaguid TEXT NOT NULL,
            sign_count INTEGER,
            backup_eligible INTEGER NOT NULL,
            backup_state INTEGER NOT NULL,
            uv_initialized INTEGER NOT NULL,
            cose_pub_key BLOB NOT NULL,
            created_time INTEGER NOT NULL,
            updated_time INTEGER,
            PRIMARY KEY (user_handle, cred_id)
        ) STRICT
    """)
    db.commit()
    db.close()


# ---- Formatting helpers ----


def format_algorithm(auth_data):
    if auth_data.pub_key_bytes:
        pub_key = cbor.loads(auth_data.pub_key_bytes)
        alg = pub_key.get(3)
        return COSE_ALG_NAMES.get(alg, f"Unknown ({alg})")
    return "Unknown"


def format_aaguid(aaguid):
    if aaguid:
        return str(uuid.UUID(bytes=aaguid))
    return "—"


def format_cred_id(cred_id):
    if cred_id:
        return util.b64_encode(cred_id)
    return "—"


# ---- UI helpers ----


def _detail_row(title, value):
    row = Adw.ActionRow(title=title, subtitle=str(value))
    row.set_subtitle_selectable(True)
    return row


def _flag_row(title, is_set):
    row = Adw.ActionRow(title=title)
    icon = Gtk.Image(
        icon_name="object-select-symbolic" if is_set else "window-close-symbolic",
        valign=Gtk.Align.CENTER,
    )
    row.add_suffix(icon)
    return row


# ---- Pages ----


def _make_error_page(message):
    status = Adw.StatusPage(
        icon_name="dialog-error-symbolic",
        title="Portal Not Available",
        description=message,
    )

    env_label = Gtk.Label(
        label="XDG_DESKTOP_PORTAL_ENABLE_EXPERIMENTAL=Credential",
        selectable=True,
        css_classes=["monospace"],
    )
    status.set_child(env_label)

    toolbar = Adw.ToolbarView()
    toolbar.add_top_bar(Adw.HeaderBar())
    toolbar.set_content(status)
    return Adw.NavigationPage(title="Passkey Demo", child=toolbar)


def _make_welcome_page(win):
    status = Adw.StatusPage(
        icon_name="dialog-password-symbolic",
        title="Passkey Demo",
        description=(
            "Test passkey registration and authentication\n"
            "via the Credential portal"
        ),
    )

    btn_box = Gtk.Box(
        orientation=Gtk.Orientation.VERTICAL,
        spacing=12,
        halign=Gtk.Align.CENTER,
    )

    create_btn = Gtk.Button(label="Create Account")
    create_btn.add_css_class("pill")
    create_btn.connect("clicked", lambda _: win.push_page(_make_register_page(win)))
    btn_box.append(create_btn)

    signin_btn = Gtk.Button(label="Sign In")
    signin_btn.add_css_class("suggested-action")
    signin_btn.add_css_class("pill")
    signin_btn.connect("clicked", lambda _: win.push_page(_make_signin_page(win)))
    btn_box.append(signin_btn)

    accounts_btn = Gtk.Button(label="Manage Accounts")
    accounts_btn.add_css_class("pill")
    accounts_btn.add_css_class("dim-label")
    accounts_btn.add_css_class("flat")
    accounts_btn.connect("clicked", lambda _: win.push_page(_make_accounts_page(win)))
    btn_box.append(accounts_btn)

    status.set_child(btn_box)

    toolbar = Adw.ToolbarView()
    toolbar.add_top_bar(Adw.HeaderBar())
    toolbar.set_content(status)
    return Adw.NavigationPage(title="Passkey Demo", tag="welcome", child=toolbar)


def _make_accounts_page(win):
    content = Gtk.Box(
        orientation=Gtk.Orientation.VERTICAL,
        spacing=12,
        margin_top=24,
        margin_bottom=24,
        margin_start=12,
        margin_end=12,
    )

    db = get_db()
    with closing(db.cursor()) as cur:
        cur.execute(
            "SELECT u.username, u.user_handle, p.cred_id, p.created_time "
            "FROM users u "
            "LEFT JOIN user_passkeys p ON u.user_handle = p.user_handle "
            "ORDER BY u.username"
        )
        rows = cur.fetchall()
    db.close()

    group = Adw.PreferencesGroup(
        title="Registered Accounts",
        description=(
            f"Relying party credential store for {RP_ID}.\n"
            "In a real application, this data would be stored "
            "on the website's backend. Deleting an account here "
            "does not remove the credential from the authenticator."
        ),
    )

    account_rows = []

    if not rows:
        group.set_description(
            "No accounts registered yet.\n"
            "Register a passkey to get started."
        )
    else:
        users = {}
        for username, user_handle, cred_id, created_time in rows:
            if username not in users:
                users[username] = []
            if cred_id:
                users[username].append(cred_id)

        for username, cred_ids in users.items():
            subtitle = f"{len(cred_ids)} credential{'s' if len(cred_ids) != 1 else ''}"
            row = Adw.ActionRow(
                title=username,
                subtitle=subtitle,
            )

            delete_btn = Gtk.Button(
                icon_name="user-trash-symbolic",
                valign=Gtk.Align.CENTER,
                css_classes=["flat", "error"],
            )

            def on_delete(_btn, uname=username, r=row):
                db = get_db()
                with closing(db.cursor()) as cur:
                    cur.execute(
                        "DELETE FROM user_passkeys WHERE user_handle = "
                        "(SELECT user_handle FROM users WHERE username = ?)",
                        (uname,),
                    )
                    cur.execute("DELETE FROM users WHERE username = ?", (uname,))
                db.commit()
                db.close()
                group.remove(r)
                account_rows.remove(r)

            delete_btn.connect("clicked", on_delete)
            row.add_suffix(delete_btn)
            group.add(row)
            account_rows.append(row)

    content.append(group)

    clear_btn = Gtk.Button(
        label="Clear All Accounts",
        halign=Gtk.Align.CENTER,
        css_classes=["pill", "destructive-action"],
    )

    def on_clear_all(_btn):
        db = get_db()
        db.execute("DELETE FROM user_passkeys")
        db.execute("DELETE FROM users")
        db.commit()
        db.close()
        for r in account_rows:
            group.remove(r)
        account_rows.clear()

    clear_btn.connect("clicked", on_clear_all)
    content.append(clear_btn)

    scroll = Gtk.ScrolledWindow(
        vexpand=True,
        child=Adw.Clamp(maximum_size=500, child=content),
    )
    toolbar = Adw.ToolbarView()
    toolbar.add_top_bar(Adw.HeaderBar())
    toolbar.set_content(scroll)
    return Adw.NavigationPage(title="Manage Accounts", child=toolbar)


def _make_register_page(win):
    content = Gtk.Box(
        orientation=Gtk.Orientation.VERTICAL,
        spacing=24,
        margin_top=24,
        margin_bottom=24,
        margin_start=12,
        margin_end=12,
    )

    # Username
    account_group = Adw.PreferencesGroup(title="Account")
    username_row = Adw.EntryRow(title="Username")
    account_group.add(username_row)
    content.append(account_group)

    # Options
    options_group = Adw.PreferencesGroup(title="Options")

    uv_model = Gtk.StringList.new(["Preferred", "Required", "Discouraged"])
    uv_row = Adw.ComboRow(title="User Verification", model=uv_model)
    options_group.add(uv_row)

    rk_model = Gtk.StringList.new(["Preferred", "Required", "Discouraged"])
    rk_row = Adw.ComboRow(title="Discoverable Credential", model=rk_model)
    options_group.add(rk_row)

    content.append(options_group)

    # Action area
    register_btn = Gtk.Button(label="Register Passkey", halign=Gtk.Align.CENTER)
    register_btn.add_css_class("suggested-action")
    register_btn.add_css_class("pill")

    page_ref = [None]

    def set_busy(busy):
        register_btn.set_sensitive(not busy)
        if page_ref[0]:
            page_ref[0].set_can_pop(not busy)

    def on_register(_btn):
        username = username_row.get_text().strip()
        if not username:
            win.show_error("Username is required")
            return

        uv_values = ["preferred", "required", "discouraged"]
        rk_values = ["preferred", "required", "discouraged"]

        async def do_register():
            db = get_db()
            cur = db.cursor()
            try:
                cur.execute(
                    "SELECT user_id, user_handle FROM users WHERE username = ?",
                    (username,),
                )
                row = cur.fetchone()
                user_id, user_handle = row if row else (None, secrets.token_bytes(16))

                options = {
                    "challenge": util.b64_encode(secrets.token_bytes(16)),
                    "rp": {"name": RP_NAME, "id": RP_ID},
                    "user": {
                        "id": util.b64_encode(user_handle),
                        "name": username,
                        "displayName": username,
                    },
                    "pubKeyCredParams": [
                        {"type": "public-key", "alg": -7},
                        {"type": "public-key", "alg": -257},
                        {"type": "public-key", "alg": -8},
                    ],
                    "userVerification": uv_values[uv_row.get_selected()],
                    "authenticatorSelection": {
                        "residentKey": rk_values[rk_row.get_selected()],
                    },
                }

                surface = win.get_surface()
                handle = await get_window_handle(surface)
                try:
                    auth_data = await portal_create_credential(
                        INTERFACE, handle, options
                    )
                finally:
                    drop_window_handle(surface, handle)

                now = math.floor(time.time())
                if not user_id:
                    cur.execute(
                        "INSERT INTO users (username, user_handle, created_time) "
                        "VALUES (?, ?, ?)",
                        (username, user_handle, now),
                    )
                cur.execute(
                    "INSERT INTO user_passkeys "
                    "(user_handle, cred_id, aaguid, sign_count, backup_eligible, "
                    "backup_state, uv_initialized, cose_pub_key, created_time) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        user_handle,
                        auth_data.cred_id,
                        format_aaguid(auth_data.aaguid),
                        auth_data.sign_count or None,
                        1 if "BE" in auth_data.flags else 0,
                        1 if "BS" in auth_data.flags else 0,
                        1 if "UV" in auth_data.flags else 0,
                        auth_data.pub_key_bytes,
                        now,
                    ),
                )
                db.commit()
                return auth_data
            finally:
                cur.close()
                db.close()

        def on_done(auth_data):
            set_busy(False)
            win.push_page(
                _make_registration_result_page(win, auth_data, username)
            )

        def on_error(err):
            set_busy(False)
            win.show_error(str(err))

        set_busy(True)
        run_async(do_register(), on_done, on_error)

    register_btn.connect("clicked", on_register)
    username_row.connect("entry-activated", on_register)
    content.append(register_btn)


    scroll = Gtk.ScrolledWindow(
        vexpand=True,
        child=Adw.Clamp(maximum_size=500, child=content),
    )
    toolbar = Adw.ToolbarView()
    toolbar.add_top_bar(Adw.HeaderBar())
    toolbar.set_content(scroll)
    page = Adw.NavigationPage(title="Create Account", child=toolbar)
    page.connect("shown", lambda _: username_row.grab_focus())
    page_ref[0] = page
    return page


def _make_signin_page(win):
    content = Gtk.Box(
        orientation=Gtk.Orientation.VERTICAL,
        spacing=24,
        margin_top=24,
        margin_bottom=24,
        margin_start=12,
        margin_end=12,
    )

    account_group = Adw.PreferencesGroup(
        title="Account",
        description="Leave empty to sign in without a username",
    )
    username_row = Adw.EntryRow(title="Username")
    account_group.add(username_row)
    content.append(account_group)

    signin_btn = Gtk.Button(label="Sign In", halign=Gtk.Align.CENTER)
    signin_btn.add_css_class("suggested-action")
    signin_btn.add_css_class("pill")

    page_ref = [None]

    def set_busy(busy):
        signin_btn.set_sensitive(not busy)
        if page_ref[0]:
            page_ref[0].set_can_pop(not busy)

    def on_signin(_btn):
        username = username_row.get_text().strip()

        async def do_signin():
            db = get_db()
            cred_ids = []
            user_creds = []

            if username:
                with closing(db.cursor()) as cur:
                    cur.execute(
                        "SELECT user_id FROM users WHERE username = ?",
                        (username,),
                    )
                    if not cur.fetchone():
                        raise Exception(f"No account found for '{username}'")
                    cur.execute(
                        "SELECT p.user_handle, cred_id, backup_eligible, "
                        "backup_state, cose_pub_key, sign_count "
                        "FROM user_passkeys p "
                        "INNER JOIN users u ON u.user_handle = p.user_handle "
                        "WHERE u.username = ?",
                        (username,),
                    )
                    for row in cur.fetchall():
                        user_creds.append({
                            "user_handle": row[0],
                            "cred_id": row[1],
                            "backup_eligible": row[2],
                            "backup_state": row[3],
                            "pub_key": row[4],
                            "sign_count": row[5],
                        })
                cred_ids = [c["cred_id"] for c in user_creds]

            options = {
                "challenge": util.b64_encode(secrets.token_bytes(16)),
                "rpId": RP_ID,
                "allowCredentials": [
                    {"type": "public-key", "id": util.b64_encode(c)}
                    for c in cred_ids
                ],
            }

            found_user_handle = None

            def lookup_cred(user_handle, cred_id):
                nonlocal found_user_handle
                if username:
                    match = next(
                        (c for c in user_creds if c["cred_id"] == cred_id),
                        None,
                    )
                    if match:
                        found_user_handle = match["user_handle"]
                    return match
                if not user_handle:
                    return None
                with closing(get_db().cursor()) as cur:
                    cur.execute(
                        "SELECT user_handle, cred_id, backup_eligible, "
                        "backup_state, cose_pub_key, sign_count "
                        "FROM user_passkeys "
                        "WHERE user_handle = ? AND cred_id = ?",
                        (user_handle, cred_id),
                    )
                    if row := cur.fetchone():
                        found_user_handle = row[0]
                        return {
                            "user_handle": row[0],
                            "cred_id": row[1],
                            "backup_eligible": row[2],
                            "backup_state": row[3],
                            "pub_key": row[4],
                            "sign_count": row[5],
                        }
                return None

            surface = win.get_surface()
            handle = await get_window_handle(surface)
            try:
                auth_data = await portal_get_credential(
                    INTERFACE, handle, options, lookup_cred
                )
            finally:
                drop_window_handle(surface, handle)

            resolved_username = username
            if not resolved_username and found_user_handle:
                with closing(get_db().cursor()) as cur:
                    cur.execute(
                        "SELECT username FROM users WHERE user_handle = ?",
                        (found_user_handle,),
                    )
                    if row := cur.fetchone():
                        resolved_username = row[0]

            db.close()
            return auth_data, resolved_username

        def on_done(result):
            auth_data, resolved_username = result
            set_busy(False)
            win.push_page(
                _make_auth_result_page(win, auth_data, resolved_username)
            )

        def on_error(err):
            set_busy(False)
            msg = str(err)
            if "No credential for user found" in msg:
                msg = "Account not found — it may have been deleted"
            win.show_error(msg)

        set_busy(True)
        run_async(do_signin(), on_done, on_error)

    signin_btn.connect("clicked", on_signin)
    username_row.connect("entry-activated", on_signin)
    content.append(signin_btn)


    scroll = Gtk.ScrolledWindow(
        vexpand=True,
        child=Adw.Clamp(maximum_size=500, child=content),
    )
    toolbar = Adw.ToolbarView()
    toolbar.add_top_bar(Adw.HeaderBar())
    toolbar.set_content(scroll)
    page = Adw.NavigationPage(title="Sign In", child=toolbar)
    page.connect("shown", lambda _: username_row.grab_focus())
    page_ref[0] = page
    return page


def _result_header(icon_name, title, description):
    box = Gtk.Box(
        orientation=Gtk.Orientation.VERTICAL,
        spacing=8,
        halign=Gtk.Align.CENTER,
        margin_top=24,
        margin_bottom=12,
    )
    icon = Gtk.Image(icon_name=icon_name, pixel_size=64)
    box.append(icon)
    title_label = Gtk.Label(label=title)
    title_label.add_css_class("title-1")
    box.append(title_label)
    desc_label = Gtk.Label(label=description)
    desc_label.add_css_class("dim-label")
    box.append(desc_label)
    return box


def _make_registration_result_page(win, auth_data, username):
    scroll_content = Gtk.Box(
        orientation=Gtk.Orientation.VERTICAL,
        spacing=24,
        margin_start=12,
        margin_end=12,
        margin_bottom=24,
    )

    scroll_content.append(
        _result_header(
            "object-select-symbolic",
            "Account Created",
            f"Passkey registered for {username}",
        )
    )

    details = Adw.PreferencesGroup(title="Credential Details")
    details.add(_detail_row("Credential ID", format_cred_id(auth_data.cred_id)))
    details.add(_detail_row("AAGUID", format_aaguid(auth_data.aaguid)))
    details.add(_detail_row("Algorithm", format_algorithm(auth_data)))
    details.add(_detail_row("Sign Count", auth_data.sign_count))
    scroll_content.append(details)

    flags_group = Adw.PreferencesGroup(title="Flags")
    flags_group.add(_flag_row("User Present", "UP" in auth_data.flags))
    flags_group.add(_flag_row("User Verified", "UV" in auth_data.flags))
    flags_group.add(_flag_row("Backup Eligible", "BE" in auth_data.flags))
    flags_group.add(_flag_row("Backed Up", "BS" in auth_data.flags))
    scroll_content.append(flags_group)

    scroll = Gtk.ScrolledWindow(
        child=Adw.Clamp(maximum_size=500, child=scroll_content),
    )

    done_btn = Gtk.Button(label="Done", halign=Gtk.Align.CENTER, margin_top=12, margin_bottom=12)
    done_btn.add_css_class("pill")
    done_btn.connect("clicked", lambda _: win.nav_view.pop_to_tag("welcome"))

    toolbar = Adw.ToolbarView()
    toolbar.add_top_bar(Adw.HeaderBar())
    toolbar.set_content(scroll)
    toolbar.add_bottom_bar(done_btn)
    return Adw.NavigationPage(title="Registered", child=toolbar, can_pop=False)


def _make_auth_result_page(win, auth_data, username):
    scroll_content = Gtk.Box(
        orientation=Gtk.Orientation.VERTICAL,
        spacing=24,
        margin_start=12,
        margin_end=12,
        margin_bottom=24,
    )

    desc = f"Authenticated as {username}" if username else "Authentication successful"
    scroll_content.append(
        _result_header("object-select-symbolic", "Signed In", desc)
    )

    details = Adw.PreferencesGroup(title="Authentication Details")
    if username:
        details.add(_detail_row("Username", username))
    details.add(_detail_row("Credential ID", format_cred_id(auth_data.cred_id)))
    details.add(_detail_row("RP ID Hash", auth_data.rp_id_hash.hex()))
    details.add(_detail_row("Sign Count", auth_data.sign_count))
    scroll_content.append(details)

    flags_group = Adw.PreferencesGroup(title="Flags")
    flags_group.add(_flag_row("User Present", "UP" in auth_data.flags))
    flags_group.add(_flag_row("User Verified", "UV" in auth_data.flags))
    flags_group.add(_flag_row("Backup Eligible", "BE" in auth_data.flags))
    flags_group.add(_flag_row("Backed Up", "BS" in auth_data.flags))
    scroll_content.append(flags_group)

    scroll = Gtk.ScrolledWindow(
        child=Adw.Clamp(maximum_size=500, child=scroll_content),
    )

    done_btn = Gtk.Button(label="Done", halign=Gtk.Align.CENTER, margin_top=12, margin_bottom=12)
    done_btn.add_css_class("pill")
    done_btn.connect("clicked", lambda _: win.nav_view.pop_to_tag("welcome"))

    toolbar = Adw.ToolbarView()
    toolbar.add_top_bar(Adw.HeaderBar())
    toolbar.set_content(scroll)
    toolbar.add_bottom_bar(done_btn)
    return Adw.NavigationPage(title="Authenticated", child=toolbar, can_pop=False)


# ---- Window ----


@Gtk.Template(resource_path="/io/github/swick/CredentialsPortalDemo/window.ui")
class DemoWindow(Adw.ApplicationWindow):
    __gtype_name__ = "DemoWindow"

    nav_view = Gtk.Template.Child()
    toast_overlay = Gtk.Template.Child()

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        if PORTAL_ERROR:
            self.nav_view.push(_make_error_page(PORTAL_ERROR))
        else:
            self.nav_view.push(_make_welcome_page(self))

        key_ctrl = Gtk.EventControllerKey()
        key_ctrl.set_propagation_phase(Gtk.PropagationPhase.CAPTURE)
        key_ctrl.connect("key-pressed", self._on_key_pressed)
        self.add_controller(key_ctrl)

    def _on_key_pressed(self, _ctrl, keyval, _keycode, _state):
        if keyval == Gdk.KEY_Escape:
            page = self.nav_view.get_visible_page()
            if not page or page.get_tag() == "welcome":
                return False
            if page.get_can_pop():
                self.nav_view.pop()
            else:
                self.nav_view.pop_to_tag("welcome")
            return True
        return False

    def push_page(self, page):
        self.nav_view.push(page)

    def show_error(self, message):
        toast = Adw.Toast(title=str(message), timeout=5)
        self.toast_overlay.add_toast(toast)


# ---- Application ----


class DemoApp(Adw.Application):
    def __init__(self):
        super().__init__(application_id=APP_ID)
        GLibUnix.signal_add(GLib.PRIORITY_DEFAULT, signal.SIGINT, self._on_sigint)

    def _on_sigint(self):
        self.quit()
        return GLib.SOURCE_REMOVE

    def do_activate(self):
        win = self.get_active_window()
        if not win:
            win = DemoWindow(application=self)
        win.present()


# ---- Entry point ----


if __name__ == "__main__":
    setup_db()

    LOOP = GLibEventLoop(GLib.MainContext())
    try:
        LOOP.run_until_complete(connect_to_portal())
    except Exception as e:
        PORTAL_ERROR = str(e)

    threading.Thread(
        target=lambda: LOOP.run_until_complete(asyncio.Event().wait()),
        daemon=True,
    ).start()

    app = DemoApp()
    app.run(sys.argv)
