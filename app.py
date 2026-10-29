import io
import base64
import hashlib
import hmac
import mimetypes
from importlib import import_module
import os
import re
import smtplib
import struct
import sqlite3
import secrets
import time
import uuid
import zipfile
from datetime import datetime
from email.message import EmailMessage
from urllib.parse import quote

import streamlit as st

try:
    qrcode = __import__("qrcode")
except ImportError:
    qrcode = None

try:
    st_ace = import_module("streamlit_ace").st_ace
except ImportError:
    st_ace = None

DB_PATH = "app.db"
SESSION_TIMEOUT_SECONDS = 15 * 60
TOTP_STEP_SECONDS = 30
MAX_ZIP_IMPORT_BYTES = 500 * 1024 * 1024
ACE_LANGUAGES = {
    "python": "python",
    "javascript": "javascript",
    "html": "html",
    "css": "css",
    "sql": "sql",
    "bash": "sh",
    "json": "json",
    "c_cpp": "c_cpp",
    "text": "text",
}

st.set_page_config(page_title="Code Vault", page_icon="🧠", layout="wide")

COMPACT_LAYOUT_CSS = """
<style>
    [data-testid="stAppViewContainer"] .block-container {
        padding-top: 3.5rem;
        padding-bottom: 1.5rem;
    }
    [data-testid="stForm"] [data-testid="stVerticalBlock"] {
        gap: 0.65rem;
    }
    .st-key-auth-switch [data-testid="stSegmentedControl"] {
        margin: 0 auto;
    }
    .st-key-auth-panel {
        max-width: 430px;
        width: 100%;
        margin: 2rem auto 0;
    }
    .st-key-file-row-actions [data-testid="stDownloadButton"] button,
    .st-key-file-row-actions [data-testid="stButton"] button {
        min-height: 1.8rem !important;
        padding: 0 !important;
        border: 0 !important;
        background: transparent !important;
        box-shadow: none !important;
    }
    .st-key-selected-file-actions [data-testid="stHorizontalBlock"] {
        justify-content: flex-end;
        gap: 0.625rem;
    }
    .st-key-admin-bulk-tools [data-testid="stHorizontalBlock"] {
        align-items: flex-end;
    }
    @media (max-width: 640px) {
        [data-testid="stAppViewContainer"] .block-container {
            padding: 2rem 1rem 1rem;
        }
        .st-key-auth-panel {
            margin-top: 1rem;
        }
    }
</style>
"""

st.markdown(COMPACT_LAYOUT_CSS, unsafe_allow_html=True)


def get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_conn()
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT NOT NULL CHECK(role IN ('user','admin')),
            email TEXT,
            locked INTEGER NOT NULL DEFAULT 0,
            mfa_secret TEXT,
            mfa_enabled INTEGER NOT NULL DEFAULT 0,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
        """
    )
    user_columns = {row["name"] for row in conn.execute("PRAGMA table_info(users)")}
    if "locked" not in user_columns:
        conn.execute("ALTER TABLE users ADD COLUMN locked INTEGER NOT NULL DEFAULT 0")
    if "mfa_secret" not in user_columns:
        conn.execute("ALTER TABLE users ADD COLUMN mfa_secret TEXT")
    if "mfa_enabled" not in user_columns:
        conn.execute("ALTER TABLE users ADD COLUMN mfa_enabled INTEGER NOT NULL DEFAULT 0")
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS scripts (
            id TEXT PRIMARY KEY,
            filename TEXT NOT NULL,
            script_type TEXT NOT NULL,
            content TEXT NOT NULL,
            uploaded_by TEXT NOT NULL,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS password_reset_tokens (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            token TEXT NOT NULL,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS stored_files (
            id TEXT PRIMARY KEY,
            filename TEXT NOT NULL,
            content BLOB NOT NULL,
            mime_type TEXT,
            uploaded_by TEXT NOT NULL,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
        """
    )
    conn.commit()
    conn.close()

    create_user_if_missing("admin", "admin", "admin", "admin@example.com")
    create_user_if_missing("user", "user", "user", "user@example.com")


def create_user_if_missing(username, password, role, email):
    conn = get_conn()
    row = conn.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()
    if row is None:
        conn.execute(
            "INSERT INTO users (username, password, role, email) VALUES (?, ?, ?, ?)",
            (username, hash_password(password), role, email),
        )
        conn.commit()
    conn.close()


def hash_password(password):
    import hashlib
    return hashlib.sha256(password.encode("utf-8")).hexdigest()


def login_user(username, password):
    conn = get_conn()
    row = conn.execute(
        "SELECT username, role, email, mfa_secret, mfa_enabled FROM users WHERE username = ? AND password = ? AND locked = 0",
        (username, hash_password(password)),
    ).fetchone()
    conn.close()
    if row:
        return {
            "username": row["username"],
            "role": row["role"],
            "email": row["email"],
            "mfa_secret": row["mfa_secret"],
            "mfa_enabled": bool(row["mfa_enabled"]),
        }
    return None


def get_user_auth_settings(username):
    conn = get_conn()
    row = conn.execute(
        "SELECT username, role, email, mfa_secret, mfa_enabled, locked FROM users WHERE username = ?",
        (username,),
    ).fetchone()
    conn.close()
    return row


def generate_totp_secret():
    return base64.b32encode(secrets.token_bytes(20)).decode("ascii").rstrip("=")


def totp_code(secret, timestamp=None):
    padded_secret = secret + "=" * (-len(secret) % 8)
    key = base64.b32decode(padded_secret, casefold=True)
    counter = int((time.time() if timestamp is None else timestamp) // TOTP_STEP_SECONDS)
    digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code = (int.from_bytes(digest[offset:offset + 4], "big") & 0x7FFFFFFF) % 1_000_000
    return f"{code:06d}"


def verify_totp(secret, token, timestamp=None):
    token = "".join((token or "").split())
    if not secret or len(token) != 6 or not token.isdigit():
        return False
    current_time = time.time() if timestamp is None else timestamp
    return any(
        hmac.compare_digest(totp_code(secret, current_time + offset * TOTP_STEP_SECONDS), token)
        for offset in (-1, 0, 1)
    )


def set_user_mfa(username, secret, enabled):
    conn = get_conn()
    conn.execute(
        "UPDATE users SET mfa_secret = ?, mfa_enabled = ? WHERE username = ?",
        (secret, int(enabled), username),
    )
    conn.commit()
    conn.close()


def is_user_locked(username):
    conn = get_conn()
    row = conn.execute(
        "SELECT locked FROM users WHERE username = ?",
        (username,),
    ).fetchone()
    conn.close()
    return bool(row and row["locked"])


def list_user_accounts(search_term=""):
    conn = get_conn()
    if search_term:
        rows = conn.execute(
            "SELECT username, role, locked FROM users WHERE username LIKE ? COLLATE NOCASE ORDER BY username",
            (f"%{search_term}%",),
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT username, role, locked FROM users ORDER BY username"
        ).fetchall()
    conn.close()
    return rows


def set_user_locked(username, locked):
    conn = get_conn()
    result = conn.execute(
        "UPDATE users SET locked = ? WHERE username = ? AND role != 'admin'",
        (int(locked), username),
    )
    conn.commit()
    updated = result.rowcount > 0
    conn.close()
    return updated


def update_user_profile(current_username, new_username=None, new_password=None, email=None):
    conn = get_conn()
    if new_username:
        existing = conn.execute(
            "SELECT id FROM users WHERE username = ? AND username != ?",
            (new_username, current_username),
        ).fetchone()
        if existing:
            conn.close()
            return False, "Username already exists."
        conn.execute("UPDATE users SET username = ? WHERE username = ?", (new_username, current_username))
        current_username = new_username
    if new_password:
        conn.execute("UPDATE users SET password = ? WHERE username = ?", (hash_password(new_password), current_username))
    if email:
        conn.execute("UPDATE users SET email = ? WHERE username = ?", (email, current_username))
    conn.commit()
    conn.close()
    return True, "Profile updated successfully."


def detect_script_type(code):
    code = (code or "").strip()
    if not code:
        return "text"

    if re.search(r"^(from|import|def|class|if|for|while|return|print|async|await)\s", code, re.M):
        return "python"
    if re.search(r"<html|<!DOCTYPE|<body|<div|<script|<style", code, re.I):
        return "html"
    if re.search(r"^(const|let|var|function|return|console\.log|document\.)", code, re.M):
        return "javascript"
    if re.search(r"^(SELECT|INSERT|UPDATE|DELETE|CREATE TABLE|ALTER TABLE|DROP TABLE)", code, re.I):
        return "sql"
    if re.search(r"^\s*(#include|int main|public class|class |using System|package )", code, re.M):
        return "c_cpp"
    if re.search(r"^\s*(css|body|#id|\.class)", code, re.I):
        return "css"
    if re.search(r"^\s*(#!/bin/bash|echo |curl |apt |sudo |ls |cat )", code, re.M):
        return "bash"
    if re.search(r"^\s*[{\[]", code):
        return "json"
    return "text"


def script_type_label(script_type):
    mapping = {
        "python": "Python",
        "javascript": "JavaScript",
        "html": "HTML",
        "css": "CSS",
        "sql": "SQL",
        "bash": "Bash",
        "c_cpp": "C/C++",
        "json": "JSON",
        "text": "Text",
    }
    return mapping.get(script_type, "Text")


def save_script(filename, content, script_type, uploaded_by):
    sid = str(uuid.uuid4())
    conn = get_conn()
    conn.execute(
        """
        INSERT INTO scripts (id, filename, script_type, content, uploaded_by, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (sid, filename, script_type, content, uploaded_by, datetime.utcnow().isoformat(), datetime.utcnow().isoformat()),
    )
    conn.commit()
    conn.close()
    return sid


def list_scripts_for_user(username):
    conn = get_conn()
    rows = conn.execute(
        "SELECT * FROM scripts WHERE uploaded_by = ? ORDER BY created_at DESC",
        (username,),
    ).fetchall()
    conn.close()
    return rows


def list_all_scripts():
    conn = get_conn()
    rows = conn.execute("SELECT * FROM scripts ORDER BY created_at DESC").fetchall()
    conn.close()
    return rows


def get_script_by_id(script_id):
    conn = get_conn()
    row = conn.execute("SELECT * FROM scripts WHERE id = ?", (script_id,)).fetchone()
    conn.close()
    return row


def update_script_by_id(script_id, filename, content, script_type):
    conn = get_conn()
    conn.execute(
        """
        UPDATE scripts
        SET filename = ?, script_type = ?, content = ?, updated_at = ?
        WHERE id = ?
        """,
        (filename, script_type, content, datetime.utcnow().isoformat(), script_id),
    )
    conn.commit()
    conn.close()


def delete_script_by_id(script_id):
    conn = get_conn()
    conn.execute("DELETE FROM scripts WHERE id = ?", (script_id,))
    conn.commit()
    conn.close()


def save_uploaded_file(uploaded_file, uploaded_by):
    return save_file_content(
        uploaded_file.name,
        uploaded_file.getvalue(),
        uploaded_file.type,
        uploaded_by,
    )


def save_file_content(filename, content, mime_type, uploaded_by):
    file_id = str(uuid.uuid4())
    conn = get_conn()
    conn.execute(
        "INSERT INTO stored_files (id, filename, content, mime_type, uploaded_by) VALUES (?, ?, ?, ?, ?)",
        (file_id, filename, content, mime_type, uploaded_by),
    )
    conn.commit()
    conn.close()
    return file_id


def import_stored_files_zip(uploaded_zip, uploaded_by):
    try:
        with zipfile.ZipFile(io.BytesIO(uploaded_zip.getvalue())) as archive:
            members = [member for member in archive.infolist() if not member.is_dir()]
            total_size = sum(member.file_size for member in members)
            if total_size > MAX_ZIP_IMPORT_BYTES:
                return 0, "The ZIP contents exceed the 500 MB import limit."

            imported_rows = []
            for member in members:
                filename = member.filename.replace("\\", "/").rsplit("/", 1)[-1]
                if not filename or filename in {".", ".."}:
                    continue
                content = archive.read(member)
                mime_type = mimetypes.guess_type(filename)[0] or "application/octet-stream"
                imported_rows.append(
                    (str(uuid.uuid4()), filename, content, mime_type, uploaded_by)
                )
    except (OSError, RuntimeError, zipfile.BadZipFile):
        return 0, "The selected file is not a valid ZIP archive."

    if not imported_rows:
        return 0, "The ZIP archive does not contain any files to import."

    conn = get_conn()
    conn.executemany(
        "INSERT INTO stored_files (id, filename, content, mime_type, uploaded_by) VALUES (?, ?, ?, ?, ?)",
        imported_rows,
    )
    conn.commit()
    conn.close()
    return len(imported_rows), None


def export_stored_files_zip(files):
    buffer = io.BytesIO()
    used_names = set()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for stored_file in files:
            file_data = get_stored_file(stored_file["id"])
            filename = file_data["filename"].replace("\\", "/").rsplit("/", 1)[-1]
            if filename in used_names:
                filename = f"{stored_file['id'][:8]}_{filename}"
            used_names.add(filename)
            archive.writestr(filename, file_data["content"])
    buffer.seek(0)
    return buffer


def list_stored_files(username=None):
    conn = get_conn()
    if username is None:
        rows = conn.execute("SELECT id, filename, mime_type, uploaded_by, created_at FROM stored_files ORDER BY created_at DESC").fetchall()
    else:
        rows = conn.execute(
            "SELECT id, filename, mime_type, uploaded_by, created_at FROM stored_files WHERE uploaded_by = ? ORDER BY created_at DESC",
            (username,),
        ).fetchall()
    conn.close()
    return rows


def get_stored_file(file_id):
    conn = get_conn()
    row = conn.execute(
        "SELECT filename, content, mime_type FROM stored_files WHERE id = ?",
        (file_id,),
    ).fetchone()
    conn.close()
    return row


def delete_stored_file(file_id):
    conn = get_conn()
    conn.execute("DELETE FROM stored_files WHERE id = ?", (file_id,))
    conn.commit()
    conn.close()


def create_reset_token(username):
    token = str(uuid.uuid4())
    conn = get_conn()
    conn.execute("INSERT INTO password_reset_tokens (username, token) VALUES (?, ?)", (username, token))
    conn.commit()
    conn.close()
    return token


def validate_reset_token(username, token):
    conn = get_conn()
    row = conn.execute(
        "SELECT token FROM password_reset_tokens WHERE username = ? AND token = ? ORDER BY created_at DESC LIMIT 1",
        (username, token),
    ).fetchone()
    conn.close()
    return bool(row)


def clear_reset_token(username, token):
    conn = get_conn()
    conn.execute("DELETE FROM password_reset_tokens WHERE username = ? AND token = ?", (username, token))
    conn.commit()
    conn.close()


def send_password_reset_email(to_email, username, token):
    smtp_host = os.getenv("SMTP_HOST", "")
    smtp_port = int(os.getenv("SMTP_PORT", "587"))
    smtp_user = os.getenv("SMTP_USER", "")
    smtp_password = os.getenv("SMTP_PASSWORD", "")
    sender_email = os.getenv("SMTP_FROM_EMAIL", smtp_user)

    if not smtp_host or not smtp_user or not smtp_password:
        return False, "Email not configured. Set SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASSWORD, SMTP_FROM_EMAIL."

    msg = EmailMessage()
    msg["Subject"] = "Password Reset Request"
    msg["From"] = sender_email
    msg["To"] = to_email
    reset_link = f"https://your-app-url/reset?username={username}&token={token}"
    msg.set_content(
        f"Hello {username},\n\n"
        f"Use this reset token: {token}\n"
        f"Or open: {reset_link}\n\n"
        "If you did not request this, ignore this email."
    )

    try:
        with smtplib.SMTP(smtp_host, smtp_port) as server:
            server.starttls()
            server.login(smtp_user, smtp_password)
            server.send_message(msg)
        return True, "Password reset email sent."
    except Exception as exc:
        return False, f"Failed to send email: {exc}"


def export_scripts_zip(rows, folder=""):
    buffer = io.BytesIO()
    folder_parts = [
        part
        for part in folder.replace("\\", "/").split("/")
        if part and part not in {".", ".."}
    ]
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as zf:
        for row in rows:
            filename = row["filename"].replace("\\", "/").rsplit("/", 1)[-1]
            if not filename.lower().endswith((".py", ".js", ".html", ".css", ".sql", ".txt", ".json", ".sh")):
                filename = f"{filename}.{row['script_type']}"
            archive_path = "/".join([*folder_parts, filename])
            zf.writestr(archive_path, row["content"])
    buffer.seek(0)
    return buffer


def render_code_preview(content, script_type):
    if script_type in ["python", "javascript", "sql", "bash", "json", "c_cpp", "text"]:
        st.code(content, language=script_type)
    elif script_type == "html":
        st.code(content, language="html")
    else:
        st.code(content, language="text")


def script_download_filename(filename, script_type):
    extensions = {
        "python": ".py",
        "javascript": ".js",
        "html": ".html",
        "css": ".css",
        "sql": ".sql",
        "bash": ".sh",
        "json": ".json",
        "c_cpp": ".cpp",
        "text": ".txt",
    }
    if not os.path.splitext(filename)[1]:
        return f"{filename}{extensions.get(script_type, '.txt')}"
    return filename


@st.dialog("Script preview", width="large")
def show_script_preview(filename, content, script_type):
    st.caption(filename)
    render_code_preview(content, script_type)


def render_file_library(is_admin):
    uploader_version = st.session_state.get("file_uploader_version", 0)
    uploaded_files = st.file_uploader(
        "Choose files",
        accept_multiple_files=True,
        key=f"stored_file_uploader_{uploader_version}",
    )
    if uploaded_files and st.button("Save uploaded files", type="primary"):
        for uploaded_file in uploaded_files:
            save_uploaded_file(uploaded_file, st.session_state.username)
        st.session_state.file_uploader_version = uploader_version + 1
        st.success(f"Saved {len(uploaded_files)} file(s).")
        st.rerun()

    files = list_stored_files(None if is_admin else st.session_state.username)
    if not files:
        st.info("No files stored yet.")
        return

    grid_version = st.session_state.get("file_grid_version", 0)
    grid_key = f"stored_file_grid_{'admin' if is_admin else 'user'}_{grid_version}"
    grid_state = st.session_state.get(grid_key, {})
    if isinstance(grid_state, dict):
        selection_state = grid_state.get("selection", {})
    else:
        selection_state = getattr(grid_state, "selection", {})
    if isinstance(selection_state, dict):
        selected_rows = selection_state.get("rows", [])
    else:
        selected_rows = getattr(selection_state, "rows", [])

    selected_file = files[selected_rows[0]] if selected_rows and selected_rows[0] < len(files) else None
    if selected_file:
        filename_column, actions_column = st.columns([8, 2], vertical_alignment="center")
        with filename_column:
            st.markdown(f"**{selected_file['filename']}**")
        with actions_column:
            with st.container(key="selected-file-actions"):
                action_columns = st.columns(2 if is_admin else 1, gap="medium")
                file_data = get_stored_file(selected_file["id"])
                with action_columns[0]:
                    st.download_button(
                        " ",
                        data=file_data["content"],
                        file_name=file_data["filename"],
                        mime=file_data["mime_type"] or "application/octet-stream",
                        key=f"download_stored_file_{selected_file['id']}",
                        icon=":material/download:",
                        help=f"Download {file_data['filename']}",
                        type="tertiary",
                    )
                if is_admin:
                    with action_columns[1]:
                        if st.button(
                            " ",
                            key=f"delete_stored_file_{selected_file['id']}",
                            icon=":material/delete:",
                            help=f"Delete {selected_file['filename']}",
                            type="tertiary",
                        ):
                            delete_stored_file(selected_file["id"])
                            st.session_state.file_grid_version = grid_version + 1
                            st.rerun()
    else:
        st.caption("Select a file row to show its actions.")

    grid_data = [
        {
            "Filename": stored_file["filename"],
            "Created by": stored_file["uploaded_by"],
            "Date": stored_file["created_at"],
        }
        for stored_file in files
    ]
    grid = st.dataframe(
        grid_data,
        key=grid_key,
        on_select="rerun",
        selection_mode="single-row",
        hide_index=True,
        width="stretch",
        height=min(180 + 35 * len(files), 520),
        column_config={
            "Filename": st.column_config.TextColumn("Filename", width="large"),
            "Created by": st.column_config.TextColumn("Created by", width="medium"),
            "Date": st.column_config.TextColumn("Date", width="medium"),
        },
    )


def render_bulk_file_tools():
    st.subheader("Bulk file tools")
    export_files = list_stored_files()
    with st.container(key="admin-bulk-tools"):
        import_column, export_column = st.columns([3, 1], vertical_alignment="bottom")
        with import_column:
            uploaded_zip = st.file_uploader(
                "Import files from ZIP",
                type=["zip"],
                key="stored_files_zip_uploader",
            )
            if uploaded_zip and st.button("Import ZIP", key="import_stored_files_zip"):
                imported_count, error = import_stored_files_zip(
                    uploaded_zip,
                    st.session_state.username,
                )
                if error:
                    st.error(error)
                else:
                    st.success(f"Imported {imported_count} file(s).")
                    st.session_state.file_grid_version = st.session_state.get("file_grid_version", 0) + 1
                    st.rerun()
        with export_column:
            if export_files:
                st.download_button(
                    "Download all as ZIP",
                    data=export_stored_files_zip(export_files),
                    file_name="all_stored_files.zip",
                    mime="application/zip",
                    key="download_all_stored_files",
                    use_container_width=True,
                )
            else:
                st.caption("No files available to export.")


def render_user_account_manager():
    search_term = st.text_input("Search users", key="admin_user_search")
    accounts = list_user_accounts(search_term.strip())
    if not accounts:
        st.info("No user accounts found.")
        return

    grid_version = st.session_state.get("admin_account_grid_version", 0)
    grid = st.dataframe(
        [
            {
                "Username": account["username"],
                "Account status": (
                    "Admin (protected)"
                    if account["role"] == "admin"
                    else "Locked" if account["locked"] else "Active"
                ),
            }
            for account in accounts
        ],
        key=f"admin_account_grid_{grid_version}_{search_term.strip().casefold()}",
        on_select="rerun",
        selection_mode="single-row",
        hide_index=True,
        width="stretch",
        height=min(150 + 35 * len(accounts), 420),
        column_config={
            "Username": st.column_config.TextColumn("Username", width="large"),
            "Account status": st.column_config.TextColumn("Account status", width="medium"),
        },
    )

    if not grid.selection.rows:
        st.caption("Select a user account to manage its status.")
        return

    account = accounts[grid.selection.rows[0]]
    if account["role"] == "admin":
        st.caption(f"{account['username']} is an administrator account and cannot be locked.")
        return

    is_locked = bool(account["locked"])
    action_column, _ = st.columns([1, 5])
    with action_column:
        if st.button(
            "Unlock account" if is_locked else "Lock account",
            icon=":material/lock_open:" if is_locked else ":material/lock:",
            type="secondary",
            key=f"toggle_user_lock_{account['username']}_{int(is_locked)}",
        ):
            set_user_locked(account["username"], not is_locked)
            st.session_state.admin_account_grid_version = grid_version + 1
            st.rerun()

    st.subheader(f"Reset password for {account['username']}")
    admin_auth = get_user_auth_settings(st.session_state.username)
    with st.form("admin_reset_user_password_form"):
        admin_password = st.text_input("Your admin password", type="password")
        admin_mfa_code = None
        if admin_auth["mfa_enabled"]:
            admin_mfa_code = st.text_input("Your authenticator code", max_chars=8)
        new_password = st.text_input("New user password", type="password")
        confirm_password = st.text_input("Confirm new user password", type="password")
        reset_password = st.form_submit_button("Reset user password")

    if reset_password:
        verified_admin = login_user(st.session_state.username, admin_password)
        if not verified_admin or verified_admin["role"] != "admin":
            st.error("Your admin password is incorrect.")
        elif admin_auth["mfa_enabled"] and not verify_totp(
            admin_auth["mfa_secret"], admin_mfa_code
        ):
            st.error("Your authenticator code is incorrect.")
        elif len(new_password) < 8:
            st.error("The new password must be at least 8 characters.")
        elif new_password != confirm_password:
            st.error("The new passwords do not match.")
        else:
            conn = get_conn()
            conn.execute(
                "UPDATE users SET password = ? WHERE username = ? AND role = 'user'",
                (hash_password(new_password), account["username"]),
            )
            conn.commit()
            conn.close()
            st.success(f"Password updated for {account['username']}.")


init_db()

if "logged_in" not in st.session_state:
    st.session_state.logged_in = False
if "role" not in st.session_state:
    st.session_state.role = None
if "username" not in st.session_state:
    st.session_state.username = None


def clear_login_session():
    st.session_state.logged_in = False
    st.session_state.role = None
    st.session_state.username = None
    st.session_state.profile_view = False
    st.session_state.profile_loaded = False
    st.session_state.pop("last_activity_at", None)


if st.session_state.logged_in:
    username = st.session_state.get("username")
    now = time.time()
    last_activity_at = st.session_state.get("last_activity_at", now)
    if is_user_locked(username) or now - last_activity_at >= SESSION_TIMEOUT_SECONDS:
        clear_login_session()
    else:
        st.session_state.last_activity_at = now


@st.fragment(run_every="30s")
def session_timeout_guard():
    if not st.session_state.get("logged_in", False):
        return
    last_activity_at = st.session_state.get("last_activity_at", time.time())
    if is_user_locked(st.session_state.get("username")) or time.time() - last_activity_at >= SESSION_TIMEOUT_SECONDS:
        clear_login_session()
        st.rerun()


def login_screen():
    st.markdown("### Code Vault")
    st.caption("Sign in to your account")
    username = st.text_input("Username", key="login_username")
    auth_account = get_user_auth_settings(username.strip()) if username.strip() else None
    with st.form("login_form"):
        password = st.text_input("Password", type="password")
        mfa_code = None
        if auth_account and auth_account["mfa_enabled"]:
            mfa_code = st.text_input("Authenticator code", max_chars=8)
        submitted = st.form_submit_button("Login", use_container_width=True)
        if submitted:
            user = login_user(username, password)
            if user:
                if user["mfa_enabled"] and not verify_totp(user["mfa_secret"], mfa_code):
                    st.error("Enter a valid authenticator code.")
                else:
                    st.session_state.logged_in = True
                    st.session_state.role = user["role"]
                    st.session_state.username = user["username"]
                    st.session_state.last_activity_at = time.time()
                    st.session_state.mfa_setup_prompt = not user["mfa_enabled"]
                    st.rerun()
            else:
                st.error("Invalid username or password.")


def forgot_password_screen():
    st.markdown("### Forgot password")
    with st.form("forgot_password"):
        fp_username = st.text_input("Username")
        fp_email = st.text_input("Email")
        reset_clicked = st.form_submit_button("Send Reset Email", use_container_width=True)
    if reset_clicked:
        conn = get_conn()
        row = conn.execute(
            "SELECT username, email FROM users WHERE username = ? AND email = ?",
            (fp_username, fp_email),
        ).fetchone()
        conn.close()
        if row:
            token = create_reset_token(fp_username)
            _, message = send_password_reset_email(fp_email, fp_username, token)
            st.info(message)
        else:
            st.warning("No account matches that username and email.")


def reset_password_screen():
    st.markdown("### Reset password")
    with st.form("reset_password_form"):
        username = st.text_input("Username")
        token = st.text_input("Reset token")
        new_password = st.text_input("New password", type="password")
        submitted = st.form_submit_button("Set new password", use_container_width=True)
    if submitted:
        if not username or not token or not new_password:
            st.warning("Username, token, and new password are required.")
            return
        if validate_reset_token(username, token):
            conn = get_conn()
            conn.execute("UPDATE users SET password = ? WHERE username = ?", (hash_password(new_password), username))
            conn.commit()
            conn.close()
            clear_reset_token(username, token)
            st.success("Password reset successfully.")
        else:
            st.error("Invalid reset token.")


def change_password_screen():
    st.markdown("### Change password")
    username = st.text_input("Username", key="change_password_username")
    auth_account = get_user_auth_settings(username.strip()) if username.strip() else None
    with st.form("change_password_form"):
        current_password = st.text_input("Current password", type="password")
        mfa_code = None
        if auth_account and auth_account["mfa_enabled"]:
            mfa_code = st.text_input("Authenticator code", max_chars=8)
        new_password = st.text_input("New password", type="password")
        confirm_password = st.text_input("Confirm new password", type="password")
        submitted = st.form_submit_button("Change password", use_container_width=True)
    if submitted:
        if not username or not current_password or not new_password:
            st.warning("Complete all password fields.")
        elif new_password != confirm_password:
            st.warning("The new passwords do not match.")
        elif not login_user(username, current_password):
            st.error("Username or current password is incorrect.")
        elif auth_account and auth_account["mfa_enabled"] and not verify_totp(
            auth_account["mfa_secret"], mfa_code
        ):
            st.error("Enter a valid authenticator code.")
        else:
            conn = get_conn()
            conn.execute(
                "UPDATE users SET password = ? WHERE username = ?",
                (hash_password(new_password), username),
            )
            conn.commit()
            conn.close()
            st.success("Password changed successfully.")


def show_mfa_setup_content(username):
    account = get_user_auth_settings(username)
    secret = account["mfa_secret"]
    if not secret:
        secret = generate_totp_secret()
        set_user_mfa(username, secret, False)
    account_label = quote(f"Code Vault:{username}")
    issuer = quote("Code Vault")
    provisioning_uri = (
        f"otpauth://totp/{account_label}?secret={secret}&issuer={issuer}"
        "&algorithm=SHA1&digits=6&period=30"
    )
    st.caption("Scan this QR code using Google Authenticator or another TOTP app.")
    if qrcode:
        qr_image = qrcode.make(provisioning_uri, box_size=4, border=2)
        qr_buffer = io.BytesIO()
        qr_image.save(qr_buffer, format="PNG")
        st.image(qr_buffer.getvalue(), width="content", output_format="PNG")
    else:
        st.warning("QR display requires the qrcode project dependency. Use the optional setup details below.")
    with st.expander("Can't scan? Show setup key"):
        st.code(secret, language="text")
        st.code(provisioning_uri, language="text")

    if st.button("Generate a new setup key", key="regenerate_mfa_secret"):
        set_user_mfa(username, generate_totp_secret(), False)
        st.rerun()

    with st.form("enable_mfa_form"):
        code_column, verify_column = st.columns([2, 1], vertical_alignment="bottom")
        with code_column:
            code = st.text_input("One-time code from your authenticator", max_chars=8)
        with verify_column:
            submitted = st.form_submit_button("Verify and enable", use_container_width=True)
    if submitted:
        if verify_totp(secret, code):
            set_user_mfa(username, secret, True)
            st.session_state.mfa_setup_prompt = False
            st.session_state.profile_mfa_setup = False
            st.success("MFA is enabled.")
            st.rerun()
        else:
            st.error("That code is not valid. Check the authenticator time and try again.")


@st.dialog("Set up authenticator app", width="large")
def show_mfa_setup_dialog(username):
    show_mfa_setup_content(username)


def render_mfa_settings(username):
    account = get_user_auth_settings(username)
    st.markdown("#### Multi-factor authentication")
    if st.session_state.get("profile_mfa_setup", False):
        show_mfa_setup_content(username)
        return

    if account["mfa_enabled"]:
        st.success("Authenticator app MFA is enabled.")
        with st.form("manage_mfa_form"):
            action_column, password_column, code_column, continue_column = st.columns(
                [1.5, 2, 1.5, 1],
                vertical_alignment="bottom",
            )
            with action_column:
                action = st.selectbox("MFA settings", ["Turn off MFA", "Replace authenticator"])
            with password_column:
                current_password = st.text_input("Current password", type="password")
            with code_column:
                code = st.text_input("Current authenticator code", max_chars=8)
            with continue_column:
                submitted = st.form_submit_button("Continue", use_container_width=True)
        if submitted:
            user = login_user(username, current_password)
            if not user:
                st.error("Current password is incorrect.")
            elif not verify_totp(account["mfa_secret"], code):
                st.error("Enter a valid authenticator code.")
            elif action == "Turn off MFA":
                set_user_mfa(username, None, False)
                st.success("MFA is now turned off.")
                st.rerun()
            else:
                set_user_mfa(username, generate_totp_secret(), False)
                st.session_state.profile_mfa_setup = True
                st.rerun()
        return

    button_label = "Continue MFA setup" if account["mfa_secret"] else "Set up authenticator app"
    if st.button(button_label, key="open_mfa_setup"):
        if not account["mfa_secret"]:
            set_user_mfa(username, generate_totp_secret(), False)
        st.session_state.profile_mfa_setup = True
        st.rerun()


@st.dialog("Profile settings", width="large")
def render_profile():
    username = st.session_state.username
    auth_account = get_user_auth_settings(username)
    with st.form("load_profile_form"):
        password_column, code_column, verify_column = st.columns(
            [2, 1, 1],
            vertical_alignment="bottom",
        )
        with password_column:
            current_password = st.text_input("Current password", type="password")
        mfa_code = None
        with code_column:
            if auth_account["mfa_enabled"]:
                mfa_code = st.text_input("Authenticator code", max_chars=8)
        with verify_column:
            load_profile = st.form_submit_button("Verify", use_container_width=True)
    if load_profile:
        user = login_user(st.session_state.username, current_password)
        if user and (
            not auth_account["mfa_enabled"]
            or verify_totp(auth_account["mfa_secret"], mfa_code)
        ):
            st.session_state.profile_loaded = True
            st.session_state.current_email = user["email"] or ""
        else:
            st.warning("Current password or authenticator code is incorrect.")

    if st.session_state.get("profile_loaded", False):
        with st.form("update_profile_form"):
            username_column, email_column, password_column, update_column = st.columns(
                [2, 2, 2, 1],
                vertical_alignment="bottom",
            )
            with username_column:
                new_username = st.text_input(
                    "Username",
                    value=st.session_state.username,
                    key=f"profile_username_{username}",
                )
            with email_column:
                new_email = st.text_input(
                    "Email",
                    value=st.session_state.get("current_email", ""),
                    key=f"profile_email_{username}",
                )
            with password_column:
                new_password = st.text_input("New password", type="password")
            with update_column:
                update_profile = st.form_submit_button("Update", use_container_width=True)
        if update_profile:
            ok, msg = update_user_profile(
                st.session_state.username,
                new_username.strip(),
                new_password.strip() or None,
                new_email.strip() or None,
            )
            if ok:
                st.session_state.username = new_username.strip()
                st.success(msg)
                st.rerun()
            else:
                st.error(msg)
        render_mfa_settings(username)


if not st.session_state.logged_in:
    with st.container(key="auth-switch"):
        auth_mode = st.segmented_control(
            "Authentication",
            ["Login", "Forgot", "Reset", "Change password"],
            default="Login",
            label_visibility="collapsed",
            key="auth_mode",
            width="content",
        )

    with st.container(key="auth-panel"):
        if auth_mode == "Forgot":
            forgot_password_screen()
        elif auth_mode == "Reset":
            reset_password_screen()
        elif auth_mode == "Change password":
            change_password_screen()
        else:
            login_screen()
else:
    session_timeout_guard()
    _, account_column = st.columns([10, 1])
    with account_column:
        with st.popover("Account", icon=":material/account_circle:", help="Profile and logout", use_container_width=True):
            st.caption(st.session_state.username)
            if st.button("Profile", use_container_width=True):
                render_profile()
            if st.button("Logout", use_container_width=True):
                clear_login_session()
                st.rerun()

    if st.session_state.get("mfa_setup_prompt", False):
        st.info("MFA is not enabled for this account. Set it up from Profile settings for stronger sign-in security.")
        setup_column, defer_column, _ = st.columns([1, 1, 4])
        with setup_column:
            if st.button("Set up MFA", key="open_mfa_setup"):
                st.session_state.mfa_setup_prompt = False
                show_mfa_setup_dialog(st.session_state.username)
        with defer_column:
            if st.button("Later", key="defer_mfa_setup"):
                st.session_state.mfa_setup_prompt = False
                st.rerun()

    if st.session_state.role == "user":
        user_tab1, user_tab2, user_tab3 = st.tabs(["Paste Code", "My Scripts", "Files"])

        with user_tab1:
            col_a, col_b = st.columns([2, 1])
            with col_a:
                filename = st.text_input("Filename", placeholder="example.py")
            with col_b:
                script_type = st.selectbox(
                    "Type",
                    ["python", "javascript", "html", "css", "sql", "bash", "json", "c_cpp", "text"],
                    index=0,
                )
            if st_ace:
                if "user_code_editor_version" not in st.session_state:
                    st.session_state.user_code_editor_version = 0
                raw_code = st_ace(
                    value="",
                    language=ACE_LANGUAGES[script_type],
                    theme="tomorrow_night",
                    key=f"user_code_editor_{st.session_state.user_code_editor_version}",
                    height=260,
                    auto_update=True,
                    keybinding="vscode",
                    show_print_margin=False,
                ) or ""
            else:
                raw_code = st.text_area("Code", height=260)
                st.caption("Install the project requirements to enable syntax highlighting.")
            detected = detect_script_type(raw_code) if raw_code.strip() else "text"
            st.caption(f"Auto-detected type: {script_type_label(detected)}")

            if st.button("Save Code", type="primary"):
                if not filename.strip() or not raw_code.strip():
                    st.warning("Filename and code are required.")
                else:
                    chosen_type = script_type if script_type != "text" else detected
                    save_script(filename.strip(), raw_code.strip(), chosen_type, st.session_state.username)
                    st.success(f"Saved: {filename.strip()} ({script_type_label(chosen_type)})")
                    if st_ace:
                        st.session_state.user_code_editor_version += 1
                    st.rerun()

        with user_tab2:
            rows = list_scripts_for_user(st.session_state.username)
            if not rows:
                st.info("No saved scripts.")
            else:
                for row in rows:
                    info_column, preview_column, download_column = st.columns([6, 1, 1])
                    with info_column:
                        st.write(f"{row['filename']} • {script_type_label(row['script_type'])}")
                        st.caption(f"Created: {row['created_at']}")
                    with preview_column:
                        if st.button(
                            " ",
                            key=f"preview_user_script_{row['id']}",
                            icon=":material/visibility:",
                            help=f"Preview {row['filename']}",
                            type="tertiary",
                        ):
                            show_script_preview(row["filename"], row["content"], row["script_type"])
                    with download_column:
                        st.download_button(
                            " ",
                            data=row["content"].encode("utf-8"),
                            file_name=script_download_filename(row["filename"], row["script_type"]),
                            mime="text/plain",
                            key=f"download_user_script_{row['id']}",
                            icon=":material/download:",
                            help=f"Download {row['filename']}",
                            type="tertiary",
                        )

        with user_tab3:
            render_file_library(is_admin=False)

    elif st.session_state.role == "admin":
        admin_tab1, admin_tab2, admin_tab3, admin_tab4, admin_tab5, admin_tab6 = st.tabs(
            ["Codes", "Add Script", "Export ZIP", "Files", "Bulk Files", "Accounts"]
        )

        with admin_tab1:
            rows = list_all_scripts()
            if not rows:
                st.info("No scripts found.")
            else:
                scripts_by_id = {row["id"]: row for row in rows}
                script_ids = list(scripts_by_id)
                select_column, action_preview, action_download, action_edit, action_cancel, action_delete = st.columns(
                    [4, 1, 1, 1, 1, 1],
                    vertical_alignment="bottom",
                )
                with select_column:
                    selected_id = st.selectbox(
                        "Select script",
                        script_ids,
                        format_func=lambda script_id: (
                            f"{scripts_by_id[script_id]['filename']} • "
                            f"{script_type_label(scripts_by_id[script_id]['script_type'])}"
                        ),
                    )
                script = scripts_by_id[selected_id]
                if st.session_state.get("admin_selected_script_id") != selected_id:
                    st.session_state.admin_selected_script_id = selected_id
                    st.session_state.admin_edit_mode = False

                with action_preview:
                    if st.button(
                        " ",
                        key=f"preview_admin_script_{selected_id}",
                        icon=":material/visibility:",
                        help=f"Preview {script['filename']}",
                        type="tertiary",
                    ):
                        show_script_preview(script["filename"], script["content"], script["script_type"])
                with action_download:
                    st.download_button(
                        " ",
                        data=script["content"].encode("utf-8"),
                        file_name=script_download_filename(script["filename"], script["script_type"]),
                        mime="text/plain",
                        key=f"download_admin_script_{selected_id}",
                        icon=":material/download:",
                        help=f"Download {script['filename']}",
                        type="tertiary",
                    )
                is_editing = st.session_state.get("admin_edit_mode", False)
                with action_edit:
                    if not is_editing and st.button("Edit Code", key="edit_selected_code"):
                        st.session_state.admin_edit_mode = True
                        st.rerun()
                with action_cancel:
                    if is_editing and st.button("Cancel", key="cancel_code_edit"):
                        st.session_state.admin_edit_mode = False
                        st.session_state.admin_editor_version = st.session_state.get("admin_editor_version", 0) + 1
                        st.rerun()
                with action_delete:
                    if st.button("Delete Script", key="delete_selected_code"):
                        delete_script_by_id(selected_id)
                        st.session_state.admin_edit_mode = False
                        st.rerun()

                if not st.session_state.get("admin_edit_mode", False):
                    render_code_preview(script["content"], script["script_type"])
                else:
                    editor_version = st.session_state.get("admin_editor_version", 0)
                    script_types = [
                        "python", "javascript", "html", "css", "sql",
                        "bash", "json", "c_cpp", "text",
                    ]
                    current_type = script["script_type"] if script["script_type"] in script_types else "text"
                    filename_column, type_column = st.columns([2, 1])
                    with filename_column:
                        filename = st.text_input(
                            "Filename",
                            value=script["filename"],
                            key=f"admin_filename_{selected_id}",
                        )
                    with type_column:
                        script_type = st.selectbox(
                            "Type",
                            script_types,
                            index=script_types.index(current_type),
                            key=f"admin_type_{selected_id}",
                        )
                    if st_ace:
                        content = st_ace(
                            value=script["content"],
                            language=ACE_LANGUAGES[script_type],
                            theme="tomorrow_night",
                            key=f"admin_code_{selected_id}_{editor_version}",
                            height=260,
                            auto_update=True,
                            keybinding="vscode",
                            show_print_margin=False,
                        ) or script["content"]
                    else:
                        content = st.text_area(
                            "Code",
                            value=script["content"],
                            height=260,
                            key=f"admin_code_{selected_id}_{editor_version}",
                        )

                    save_column, cancel_column = st.columns(2)
                    with save_column:
                        if st.button("Save changes", type="primary", key="save_selected_code"):
                            update_script_by_id(selected_id, filename, content, script_type)
                            st.session_state.admin_edit_mode = False
                            st.session_state.admin_editor_version = editor_version + 1
                            st.rerun()

        with admin_tab2:
            filename_column, type_column = st.columns([2, 1])
            with filename_column:
                new_filename = st.text_input(
                    "Filename",
                    placeholder="example.py",
                    key="admin_new_filename",
                )
            with type_column:
                new_script_type = st.selectbox(
                    "Type",
                    ["python", "javascript", "html", "css", "sql", "bash", "json", "c_cpp", "text"],
                    key="admin_new_script_type",
                )

            if "admin_new_editor_version" not in st.session_state:
                st.session_state.admin_new_editor_version = 0
            if st_ace:
                new_content = st_ace(
                    value="",
                    language=ACE_LANGUAGES[new_script_type],
                    theme="tomorrow_night",
                    key=f"admin_new_code_{st.session_state.admin_new_editor_version}",
                    height=260,
                    auto_update=True,
                    keybinding="vscode",
                    show_print_margin=False,
                ) or ""
            else:
                new_content = st.text_area(
                    "Code",
                    height=260,
                    key=f"admin_new_code_{st.session_state.admin_new_editor_version}",
                )

            if st.button("Save Script", type="primary", key="admin_save_new_script"):
                if not new_filename.strip() or not new_content.strip():
                    st.warning("Filename and code are required.")
                else:
                    chosen_type = (
                        new_script_type
                        if new_script_type != "text"
                        else detect_script_type(new_content)
                    )
                    save_script(
                        new_filename.strip(),
                        new_content.strip(),
                        chosen_type,
                        st.session_state.username,
                    )
                    st.session_state.admin_new_editor_version += 1
                    st.success(f"Saved: {new_filename.strip()} ({script_type_label(chosen_type)})")
                    st.rerun()

        with admin_tab3:
            rows = list_all_scripts()
            if not rows:
                st.info("No scripts available for export.")
            else:
                scripts_by_id = {row["id"]: row for row in rows}
                script_ids = list(scripts_by_id)
                selected_ids = st.multiselect(
                    "Select files to include",
                    script_ids,
                    format_func=lambda script_id: (
                        f"{scripts_by_id[script_id]['filename']} • "
                        f"{script_type_label(scripts_by_id[script_id]['script_type'])}"
                    ),
                )
                folder = st.text_input("Folder inside ZIP", value="code-vault")
                if selected_ids:
                    selected_rows = [scripts_by_id[script_id] for script_id in selected_ids]
                    zip_buffer = export_scripts_zip(selected_rows, folder)
                    st.download_button(
                        label="Download selected files",
                        data=zip_buffer,
                        file_name="code_vault_export.zip",
                        mime="application/zip",
                    )
                else:
                    st.info("Select at least one file to prepare a download.")

        with admin_tab4:
            render_file_library(is_admin=True)

        with admin_tab5:
            render_bulk_file_tools()

        with admin_tab6:
            render_user_account_manager()


st.sidebar.title("Code Vault")
st.sidebar.caption("Role-based code management")
