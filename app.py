import io
from importlib import import_module
import os
import re
import smtplib
import sqlite3
import time
import uuid
import zipfile
from datetime import datetime
from email.message import EmailMessage

import streamlit as st

try:
    st_ace = import_module("streamlit_ace").st_ace
except ImportError:
    st_ace = None

DB_PATH = "app.db"
SESSION_TIMEOUT_SECONDS = 15 * 60
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
    .st-key-file-list-table [data-testid="stVerticalBlock"] {
        gap: 0;
    }
    .st-key-file-list-table [data-testid="stHorizontalBlock"] {
        padding: 0.15rem 0;
        border-bottom: 1px solid var(--border-color, rgba(128, 128, 128, 0.2));
    }
    .st-key-file-list-table [data-testid="stMarkdownContainer"] p {
        margin: 0;
        font-size: 0.85rem;
        line-height: 1.25rem;
    }
    .st-key-file-list-table [data-testid="stDownloadButton"] button,
    .st-key-file-list-table [data-testid="stButton"] button {
        min-height: 1.6rem !important;
        padding: 0 !important;
        border: 0 !important;
        background: transparent !important;
        box-shadow: none !important;
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
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
        """
    )
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
        "SELECT username, role, email FROM users WHERE username = ? AND password = ?",
        (username, hash_password(password)),
    ).fetchone()
    conn.close()
    if row:
        return {"username": row["username"], "role": row["role"], "email": row["email"]}
    return None


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
    file_id = str(uuid.uuid4())
    conn = get_conn()
    conn.execute(
        "INSERT INTO stored_files (id, filename, content, mime_type, uploaded_by) VALUES (?, ?, ?, ?, ?)",
        (file_id, uploaded_file.name, uploaded_file.getvalue(), uploaded_file.type, uploaded_by),
    )
    conn.commit()
    conn.close()


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

    with st.container(key="file-list-table"):
        filename_header, creator_header, date_header, actions_header = st.columns([5, 2, 2, 1.3])
        with filename_header:
            st.markdown("**Filename**")
        with creator_header:
            st.markdown("**Created by**")
        with date_header:
            st.markdown("**Date**")
        with actions_header:
            st.markdown("**Actions**")

        for stored_file in files:
            file_column, creator_column, date_column, actions_column = st.columns(
                [5, 2, 2, 1.3],
                gap="small",
                vertical_alignment="center",
            )
            with file_column:
                st.write(stored_file["filename"])
            with creator_column:
                st.write(stored_file["uploaded_by"])
            with date_column:
                st.write(stored_file["created_at"])

            file_data = get_stored_file(stored_file["id"])
            with actions_column:
                if is_admin:
                    download_column, delete_column = st.columns(2, gap="small")
                else:
                    download_column = st.container()
                    delete_column = None

                with download_column:
                    st.download_button(
                        " ",
                        data=file_data["content"],
                        file_name=file_data["filename"],
                        mime=file_data["mime_type"] or "application/octet-stream",
                        key=f"download_stored_file_{stored_file['id']}",
                        icon=":material/download:",
                        help=f"Download {file_data['filename']}",
                    )
                if is_admin:
                    with delete_column:
                        if st.button(
                            " ",
                            key=f"delete_stored_file_{stored_file['id']}",
                            icon=":material/delete:",
                            help=f"Delete {stored_file['filename']}",
                        ):
                            delete_stored_file(stored_file["id"])
                            st.rerun()


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
    now = time.time()
    last_activity_at = st.session_state.get("last_activity_at", now)
    if now - last_activity_at >= SESSION_TIMEOUT_SECONDS:
        clear_login_session()
    else:
        st.session_state.last_activity_at = now


@st.fragment(run_every="30s")
def session_timeout_guard():
    if not st.session_state.get("logged_in", False):
        return
    last_activity_at = st.session_state.get("last_activity_at", time.time())
    if time.time() - last_activity_at >= SESSION_TIMEOUT_SECONDS:
        clear_login_session()
        st.rerun()


def login_screen():
    st.markdown("### Code Vault")
    st.caption("Sign in to your account")
    with st.form("login_form"):
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")
        submitted = st.form_submit_button("Login", use_container_width=True)
        if submitted:
            user = login_user(username, password)
            if user:
                st.session_state.logged_in = True
                st.session_state.role = user["role"]
                st.session_state.username = user["username"]
                st.session_state.last_activity_at = time.time()
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
    with st.form("change_password_form"):
        username = st.text_input("Username")
        current_password = st.text_input("Current password", type="password")
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
        else:
            conn = get_conn()
            conn.execute(
                "UPDATE users SET password = ? WHERE username = ?",
                (hash_password(new_password), username),
            )
            conn.commit()
            conn.close()
            st.success("Password changed successfully.")


def render_profile():
    current_password = st.text_input("Current password", type="password")
    if st.button("Load Profile"):
        user = login_user(st.session_state.username, current_password)
        if user:
            st.session_state.profile_loaded = True
            st.session_state.current_email = user["email"] or ""
        else:
            st.warning("Incorrect current password.")

    if st.session_state.get("profile_loaded", False):
        new_username = st.text_input("New Username", value=st.session_state.username)
        new_email = st.text_input("Email", value=st.session_state.get("current_email", ""))
        new_password = st.text_input("New Password", type="password")
        if st.button("Update Profile"):
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
                st.session_state.profile_view = True
                st.rerun()
            if st.button("Logout", use_container_width=True):
                clear_login_session()
                st.rerun()

    if st.session_state.get("profile_view", False):
        st.subheader("Profile")
        if st.button("Back to workspace"):
            st.session_state.profile_view = False
            st.rerun()
        render_profile()
    elif st.session_state.role == "user":
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
                    with st.expander(f"{row['filename']} • {script_type_label(row['script_type'])}"):
                        render_code_preview(row["content"], row["script_type"])
                        st.caption(f"Created: {row['created_at']}")

        with user_tab3:
            render_file_library(is_admin=False)

    elif st.session_state.role == "admin":
        admin_tab1, admin_tab2, admin_tab3, admin_tab4 = st.tabs(
            ["Codes", "Add Script", "Export ZIP", "Files"]
        )

        with admin_tab1:
            rows = list_all_scripts()
            if not rows:
                st.info("No scripts found.")
            else:
                scripts_by_id = {row["id"]: row for row in rows}
                script_ids = list(scripts_by_id)
                select_column, action_edit, action_cancel, action_delete = st.columns(
                    [5, 1, 1, 1],
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


st.sidebar.title("Code Vault")
st.sidebar.caption("Role-based code management")
