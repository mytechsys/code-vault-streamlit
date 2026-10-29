import io
from importlib import import_module
import os
import re
import smtplib
import sqlite3
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
        padding-top: 1.5rem;
        padding-bottom: 1.5rem;
    }
    [data-testid="stForm"] [data-testid="stVerticalBlock"] {
        gap: 0.65rem;
    }
    .st-key-auth-switch [data-testid="stSegmentedControl"] {
        margin-left: auto;
    }
    .st-key-auth-panel {
        max-width: 430px;
        width: 100%;
        margin: 2rem auto 0;
    }
    @media (max-width: 640px) {
        [data-testid="stAppViewContainer"] .block-container {
            padding: 1rem;
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


init_db()

if "logged_in" not in st.session_state:
    st.session_state.logged_in = False
if "role" not in st.session_state:
    st.session_state.role = None
if "username" not in st.session_state:
    st.session_state.username = None


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
                st.rerun()
            else:
                st.error("Invalid username or password.")

    with st.expander("Forgot password"):
        with st.form("forgot_password"):
            fp_username = st.text_input("Username")
            fp_email = st.text_input("Email")
            reset_clicked = st.form_submit_button("Send Reset Email")
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
            ["Login", "Reset password"],
            default="Login",
            label_visibility="collapsed",
            key="auth_mode",
            width="content",
        )

    with st.container(key="auth-panel"):
        if auth_mode == "Reset password":
            reset_password_screen()
        else:
            login_screen()
else:
    _, account_column = st.columns([10, 1])
    with account_column:
        with st.popover("Account", icon=":material/account_circle:", help="Profile and logout", use_container_width=True):
            st.caption(st.session_state.username)
            if st.button("Profile", use_container_width=True):
                st.session_state.profile_view = True
                st.rerun()
            if st.button("Logout", use_container_width=True):
                st.session_state.logged_in = False
                st.session_state.role = None
                st.session_state.username = None
                st.session_state.profile_view = False
                st.session_state.profile_loaded = False
                st.rerun()

    if st.session_state.get("profile_view", False):
        st.subheader("Profile")
        if st.button("Back to workspace"):
            st.session_state.profile_view = False
            st.rerun()
        render_profile()
    elif st.session_state.role == "user":
        user_tab1, user_tab2 = st.tabs(["Paste Code", "My Files"])

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

    elif st.session_state.role == "admin":
        admin_tab1, admin_tab2 = st.tabs(["Codes", "Export ZIP"])

        with admin_tab1:
            search_term = st.text_input("Search by filename or type", placeholder="python, app.py")
            rows = list_all_scripts()
            if search_term:
                rows = [row for row in rows if search_term.lower() in (row["filename"] + " " + row["script_type"]).lower()]

            if not rows:
                st.info("No scripts found.")
            else:
                scripts_by_id = {row["id"]: row for row in rows}
                script_ids = list(scripts_by_id)
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

                if not st.session_state.get("admin_edit_mode", False):
                    render_code_preview(script["content"], script["script_type"])
                    if st.button("Edit Code", key="edit_selected_code"):
                        st.session_state.admin_edit_mode = True
                        st.rerun()
                else:
                    editor_version = st.session_state.get("admin_editor_version", 0)
                    filename = st.text_input(
                        "Filename",
                        value=script["filename"],
                        key=f"admin_filename_{selected_id}",
                    )
                    script_types = [
                        "python", "javascript", "html", "css", "sql",
                        "bash", "json", "c_cpp", "text",
                    ]
                    current_type = script["script_type"] if script["script_type"] in script_types else "text"
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
                            height=320,
                            auto_update=True,
                            keybinding="vscode",
                            show_print_margin=False,
                        ) or script["content"]
                    else:
                        content = st.text_area(
                            "Code",
                            value=script["content"],
                            height=320,
                            key=f"admin_code_{selected_id}_{editor_version}",
                        )

                    save_column, cancel_column = st.columns(2)
                    with save_column:
                        if st.button("Save changes", type="primary", key="save_selected_code"):
                            update_script_by_id(selected_id, filename, content, script_type)
                            st.session_state.admin_edit_mode = False
                            st.session_state.admin_editor_version = editor_version + 1
                            st.rerun()
                    with cancel_column:
                        if st.button("Cancel", key="cancel_code_edit"):
                            st.session_state.admin_edit_mode = False
                            st.session_state.admin_editor_version = editor_version + 1
                            st.rerun()

                if st.button("Delete Script", key="delete_selected_code"):
                    delete_script_by_id(selected_id)
                    st.session_state.admin_edit_mode = False
                    st.warning("Script deleted.")
                    st.rerun()

        with admin_tab2:
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


st.sidebar.title("Code Vault")
st.sidebar.caption("Role-based code management")
