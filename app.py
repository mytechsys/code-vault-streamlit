import io
import os
import re
import smtplib
import sqlite3
import uuid
import zipfile
from datetime import datetime
from email.message import EmailMessage

import streamlit as st

DB_PATH = "app.db"

CUSTOM_CSS = """
<style>
    :root {
        --bg: #ffffff;
        --panel: #ffffff;
        --panel-soft: #f4f9ff;
        --primary: #1f6feb;
        --primary-soft: #eaf3ff;
        --border: #dfe8f5;
        --text: #1b2430;
        --muted: #55657a;
        --field-bg: #ffffff;
    }
    .stApp {
        background: var(--bg);
        color: var(--text);
    }
    .block-container {
        padding-top: 1.4rem;
        padding-bottom: 1.4rem;
        max-width: 1200px;
    }
    div[data-testid="stSidebar"] {
        background: var(--panel-soft);
        border-right: 1px solid var(--border);
    }
    .stTitle, .stHeader, .stSubheader {
        letter-spacing: 0.1px;
    }
    h1 {
        font-size: 1.8rem !important;
        margin-bottom: 0.5rem !important;
    }
    h2 {
        font-size: 1.3rem !important;
        margin-bottom: 0.3rem !important;
    }
    h3 {
        font-size: 1.05rem !important;
    }
    .stTextInput > div > div > input,
    .stTextArea > div > div > textarea,
    .stSelectbox > div > div,
    .stNumberInput > div > div > input,
    .stDateInput > div > div > input,
    .stButton > button,
    select,
    input,
    textarea {
        border-radius: 8px !important;
    }
    .stTextInput > div > div > input,
    .stTextArea > div > div > textarea,
    .stSelectbox > div > div > div,
    .stNumberInput > div > div > input,
    .stDateInput > div > div > input,
    textarea,
    input,
    select {
        background: var(--field-bg) !important;
        color: var(--text) !important;
        border: 1px solid var(--border) !important;
        box-shadow: none !important;
    }
    .stTextInput > div > div > input::placeholder,
    .stTextArea > div > div > textarea::placeholder {
        color: #7d8aa1 !important;
    }
    .stButton > button {
        background: var(--primary);
        color: white;
        border: none;
        padding: 0.45rem 0.9rem;
        font-weight: 600;
    }
    .stButton > button:hover {
        background: #1557c0;
    }
    .small-note {
        color: var(--muted);
        font-size: 0.8rem;
    }
    .info-card {
        background: var(--primary-soft);
        border: 1px solid var(--border);
        border-radius: 10px;
        padding: 0.8rem 1rem;
    }
    [data-testid="stBaseButton-secondary"],
    .stDownloadButton > button,
    .stDownloadButton button {
        background: #ffffff !important;
        color: var(--primary) !important;
        border: 1px solid var(--border) !important;
    }
    .stTabs [role="tablist"] button {
        background: transparent;
        color: var(--text);
    }
    .stTabs [role="tablist"] .st-bo {
        border-color: var(--primary);
    }
    .stCodeBlock {
        background: #f7faff !important;
        border: 1px solid var(--border) !important;
    }
</style>
"""

st.markdown(CUSTOM_CSS, unsafe_allow_html=True)


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


def export_scripts_zip(rows):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as zf:
        for row in rows:
            filename = row["filename"]
            if not filename.lower().endswith((".py", ".js", ".html", ".css", ".sql", ".txt", ".json", ".sh")):
                filename = f"{filename}.{row['script_type']}"
            zf.writestr(filename, row["content"])
    buffer.seek(0)
    return buffer


def render_code_preview(content, script_type):
    if script_type in ["python", "javascript", "sql", "bash", "json", "c_cpp", "text"]:
        st.code(content, language=script_type)
    elif script_type == "html":
        st.code(content, language="html")
    else:
        st.code(content, language="text")


st.set_page_config(page_title="Code Vault", page_icon="🧠", layout="wide")
init_db()

if "logged_in" not in st.session_state:
    st.session_state.logged_in = False
if "role" not in st.session_state:
    st.session_state.role = None
if "username" not in st.session_state:
    st.session_state.username = None


def login_screen():
    st.title("Code Vault")
    st.caption("Simple code storage for users and admins")
    with st.form("login_form"):
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")
        submitted = st.form_submit_button("Login")
        if submitted:
            user = login_user(username, password)
            if user:
                st.session_state.logged_in = True
                st.session_state.role = user["role"]
                st.session_state.username = user["username"]
                st.rerun()
            else:
                st.error("Invalid username or password.")

    st.markdown("<div class='info-card'><span class='small-note'>Default accounts: admin/admin and user/user</span></div>", unsafe_allow_html=True)

    st.markdown("---")
    st.subheader("Forgot Password")
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
    st.title("Reset Password")
    username = st.text_input("Username")
    token = st.text_input("Reset Token")
    new_password = st.text_input("New Password", type="password")
    if st.button("Set New Password"):
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


if not st.session_state.logged_in:
    tab_login, tab_reset = st.tabs(["Login", "Reset Password"])
    with tab_login:
        login_screen()
    with tab_reset:
        reset_password_screen()
else:
    st.title(f"Welcome, {st.session_state.username}")
    st.caption(f"Role: {st.session_state.role}")
    if st.button("Logout"):
        st.session_state.logged_in = False
        st.session_state.role = None
        st.session_state.username = None
        st.rerun()

    if st.session_state.role == "user":
        user_tab1, user_tab2, user_tab3 = st.tabs(["Paste Code", "My Files", "Profile"])

        with user_tab1:
            with st.form("save_script_form"):
                col_a, col_b = st.columns([2, 1])
                with col_a:
                    filename = st.text_input("Filename", placeholder="example.py")
                with col_b:
                    script_type = st.selectbox(
                        "Type",
                        ["python", "javascript", "html", "css", "sql", "bash", "json", "c_cpp", "text"],
                        index=0,
                    )
                raw_code = st.text_area("Code", height=260)
                detected = detect_script_type(raw_code) if raw_code.strip() else "text"
                st.caption(f"Auto-detected type: {script_type_label(detected)}")

                submitted = st.form_submit_button("Save Code")
                if submitted:
                    if not filename.strip() or not raw_code.strip():
                        st.warning("Filename and code are required.")
                    else:
                        chosen_type = script_type if script_type != "text" else detected
                        save_script(filename.strip(), raw_code.strip(), chosen_type, st.session_state.username)
                        st.success(f"Saved: {filename.strip()} ({script_type_label(chosen_type)})")
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
                    ok, msg = update_user_profile(st.session_state.username, new_username.strip(), new_password.strip() or None, new_email.strip() or None)
                    if ok:
                        st.session_state.username = new_username.strip()
                        st.success(msg)
                        st.rerun()
                    else:
                        st.error(msg)

    elif st.session_state.role == "admin":
        admin_tab1, admin_tab2, admin_tab3 = st.tabs(["Codes", "Export ZIP", "Profile"])

        with admin_tab1:
            search_term = st.text_input("Search by filename or type", placeholder="python, app.py")
            rows = list_all_scripts()
            if search_term:
                rows = [r for r in rows if search_term.lower() in (r["filename"] + " " + r["script_type"]).lower()]

            if not rows:
                st.info("No scripts found.")
            else:
                IDs = [r["id"] for r in rows]
                selected_id = st.selectbox(
                    "Select script",
                    IDs,
                    format_func=lambda x: f"{get_script_by_id(x)['filename']} • {script_type_label(get_script_by_id(x)['script_type'])}",
                )
                script = get_script_by_id(selected_id)
                if script:
                    with st.form("admin_update_form"):
                        c1, c2 = st.columns([2, 1])
                        with c1:
                            filename = st.text_input("Filename", value=script["filename"])
                        with c2:
                            script_type = st.selectbox(
                                "Type",
                                ["python", "javascript", "html", "css", "sql", "bash", "json", "c_cpp", "text"],
                                index=["python", "javascript", "html", "css", "sql", "bash", "json", "c_cpp", "text"].index(script["script_type"]) if script["script_type"] in ["python", "javascript", "html", "css", "sql", "bash", "json", "c_cpp", "text"] else 8,
                            )

                        content = st.text_area("Code", value=script["content"], height=280)
                        detected = detect_script_type(content) if content.strip() else "text"
                        st.caption(f"Auto-detected type: {script_type_label(detected)}")

                        if st.form_submit_button("Update Code"):
                            update_script_by_id(selected_id, filename, content, script_type)
                            st.success("Code updated.")
                            st.rerun()

                    if st.button("Delete Script"):
                        delete_script_by_id(selected_id)
                        st.warning("Script deleted.")
                        st.rerun()

        with admin_tab2:
            rows = list_all_scripts()
            if not rows:
                st.info("No scripts available for export.")
            else:
                zip_buffer = export_scripts_zip(rows)
                st.download_button(
                    label="Download ZIP",
                    data=zip_buffer,
                    file_name="all_scripts_export.zip",
                    mime="application/zip",
                )

        with admin_tab3:
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
                    ok, msg = update_user_profile(st.session_state.username, new_username.strip(), new_password.strip() or None, new_email.strip() or None)
                    if ok:
                        st.session_state.username = new_username.strip()
                        st.success(msg)
                        st.rerun()
                    else:
                        st.error(msg)


st.sidebar.title("Code Vault")
st.sidebar.caption("Role-based code management")
