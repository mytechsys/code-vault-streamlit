# Streamlit Code Vault

A role-based Streamlit app for storing code snippets by user or admin. It supports login, script metadata, file-type detection, admin management, ZIP export, and password reset email support.

## Run locally

```bash
pip install -r requirements.txt
streamlit run app.py
```

## Default credentials

- Admin: `admin` / `admin`
- User: `user` / `user`

## Features

- User login and admin login
- Role-based access control
- Paste arbitrary code and save with filename + script type
- File type detection for common languages
- Admin search, update, and delete scripts
- Unique ID generation per script
- ZIP export of all scripts
- Change username/password/email
- Password reset via email token

## SMTP configuration for password reset

Set environment variables before running:

```bash
export SMTP_HOST=smtp.gmail.com
export SMTP_PORT=587
export SMTP_USER=your_email@gmail.com
export SMTP_PASSWORD=your_app_password
export SMTP_FROM_EMAIL=your_email@gmail.com
```
