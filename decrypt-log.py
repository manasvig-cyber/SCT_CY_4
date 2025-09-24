#!/usr/bin/env python3
"""
Helper to decrypt and display log entries using key.key.

Run:
    python decrypt_log.py
"""

import os, re, sys
from cryptography.fernet import Fernet

BASE = os.path.dirname(__file__)
KEY_FILE = os.path.join(BASE, "key.key")
LOG_FILE = os.path.join(BASE, "logs", "credentials.log")

if not os.path.exists(KEY_FILE):
    print("Key file not found:", KEY_FILE)
    sys.exit(1)

if not os.path.exists(LOG_FILE):
    print("Log file not found:", LOG_FILE)
    sys.exit(1)

with open(KEY_FILE, "rb") as kf:
    key = kf.read()
fernet = Fernet(key)

line_re = re.compile(r'^(?P<ts>[^\t]+)\tusername:(?P<user>[^\t]+)\tpassword_sha256:(?P<hash>[^\t]+)\tpassword_enc:(?P<enc>.+)$')

with open(LOG_FILE, "r", encoding="utf-8") as f:
    for ln in f:
        ln = ln.rstrip("\n")
        m = line_re.match(ln)
        if not m:
            print("Unrecognized line:", ln)
            continue
        ts = m.group("ts")
        user = m.group("user")
        h = m.group("hash")
        enc = m.group("enc")
        try:
            pw = fernet.decrypt(enc.encode("utf-8")).decode("utf-8")
        except Exception as e:
            pw = f"<decryption failed: {e}>"
        print(f"{ts}\t{user}\tsha256:{h}\tpassword_plain:{pw}")
