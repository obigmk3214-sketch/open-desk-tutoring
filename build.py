#!/usr/bin/env python3
"""Build the password-protected index.html from src/site.html.

The readable site lives in src/site.html, which is git-ignored and never
published. This script encrypts it with a key derived from the password
(PBKDF2-HMAC-SHA256, 310,000 iterations, random salt) using AES-256-CBC, and
writes index.html: a login page that decrypts the site in the browser.

Usage:  SITE_PASSWORD='...' python3 build.py
The password is never written to any file.
"""
import base64, hashlib, json, os, subprocess, sys

ITERATIONS = 310_000
MARKER = "ODT-OK\n"  # lets the page tell a wrong password from a right one

here = os.path.dirname(os.path.abspath(__file__))
password = os.environ.get("SITE_PASSWORD")
if not password:
    sys.exit("Set SITE_PASSWORD to build.")

with open(os.path.join(here, "src", "site.html"), encoding="utf-8") as f:
    plain = (MARKER + f.read()).encode("utf-8")

salt, iv = os.urandom(16), os.urandom(16)
key = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, ITERATIONS, 32)
cipher = subprocess.run(
    ["openssl", "enc", "-aes-256-cbc", "-K", key.hex(), "-iv", iv.hex()],
    input=plain, capture_output=True, check=True,
).stdout

payload = json.dumps({
    "i": ITERATIONS,
    "s": base64.b64encode(salt).decode(),
    "v": base64.b64encode(iv).decode(),
    "c": base64.b64encode(cipher).decode(),
})

with open(os.path.join(here, "gate.html"), encoding="utf-8") as f:
    gate = f.read()
with open(os.path.join(here, "index.html"), "w", encoding="utf-8") as f:
    f.write(gate.replace("__PAYLOAD__", payload))
print(f"Built index.html ({len(cipher):,} encrypted bytes)")
