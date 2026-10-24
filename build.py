#!/usr/bin/env python3
"""Build the password-protected website from src/.

The readable site lives in src/ (git-ignored, never published):
  src/template.html   shared layout: head, styles, header, footer, scripts
  src/pages/*.html    page content; the first line is <!-- title: ... -->

Each page is rendered into the template, then encrypted with a key derived
from the password (PBKDF2-HMAC-SHA256, 310,000 iterations) using AES-256-CBC,
and written as a login page (gate.html) at its own address:
  index.html, about/index.html, sign-up/index.html, contact/index.html

All pages share one salt, so the key a visitor saves with "Remember me" opens
every page. A fresh salt is chosen on each build.

Usage:  SITE_PASSWORD='...' python3 build.py
The password is never written to any file.
"""
import base64, hashlib, json, os, re, subprocess, sys

ITERATIONS = 310_000
MARKER = "ODT-OK\n"  # lets the page tell a wrong password from a right one

# page key -> (source file, output folder ('' = site root))
PAGES = {
    "home": ("home.html", ""),
    "about": ("about.html", "about"),
    "signup": ("sign-up.html", "sign-up"),
    "contact": ("contact.html", "contact"),
    "privacy": ("privacy.html", "privacy"),
}

here = os.path.dirname(os.path.abspath(__file__))
password = os.environ.get("SITE_PASSWORD")
if not password:
    sys.exit("Set SITE_PASSWORD to build.")


def read(*parts):
    with open(os.path.join(here, *parts), encoding="utf-8") as f:
        return f.read()


template = read("src", "template.html")
gate = read("gate.html")
salt = os.urandom(16)
key = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, ITERATIONS, 32)

for name, (src, folder) in PAGES.items():
    content = read("src", "pages", src)
    m = re.match(r"\s*<!--\s*title:\s*(.*?)\s*-->\s*", content)
    if not m:
        sys.exit(f"{src}: first line must be <!-- title: ... -->")
    title, content = m.group(1), content[m.end():]
    root = "./" if not folder else "../" * (folder.count("/") + 1)

    html = template.replace("{{CONTENT}}", content).replace("{{TITLE}}", title)
    for other in PAGES:
        html = html.replace("{{CUR_%s}}" % other, 'aria-current="page"' if other == name else "")
    html = html.replace("{{ROOT}}", root)
    left = re.findall(r"\{\{[A-Z_a-z]+\}\}", html)
    if left:
        sys.exit(f"{src}: unfilled placeholders {sorted(set(left))}")

    iv = os.urandom(16)
    cipher = subprocess.run(
        ["openssl", "enc", "-aes-256-cbc", "-K", key.hex(), "-iv", iv.hex()],
        input=(MARKER + html).encode("utf-8"), capture_output=True, check=True,
    ).stdout
    payload = json.dumps({
        "i": ITERATIONS,
        "s": base64.b64encode(salt).decode(),
        "v": base64.b64encode(iv).decode(),
        "c": base64.b64encode(cipher).decode(),
    })
    out_dir = os.path.join(here, folder)
    os.makedirs(out_dir, exist_ok=True)
    with open(os.path.join(out_dir, "index.html"), "w", encoding="utf-8") as f:
        f.write(gate.replace("__PAYLOAD__", payload).replace("{{ROOT}}", root))
    print(f"Built {folder + '/' if folder else ''}index.html  ({title}, {len(cipher):,} encrypted bytes)")
