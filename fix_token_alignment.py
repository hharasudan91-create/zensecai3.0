"""
Fix script: Align the ZentraSec DB token for default-zensec-001
with the token configured in DevHub's vite.config.ts.

This ensures POST /api/v1/events from DevHub passes authentication.
Run this ONCE when the backend is NOT running.
"""

import sqlite3
import sys

DEVHUB_TOKEN = '7c3f0a515bb30199f663e462bd2093654cf3d6bd728f260ea6a6162b439d0ce7'
DB_PATH = 'backend/zentrasec.db'
CONN_ID = 'default-zensec-001'

conn = sqlite3.connect(DB_PATH)
cursor = conn.cursor()

rows = cursor.execute(
    "SELECT connection_id, secure_token FROM website_connections WHERE connection_id=?",
    (CONN_ID,)
).fetchall()

if not rows:
    print(f"[ERROR] {CONN_ID} not found in DB. Start the backend once first to seed it.")
    conn.close()
    sys.exit(1)

current_token = rows[0][1] or ''
if current_token == DEVHUB_TOKEN:
    print(f"[OK] Token already matches DevHub config. No change needed.")
    conn.close()
    sys.exit(0)

# Update
cursor.execute(
    "UPDATE website_connections SET secure_token=? WHERE connection_id=?",
    (DEVHUB_TOKEN, CONN_ID)
)
conn.commit()

# Verify
verify = cursor.execute(
    "SELECT secure_token FROM website_connections WHERE connection_id=?",
    (CONN_ID,)
).fetchone()
suffix = verify[0][-4:] if verify and len(verify[0]) >= 4 else ''
print(f"[FIX APPLIED] {CONN_ID} token updated.")
print(f"[VERIFY] token_preview={verify[0][:4]}...{suffix}")
print(f"[VERIFY] token_matches_devhub={verify[0] == DEVHUB_TOKEN}")

conn.close()
print("[DONE] Restart the ZentraSec backend for the change to take effect.")
