import sqlite3

conn = sqlite3.connect('backend/zentrasec.db')
cursor = conn.cursor()

rows = cursor.execute(
    "SELECT connection_id, secure_token, website_url FROM website_connections"
).fetchall()

print(f"Total connections: {len(rows)}")
for r in rows:
    cid = r[0]
    t = r[1] or ''
    suffix = t[-4:] if len(t) >= 4 else ''
    preview = t[:4] + '...' + suffix
    print(f"  id={cid}  token_preview={preview}  url={r[2]}")

# Check match
expected = '7c3f0a515bb30199f663e462bd2093654cf3d6bd728f260ea6a6162b439d0ce7'
rows2 = cursor.execute(
    "SELECT secure_token FROM website_connections WHERE connection_id='default-zensec-001'"
).fetchall()
if rows2:
    t = rows2[0][0] or ''
    print(f"token_matches_devhub_hardcode={t == expected}")
else:
    print("default-zensec-001 NOT FOUND in DB")

conn.close()
