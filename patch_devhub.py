import pathlib

f1 = pathlib.Path(r'C:\Users\harih\Downloads\your-digital-canvas-main\your-digital-canvas-main\src\lib\devhub\security-events.ts')
content1 = f1.read_text('utf-8')
content1 = content1.replace('connection_id: "devhub-proxy"', 'connection_id: "default-zensec-001"')
f1.write_text(content1, 'utf-8')

f2 = pathlib.Path(r'C:\Users\harih\Downloads\your-digital-canvas-main\your-digital-canvas-main\vite.config.ts')
content2 = f2.read_text('utf-8')
content2 = content2.replace("process.env.ZENTRASEC_TOKEN || 'local-dev-token-secret'", "process.env.ZENTRASEC_TOKEN || '7c3f0a515bb30199f663e462bd2093654cf3d6bd728f260ea6a6162b439d0ce7'")
f2.write_text(content2, 'utf-8')

print("Patch successful")
