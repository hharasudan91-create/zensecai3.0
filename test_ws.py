import asyncio
import websockets

async def test():
    try:
        async with websockets.connect('ws://127.0.0.1:8000/api/v1/ws/security-flow/default-zensec-001') as ws:
            print('Connected!')
            msg = await ws.recv()
            print(f'Received: {msg}')
    except Exception as e:
        print(f"Error: {e}")

asyncio.run(test())
