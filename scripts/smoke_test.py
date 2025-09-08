import asyncio
from pathlib import Path
import sys

here = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(here))

from honeypot import server as hp

async def run_test():
    log_path = here / 'honeypot_test.log'
    if log_path.exists():
        log_path.unlink()
    logger = hp.JSONLogger(log_path)

    ssh_port = 9100
    http_port = 9101

    ssh_server = await asyncio.start_server(lambda r,w: hp.handle_ssh(r, w, logger), host='127.0.0.1', port=ssh_port)
    http_server = await asyncio.start_server(lambda r,w: hp.handle_http(r, w, logger), host='127.0.0.1', port=http_port)

    ssh_task = asyncio.create_task(ssh_server.serve_forever())
    http_task = asyncio.create_task(http_server.serve_forever())

    await asyncio.sleep(0.1)  # let servers start

    # probe HTTP
    try:
        reader, writer = await asyncio.open_connection('127.0.0.1', http_port)
        writer.write(b'GET / HTTP/1.1\r\nHost: localhost\r\n\r\n')
        await writer.drain()
        data = await asyncio.wait_for(reader.read(8192), timeout=2)
        print('HTTP response (truncated):')
        print(data.decode('utf-8', errors='replace')[:1000])
        writer.close()
        await writer.wait_closed()
    except Exception as e:
        print('HTTP probe failed:', e)

    # probe SSH
    try:
        reader, writer = await asyncio.open_connection('127.0.0.1', ssh_port)
        data = await asyncio.wait_for(reader.read(256), timeout=2)
        print('SSH banner:', data.decode('utf-8', errors='replace').strip())
        writer.close()
        await writer.wait_closed()
    except Exception as e:
        print('SSH probe failed:', e)

    await asyncio.sleep(0.2)

    # shutdown servers
    ssh_task.cancel()
    http_task.cancel()
    await asyncio.sleep(0.1)
    ssh_server.close()
    http_server.close()
    await ssh_server.wait_closed()
    await http_server.wait_closed()

    print('\nLog file contents:')
    if log_path.exists():
        print(log_path)
        print(log_path.read_text(encoding='utf-8'))
    else:
        print('No log file created at', log_path)

if __name__ == '__main__':
    asyncio.run(run_test())
