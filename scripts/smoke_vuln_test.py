import asyncio
from pathlib import Path
import sys

here = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(here))

from honeypot import server as hp

async def run_vuln_test():
    log_path = here / 'honeypot_vuln_test.log'
    if log_path.exists():
        log_path.unlink()
    logger = hp.JSONLogger(log_path)

    ssh_port = 9200
    http_port = 9201

    ssh_server = await asyncio.start_server(lambda r,w: hp.handle_ssh(r, w, logger), host='127.0.0.1', port=ssh_port)
    http_server = await asyncio.start_server(lambda r,w: hp.handle_http(r, w, logger, True), host='127.0.0.1', port=http_port)

    ssh_task = asyncio.create_task(ssh_server.serve_forever())
    http_task = asyncio.create_task(http_server.serve_forever())

    await asyncio.sleep(0.1)

    # probe vuln endpoint
    try:
        reader, writer = await asyncio.open_connection('127.0.0.1', http_port)
        writer.write(b'GET /vuln?payload=show_flag HTTP/1.1\r\nHost: localhost\r\n\r\n')
        await writer.drain()
        data = await asyncio.wait_for(reader.read(8192), timeout=2)
        print('VULN response:')
        print(data.decode('utf-8', errors='replace'))
        writer.close()
        await writer.wait_closed()
    except Exception as e:
        print('VULN probe failed:', e)

    await asyncio.sleep(0.1)

    ssh_task.cancel()
    http_task.cancel()
    await asyncio.sleep(0.05)
    ssh_server.close()
    http_server.close()
    await ssh_server.wait_closed()
    await http_server.wait_closed()

    print('\nLog file:')
    if log_path.exists():
        print(log_path.read_text(encoding='utf-8'))
    else:
        print('No log created')

if __name__ == '__main__':
    asyncio.run(run_vuln_test())
