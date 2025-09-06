#!/usr/bin/env python3
import asyncio
import sys
from contextlib import asynccontextmanager

COMMAND_PORT = 9048
KILL_CMD = b'\x03'
RESPONSE_OK = 0
RESPONSE_ERROR = 255

@asynccontextmanager
async def open_connection(host: str, port: int):
    while True:
        try:
            reader, writer = await asyncio.open_connection(host, port)
        except OSError:
            await asyncio.sleep(1)
            continue
        try:
            yield reader, writer
            break
        finally:
            await writer.drain()
            writer.close()


async def kill(host: str):
    async with open_connection(host, COMMAND_PORT) as (_, _):
        pass


if __name__ == '__main__':
    if len(sys.argv) > 2:
        print(f'usage: {__file__} ps5ip')
        sys.exit()

    if len(sys.argv) == 2:
        try:
            asyncio.run(kill(sys.argv[1]))
        except KeyboardInterrupt:
            pass
        sys.exit()
