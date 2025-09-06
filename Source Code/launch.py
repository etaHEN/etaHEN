#!/usr/bin/env python3
import asyncio
import sys
from contextlib import asynccontextmanager

COMMAND_PORT = 9028
LAUNCH_CMD = b'\x01'
KILL_APP_CMD = b'\x04'
PROC_LIST_CMD = b'\x02'
RESPONSE_OK = b'\x00'
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


async def launch(host: str, appId: str):
    async with open_connection(host, COMMAND_PORT) as (reader, writer):
        writer.write(LAUNCH_CMD)
        writer.write(appId.encode('latin-1'))
        await writer.drain()
        reply = await reader.read()
        if not reply:
            print('no response')
            return
        err = reply[0]
        reply = reply[1:]
        print(err)
        if err == RESPONSE_ERROR:
            print(f'launch failed: {reply.decode("latin-1")}')
        else:
            print('launch successful')


async def kill(host: str, appId: int):
    async with open_connection(host, COMMAND_PORT) as (reader, writer):
        writer.write(KILL_APP_CMD)
        writer.write(appId.to_bytes(length=4, byteorder='little'))
        await writer.drain()
        reply = await reader.read()
        if not reply:
            print('no response')
            return
        err = reply[0]
        reply = reply[1:]
        print(err)
        if err == RESPONSE_ERROR:
            print(f'launch failed: {reply.decode("latin-1")}')
        else:
            print('launch successful')


async def list_procs(host: str):
    async with open_connection(host, COMMAND_PORT) as (_, writer):
        writer.write(PROC_LIST_CMD)
        await writer.drain()


if __name__ == '__main__':
    if len(sys.argv) > 4:
        print(f'usage: {__file__} ps5ip titleId')
        sys.exit()

    if len(sys.argv) == 2:
        try:
            asyncio.run(list_procs(sys.argv[1]))
        except KeyboardInterrupt:
            pass
        sys.exit()
    if sys.argv[2] == 'kill':
        try:
            try:
                id = int(sys.argv[3])
            except ValueError:
                id = int(sys.argv[3], 16)
            asyncio.run(kill(sys.argv[1], id))
        except KeyboardInterrupt:
            pass
    if len(sys.argv[2]) > 9:
        print('invalid title id')
        sys.exit()

    try:
        asyncio.run(launch(sys.argv[1], sys.argv[2]))
    except KeyboardInterrupt:
        pass
