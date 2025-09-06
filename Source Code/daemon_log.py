#!/usr/bin/env python3
import asyncio
import re
import sys
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Union
import aiofiles

SEM = asyncio.Semaphore(60)
LOGGER_PORT = 9071


class LineBuffer(bytearray):

    # hack to deal with StreamReader not allowing a regex pattern
    SEP = re.compile(b'(?:\r\n)|\r|\n')

    def find(self, _, offset):
        match = self.SEP.search(self, offset)
        return match.start() if match else -1


class DummyLogger:

    async def __aenter__(self):
        await asyncio.sleep(0)
        return self

    async def __aexit__(self, *args):
        await asyncio.sleep(0)

    async def write(self, _):
        await asyncio.sleep(0)


def decode(data: bytes) -> str:
    return data.decode('latin-1')

def encode(data: str) -> bytes:
    return data.encode('latin-1')


@asynccontextmanager
async def get_logger(log: Union[Path, None]):
    if log is None:
        logger = DummyLogger()
    else:
        logger = aiofiles.open(log, 'w+', encoding='utf-8')
    async with logger as log:
        yield log


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


async def log_task(reader: asyncio.StreamReader, logger: Union[DummyLogger, aiofiles.threadpool.AsyncTextIOWrapper]):
    line = b''
    while True:
        if reader.at_eof():
            if '\r' in line:
                await logger.write(line.replace('\r', '\n'))
            break
        try:
            line = await reader.readline()
        except OSError:
            await asyncio.sleep(1)
            continue

        line = line.decode('latin-1')
        if '\r' not in line:
            await logger.write(line)
        print(line, end='')


async def logger_client(host: str):
    async with get_logger(Path('daemon_log.txt')) as logger:
        while True:
            async with SEM:
                async with open_connection(host, LOGGER_PORT) as (reader, _):
                    reader._buffer = LineBuffer(reader._buffer)
                    await log_task(reader, logger)



def main():
    if len(sys.argv) != 2:
        print(f'usage: {__file__} ps5ip')
        sys.exit()
    try:
        asyncio.run(logger_client(sys.argv[1]))
    except KeyboardInterrupt:
        pass


if __name__ == '__main__':
    main()
