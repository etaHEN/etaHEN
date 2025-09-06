#!/usr/bin/env python3
import argparse
import asyncio
import re
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Union
import aiofiles

SEM = asyncio.Semaphore(60)
ORIGINAL_ELF_PORT = 9020
LOGGER_PORT = 9021
KLOGGER_PORT = 9081
COMMAND_PORT = 9028
ELF_PORT = 9027

MAX_PROCESS_NAME_LENGTH = 32
DAEMON_TYPE = b'\x01'
GAME_TYPE = b'\x02'

RESPONSE_OK = b'\x00'
RESPONSE_ERROR = b'\xff'


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


def get_logger(log: Union[Path, None]):
    if log is None:
        return DummyLogger()
    return aiofiles.open(log, 'w+', encoding='utf-8')


class ParsedArgs:

    def __init__(self):
        self.ip: str = None
        self._elf: Path = None
        self._spawner = Path('bin/spawner.elf')
        self._log = Path('log.txt')
        self._klog = Path('klog.txt')
        self.silent = False
        self.game = False
        self.name: str = None
        self._logger: aiofiles.threadpool.AiofilesContextManager = None
        self._klogger: aiofiles.threadpool.AiofilesContextManager = None
        self.logger: DummyLogger | aiofiles.threadpool.AsyncTextIOWrapper = None
        self.klogger: DummyLogger | aiofiles.threadpool.AsyncTextIOWrapper = None

    @property
    def host(self) -> str:
        return self.ip

    @property
    def elf(self) -> Union[Path, None]:
        return self._elf

    @elf.setter
    def elf(self, elf: Union[str, None]):
        if elf:
            self._elf = Path(elf)
        else:
            self._elf = None

    @property
    def spawner(self) -> Path:
        return self._spawner

    @spawner.setter
    def spawner(self, spawner: str):
        self._spawner = Path(spawner)

    @property
    def log(self) -> Path:
        return self._log

    @log.setter
    def log(self, log: str):
        self._log = Path(log)

    @property
    def klog(self) -> Path:
        return self._klog

    @klog.setter
    def klog(self, klog: str):
        self._klog = Path(klog)

    @property
    def nolog(self):
        return None

    @nolog.setter
    def nolog(self, value: bool):
        if value:
            self._log = None
            self._klog = None

    async def __aenter__(self):
        if self.nolog:
            await asyncio.sleep(0)
        else:
            self._logger = get_logger(self.log)
            self.logger = await self._logger.__aenter__()
            self._klogger = get_logger(self.klog)
            self.klogger = await self._klogger.__aenter__()
        return self

    async def __aexit__(self, *args):
        try:
            if self._logger is not None:
                await self._logger.__aexit__(*args)
                self._logger = None
                self.logger = None
        except:
            #suppress
            pass
        if self._klogger is not None:
            await self._klogger.__aexit__(*args)
            self._klogger = None
            self.klogger = None

        #ensure we have awaited at least once
        await asyncio.sleep(0)


@asynccontextmanager
async def open_connection(host: str, port: int, wait=True):
    reader = None
    writer = None
    while True:
        try:
            reader, writer = await asyncio.open_connection(host, port)
        except OSError:
            if wait:
                await asyncio.sleep(1)
                continue
        try:
            yield reader, writer
            break
        finally:
            if writer is not None:
                await writer.drain()
                writer.close()


async def send_elf(args: ParsedArgs):
    await args.logger.write('sending_elf\n')
    nameLength = len(args.name)
    if nameLength > MAX_PROCESS_NAME_LENGTH:
        args.name = args.name[:MAX_PROCESS_NAME_LENGTH]
        print(f'process name was truncated to {args.name}')
    elif nameLength < MAX_PROCESS_NAME_LENGTH:
        args.name += '\0'*(MAX_PROCESS_NAME_LENGTH - nameLength)

    async with open_connection(args.host, ELF_PORT) as (reader, writer):
        data = args.elf.read_bytes()
        if args.game:
            writer.write(GAME_TYPE)
        else:
            writer.write(DAEMON_TYPE)
        writer.write(encode(args.name))
        writer.write(len(data).to_bytes(8, byteorder='little'))
        writer.write(data)
        writer.write_eof()
        await writer.drain()
        #response = await reader.readexactly(1)
        '''
        if response == RESPONSE_OK:
            await args.logger.write('elf sent successfully\n')
            return True
        if response == RESPONSE_ERROR:
            await args.logger.write(f'failed to send {args.elf}\n')
            line = await reader.readline()
            await args.logger.write(decode(line)+'\n')
        else:
            await args.logger.write('unexpected response ' + response.hex()+'\n')
        '''
        await log_task(reader, args.logger, False)
        return False


async def log_task(reader: asyncio.StreamReader, logger: Union[DummyLogger, aiofiles.threadpool.AsyncTextIOWrapper], silent = False):
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
        if 'a looped back NS message is' in line:
            # STFU
            continue
        if silent:
            continue
        if '\r' not in line:
            await logger.write(line)
        print(line, end='')


async def has_homebrew_daemon(host: str) -> bool:
    # checks if the homebrew daemon is already running on the PS5
    async with SEM:
        try:
            async with open_connection(host, COMMAND_PORT, wait=False) as (reader, writer):
                if writer is None:
                    return False
                writer.write(b'\x00')
                response = await reader.read(1)
                return response == b'\x00'
        except OSError:
            return False


async def logger_client(args: ParsedArgs):
    async with SEM:
        async with open_connection(args.host, LOGGER_PORT) as (reader, _):
            reader._buffer = LineBuffer(reader._buffer)
            await log_task(reader, args.logger, args.silent)
        print('logger client finished')


async def send_spawner(args: ParsedArgs):
    async with SEM:
        async with open_connection(args.host, ORIGINAL_ELF_PORT, wait=False) as (reader, writer):
            if writer is None:
                return
            reader._buffer = LineBuffer(reader._buffer)
            writer.write(args.spawner.read_bytes())
            writer.write_eof()
            await writer.drain()
        await logger_client(args)


async def send_daemon(args: ParsedArgs):
    async with SEM:
        async with open_connection(args.host, ELF_PORT) as (reader, writer):
            reader._buffer = LineBuffer(reader._buffer)
            data = Path('bin/daemon.elf').read_bytes()
            writer.write(len(data).to_bytes(8, byteorder='little'))
            writer.write(data)
            writer.write_eof()
            await writer.drain()


async def klog_client(args: ParsedArgs):
    async with SEM:
        async with open_connection(args.host, KLOGGER_PORT) as (reader, _):
            reader._buffer = LineBuffer(reader._buffer)
            await log_task(reader, args.klogger, args.silent)


async def run_loggers(args: ParsedArgs):
    async with args:
        has_daemon = await has_homebrew_daemon(args.host)
        if not has_daemon:
            await send_spawner(args)
            #await send_daemon(args)
            #spawner = asyncio.create_task(send_daemon(args))
            #logger = asyncio.create_task(logger_client(args))
            #await asyncio.wait((spawner, logger), return_when=asyncio.ALL_COMPLETED)

        if args.elf:
            if args.name is None:
                args.name = args.elf.stem
            sender = asyncio.create_task(send_elf(args))
            logger = asyncio.create_task(klog_client(args))
            await asyncio.wait((sender, logger), return_when=asyncio.ALL_COMPLETED)
        else:
            await klog_client(args)
        #klogger = asyncio.create_task(klog_client(args))
        #sender = asyncio.create_task(send_elf(args))
        #await asyncio.wait((klogger, sender), return_when=asyncio.ALL_COMPLETED)


def main():
    parser = argparse.ArgumentParser(
        description='Helper script for sending the spawner, an elf to load into spawned process and for logging',
    )
    parser.add_argument('ip', help='PS5 ip address')
    #parser.add_argument('elf', help='Path to the elf to load into the spawned process')
    parser.add_argument(
        '--spawner',
        default='bin/spawner.elf',
        help='Path to the elf used to spawn the new process. (default: bin/spawner.elf)'
    )
    parser.add_argument(
        '--log',
        default='log.txt',
        help='Path to output log file if enabled. (default: log.txt)'
    )
    parser.add_argument(
        '--klog',
        default='klog.txt',
        help='Path to output log file if enabled. (default: log.txt)'
    )
    parser.add_argument(
        '--nolog',
        default=False,
        action='store_true',
        help='Switch to disable logging to an output file. (default False)'
    )
    parser.add_argument(
        '--silent',
        default=False,
        action='store_true',
        help='Switch to disable all logging. (default: False)'
    )
    parser.add_argument(
        '--game',
        default=False,
        action='store_true',
        help='Set process type to game. (default: False)'
    )
    parser.add_argument(
        '--name',
        default=None,
        help='The name of the new process. (default: the elf file name without the extension)'
    )
    args: ParsedArgs = parser.parse_args(namespace=ParsedArgs())
    try:
        if not args.spawner.exists():
            print(f'{args.spawner} does not exist')
            return
        if args.elf and not args.elf.exists():
            print(f'{args.elf} does not exist')
            return
        asyncio.run(run_loggers(args))
    except KeyboardInterrupt:
        pass


if __name__ == '__main__':
    main()
