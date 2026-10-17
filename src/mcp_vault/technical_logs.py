"""Vault-owned UTC technical segments; business activity retains its own policy."""
from __future__ import annotations

import argparse
import json
import logging
import os
import re
import stat
from datetime import datetime, timedelta, timezone
from pathlib import Path

_SEGMENT = re.compile(r"^vault-technical-(\d{4}-\d{2}-\d{2})\.log$")
_CODE = re.compile(r"^[a-zA-Z][a-zA-Z0-9_.:-]{0,127}$")

def private_directory(value):
    path = Path(value)
    if not path.is_absolute():
        raise ValueError("absolute private technical log directory required")
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    info = path.lstat()
    if (path.resolve() != path or not stat.S_ISDIR(info.st_mode)
            or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o077):
        raise ValueError("private owned technical log directory required")
    return path


def cleanup(directory, *, now, days=30, batch=100):
    """Remove at most batch closed Vault segments, never audit or another sink."""
    if (now.utcoffset() is None or type(days) is not int or days < 30
            or type(batch) is not int or not 1 <= batch <= 1000):
        raise ValueError("invalid technical retention policy")
    directory = private_directory(directory)
    cutoff = now.astimezone(timezone.utc).date() - timedelta(days=days)
    removed = 0
    complete = True
    # This deployment directory contains only its dated segments. Bound even a
    # malformed inventory; uncertainty leaves every file intact for inspection.
    entries = []
    with os.scandir(directory) as scan:
        for entry in scan:
            entries.append(entry.name)
            if len(entries) > 10000:
                return {"removed": 0, "complete": False}
    for name in sorted(entries):
        match = _SEGMENT.fullmatch(name)
        if not match:
            continue
        try:
            day = datetime.strptime(match[1], "%Y-%m-%d").date()
        except ValueError:
            continue
        info = (directory / name).lstat()
        if (day >= cutoff or not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o077):
            continue
        if removed == batch:
            complete = False
            break
        (directory / name).unlink()
        removed += 1
    if removed:
        descriptor = os.open(directory, os.O_DIRECTORY | os.O_RDONLY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    return {"removed": removed, "complete": complete}


class TechnicalLogHandler(logging.Handler):
    def __init__(self, directory, *, clock=lambda: datetime.now(timezone.utc)):
        super().__init__()
        self.directory, self.clock = private_directory(directory), clock

    def emit(self, record):
        if not record.name.startswith(("mcp_vault.", "mcp-vault")):
            return
        now = self.clock()
        if now.utcoffset() is None:
            raise ValueError("UTC technical log clock required")
        now = now.astimezone(timezone.utc)
        # No interpolation, traceback, body or arbitrary structured fields.
        code = record.msg if isinstance(record.msg, str) and _CODE.fullmatch(record.msg) else "event"
        line = f"{now.isoformat()} {record.levelname} {record.name} {code}\n".encode()
        path = self.directory / f"vault-technical-{now.date().isoformat()}.log"
        descriptor = os.open(path, os.O_CREAT | os.O_APPEND | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
        try:
            info = os.fstat(descriptor)
            if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                    or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o077):
                raise ValueError("private owned technical segment required")
            while line:
                count = os.write(descriptor, line)
                if count <= 0:
                    raise OSError("technical log write failed")
                line = line[count:]
            os.fsync(descriptor)
        finally:
            os.close(descriptor)


class TechnicalLogsMiddleware:
    def __init__(self, app, cfg):
        self.app, self.cfg = app, cfg

    async def __call__(self, scope, receive, send):
        if scope["type"] != "lifespan" or not self.cfg.technical_log_directory:
            return await self.app(scope, receive, send)
        handler = TechnicalLogHandler(self.cfg.technical_log_directory)
        root = logging.getLogger()
        root.addHandler(handler)
        try:
            await self.app(scope, receive, send)
        finally:
            root.removeHandler(handler)
            handler.close()


def main():
    parser = argparse.ArgumentParser(description="Clean only closed Vault technical UTC segments")
    parser.add_argument("--directory", required=True)
    parser.add_argument("--days", type=int, default=30)
    parser.add_argument("--batch", type=int, default=100)
    args = parser.parse_args()
    print(json.dumps(cleanup(args.directory, now=datetime.now(timezone.utc), days=args.days, batch=args.batch)))


if __name__ == "__main__":
    main()
