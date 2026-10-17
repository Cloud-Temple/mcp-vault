"""Real filesystem/controlled UTC clock, separate from annual business audit."""
import asyncio
import logging
import os
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

from mcp_vault.technical_logs import TechnicalLogHandler, TechnicalLogsMiddleware, cleanup, private_directory

NOW = datetime(2026, 10, 16, tzinfo=timezone.utc)


def segment(directory, name):
    path = directory / name
    path.write_text("PRESERVED")
    path.chmod(0o600)
    return path


def test_31_day_segments_removed_29_day_and_audit_and_active_preserved(tmp_path):
    directory = private_directory(tmp_path / "logs")
    old = segment(directory, "vault-technical-2026-09-15.log")
    retained = [segment(directory, name) for name in (
        "vault-technical-2026-09-17.log", "vault-technical-2026-10-16.log",
        "audit-2025-01-01.log", "technical-2020-01-01.log", "vault-technical-2020-99-99.log")]
    assert cleanup(directory, now=NOW) == {"removed": 1, "complete": True}
    assert not old.exists() and all(path.exists() for path in retained)


def test_symlink_hardlink_and_unowned_mode_preserved(tmp_path):
    directory = private_directory(tmp_path / "logs")
    outside = segment(tmp_path, "outside")
    (directory / "vault-technical-2020-01-01.log").symlink_to(outside)
    os.link(outside, directory / "vault-technical-2020-01-02.log")
    public = segment(directory, "vault-technical-2020-01-03.log")
    public.chmod(0o644)
    assert cleanup(directory, now=NOW)["removed"] == 0
    assert outside.read_text() == "PRESERVED"


def test_batch_is_bounded_and_every_removal_is_fsynced(tmp_path, monkeypatch):
    directory = private_directory(tmp_path / "logs")
    for day in (1, 2, 3):
        segment(directory, f"vault-technical-2020-01-0{day}.log")
    calls = []
    monkeypatch.setattr(os, "fsync", lambda fd: calls.append(fd))
    assert cleanup(directory, now=NOW, batch=1) == {"removed": 1, "complete": False}
    assert len(list(directory.iterdir())) == 2 and len(calls) == 1


def test_dated_rotation_never_persists_arguments_tracebacks_or_third_party(tmp_path):
    clock = [NOW]
    handler = TechnicalLogHandler(tmp_path / "logs", clock=lambda: clock[0])
    record = logging.LogRecord("mcp_vault.service", logging.ERROR, "", 0,
                               "request %s", ("PRIVATE-BEARER",),
                               (ValueError, ValueError("PRIVATE-EXCEPTION"), None))
    handler.handle(record)
    clock[0] += timedelta(days=1)
    record.msg = "maintenance.completed"
    handler.handle(record)
    handler.handle(logging.LogRecord("httpx", logging.ERROR, "", 0, "PRIVATE", (), None))
    files = sorted(handler.directory.iterdir())
    assert len(files) == 2 and "2026-10-16" in files[0].name and "2026-10-17" in files[1].name
    text = "".join(path.read_text() for path in files)
    assert "PRIVATE" not in text and "request" not in text and "maintenance.completed" in text
    assert all(path.stat().st_mode & 0o777 == 0o600 for path in files)


def test_symlink_directory_and_segment_cannot_receive_logs(tmp_path):
    actual = private_directory(tmp_path / "actual")
    (tmp_path / "linked").symlink_to(actual, target_is_directory=True)
    with pytest.raises(ValueError):
        TechnicalLogHandler(tmp_path / "linked")
    handler = TechnicalLogHandler(actual, clock=lambda: NOW)
    outside = segment(tmp_path, "outside")
    (actual / "vault-technical-2026-10-16.log").symlink_to(outside)
    with pytest.raises(OSError):
        handler.handle(logging.LogRecord("mcp_vault.test", logging.INFO, "", 0, "safe.event", (), None))
    assert outside.read_text() == "PRESERVED"


@pytest.mark.parametrize("days,batch", [(29, 1), (True, 1), (30, 0), (30, 1001)])
def test_invalid_policy_never_deletes(tmp_path, days, batch):
    with pytest.raises(ValueError):
        cleanup(tmp_path / "logs", now=NOW, days=days, batch=batch)
    assert not (tmp_path / "logs").exists()


def test_real_lifespan_registers_and_always_releases_handler(tmp_path):
    root = logging.getLogger()
    baseline = list(root.handlers)

    async def app(scope, receive, send):
        assert len(root.handlers) == len(baseline) + 1
        logging.getLogger("mcp_vault.service").warning("auth.accepted")
        payload = next((tmp_path / "logs").iterdir()).read_text()
        assert "auth.accepted" in payload and "PRIVATE" not in payload
        raise RuntimeError("shutdown")

    middleware = TechnicalLogsMiddleware(app, SimpleNamespace(technical_log_directory=str(tmp_path / "logs")))
    with pytest.raises(RuntimeError, match="shutdown"):
        asyncio.run(middleware({"type": "lifespan"}, None, None))
    assert root.handlers == baseline
