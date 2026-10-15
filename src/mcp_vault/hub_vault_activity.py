"""POST de lecture propriétaire842, derrière l'auth opaque/PG ; aucune commande métier."""

from __future__ import annotations

import asyncio
import json
import re

import jwt

from .auth.hub_vault_activity import (
    HEADER,
    IDENT,
    MISSION,
    PATH,
    HubContext,
    strict_object,
)
from .storage.audit_read import ExportIncomplete
from .storage.postgres import MetadataUnavailable


async def reply(send, status, value):
    await send(
        {
            "type": "http.response.start",
            "status": status,
            "headers": [
                (b"content-type", b"application/json"),
                (b"cache-control", b"no-store"),
                (b"vary", b"Authorization"),
            ],
        }
    )
    await send(
        {
            "type": "http.response.body",
            "body": json.dumps(value, separators=(",", ":")).encode(),
        }
    )


class HubVaultActivityMiddleware:
    def __init__(self, app, cfg, context=None):
        self.app, self.cfg = app, cfg
        self.context = context or (HubContext(cfg) if cfg.hub_vault_enabled else None)
        self.slots = asyncio.Semaphore(cfg.hub_vault_max_inflight)
        self.pending = 0

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or scope.get("path") != PATH:
            return await self.app(scope, receive, send)
        if not self.cfg.hub_vault_enabled:
            return await reply(send, 404, {"status": "error", "code": "not_available"})
        if (
            scope.get("method") != "POST"
            or scope.get("query_string")
            or b"%" in scope.get("raw_path", b"")
        ):
            return await reply(
                send, 400, {"status": "error", "code": "invalid_request"}
            )
        work = asyncio.create_task(self.read(scope, receive))
        # read consumes the finite body first; monitor is started only afterwards.
        try:
            status, value = await work
            if status is not None:
                await reply(send, status, value)
        except asyncio.CancelledError:
            raise
        finally:
            work.cancel()
            await asyncio.gather(work, return_exceptions=True)

    async def read(self, scope, receive):
        acquired = False
        if self.slots.locked() and self.pending >= self.cfg.hub_vault_max_pending:
            return 503, {"status": "error", "code": "busy"}
        self.pending += 1
        try:
            async with asyncio.timeout(self.cfg.hub_vault_total_seconds):
                await self.slots.acquire()
                self.pending -= 1
                acquired = True
                values = {
                    name: [v for k, v in scope.get("headers", []) if k.lower() == name]
                    for name in (b"authorization", HEADER)
                }
                if any(len(v) != 1 for v in values.values()):
                    raise PermissionError("credentials refused")
                auth = values[b"authorization"][0]
                context = values[HEADER][0]
                if (
                    not auth.startswith(b"Bearer ")
                    or not 8 < len(auth) <= 8199
                    or len(context) > 16384
                ):
                    raise PermissionError("credentials refused")
                raw = bytearray()
                while True:
                    event = await receive()
                    if event["type"] == "http.disconnect":
                        raise asyncio.CancelledError()
                    raw.extend(event.get("body", b""))
                    if len(raw) > 8192:
                        return 400, {"status": "error", "code": "invalid_request"}
                    if not event.get("more_body"):
                        break
                try:
                    body = json.loads(raw, object_pairs_hook=strict_object)
                    if (
                        not isinstance(body, dict)
                        or set(body) - {"mission_id", "tenant_id", "limit", "cursor"}
                        or not {"mission_id", "tenant_id", "limit"} <= set(body)
                        or not isinstance(body["mission_id"], str)
                        or not MISSION.fullmatch(body["mission_id"])
                        or not isinstance(body["tenant_id"], str)
                        or not IDENT.fullmatch(body["tenant_id"])
                        or type(body["limit"]) is not int
                        or not 1 <= body["limit"] <= 100
                        or (
                            "cursor" in body
                            and (
                                not isinstance(body["cursor"], str)
                                or not re.fullmatch(
                                    r"[A-Za-z0-9_-]{43}", body["cursor"]
                                )
                            )
                        )
                    ):
                        raise ValueError("body refused")
                except (ValueError, TypeError, UnicodeError):
                    return 400, {"status": "error", "code": "invalid_request"}
                claims = await self.context.verify(
                    context.decode("ascii"), bytes(raw), body
                )

                async def validate():
                    await self.context.active(context.decode("ascii"), claims)

                from .storage.hub_vault_activity import query

                # Disconnect cancels response publication; offload retains its real worker slot until drained.
                async def disconnected():
                    while (await receive())["type"] != "http.disconnect":
                        await asyncio.sleep(0)

                running = asyncio.create_task(
                    query(auth[7:].decode("ascii"), claims, body, validate)
                )
                monitor = asyncio.create_task(disconnected())
                try:
                    await asyncio.wait(
                        {running, monitor}, return_when=asyncio.FIRST_COMPLETED
                    )
                    if monitor.done():
                        return None, None
                    value = await running
                finally:
                    running.cancel()
                    monitor.cancel()
                    await asyncio.gather(running, monitor, return_exceptions=True)
                if (
                    len(json.dumps(value).encode())
                    > self.cfg.hub_vault_max_response_bytes
                ):
                    raise MetadataUnavailable("response bound exceeded")
                return 200, value
        except ExportIncomplete:
            return 409, {"status": "error", "code": "incomplete", "complete": False}
        except (PermissionError, jwt.InvalidTokenError):
            return 403, {"status": "error", "code": "access_denied"}
        except Exception:
            return 503, {"status": "error", "code": "unavailable", "complete": False}
        finally:
            if acquired:
                self.slots.release()
            else:
                self.pending -= 1
