# -*- coding: utf-8 -*-
"""
Client Streamable HTTP pour communiquer avec le serveur MCP Vault.

Ce client gère :
- La connexion Streamable HTTP (endpoint /mcp)
- L'appel d'outils MCP via le SDK officiel
- La gestion des erreurs et reconnexion
"""

import asyncio
import json


class MCPClient:
    """Client MCP générique via Streamable HTTP."""

    def __init__(self, base_url: str, token: str = "", timeout: float = 300.0):
        self.base_url = base_url.rstrip("/")
        self.token = token
        self.timeout = timeout

    async def call_tool(
        self,
        tool_name: str,
        arguments: dict,
    ) -> dict:
        """
        Appelle un outil MCP via Streamable HTTP.

        Args:
            tool_name: Nom de l'outil (ex: "system_health")
            arguments: Paramètres de l'outil
        Returns:
            Le résultat de l'outil (dict)
        """
        import httpx2
        from mcp import Client
        from mcp.client.streamable_http import streamable_http_client

        headers = {}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"

        try:
            timeout = httpx2.Timeout(self.timeout, connect=30)
            async with httpx2.AsyncClient(
                headers=headers,
                timeout=timeout,
            ) as http:
                transport = streamable_http_client(
                    f"{self.base_url}/mcp", http_client=http,
                )
                async with Client(
                    transport, mode="auto", read_timeout_seconds=self.timeout,
                ) as client:
                    result = await client.call_tool(tool_name, arguments)

                    # Parser la réponse MCP
                    if result.is_error:
                        error_msg = "Erreur serveur MCP"
                        if result.content:
                            error_msg = getattr(result.content[0], 'text', '') or error_msg
                        return {"status": "error", "message": error_msg}

                    text = ""
                    if result.content:
                        text = getattr(result.content[0], 'text', '') or ""
                    if not text:
                        return {"status": "error", "message": "Réponse vide"}

                    try:
                        return json.loads(text)
                    except json.JSONDecodeError:
                        return {"status": "ok", "raw": text}

        except ConnectionRefusedError:
            return {"status": "error", "message": f"Serveur non accessible: {self.base_url}"}
        except (asyncio.CancelledError, KeyboardInterrupt):
            raise
        except BaseException as e:
            if self._contains_control_flow(e):
                raise
            msg = self._extract_error(e)
            return {"status": "error", "message": msg}

    @staticmethod
    def _contains_control_flow(exc: BaseException) -> bool:
        """Détecte annulation/interrupt même encapsulée par un TaskGroup."""
        if isinstance(exc, (
            asyncio.CancelledError, KeyboardInterrupt, SystemExit, GeneratorExit,
        )):
            return True
        if isinstance(exc, BaseExceptionGroup):
            return any(MCPClient._contains_control_flow(sub)
                       for sub in exc.exceptions)
        return False

    @staticmethod
    def _extract_error(exc: BaseException) -> str:
        """Extrait un message lisible, même depuis un ExceptionGroup."""
        if hasattr(exc, "exceptions"):
            msgs = []
            for sub in exc.exceptions:
                sub_msg = MCPClient._extract_error(sub)
                msgs.append(sub_msg)
            return "; ".join(msgs)

        msg = str(exc)
        if "401" in msg or "Unauthorized" in msg:
            return "Authentification refusée (401). Vérifiez MCP_TOKEN ou ADMIN_BOOTSTRAP_KEY dans .env"
        if "403" in msg or "Forbidden" in msg:
            return "Accès interdit (403). Token insuffisant."
        return msg or type(exc).__name__

    async def call_rest(self, method: str = "GET", path: str = "/health") -> dict:
        """
        Appel REST simple (sans protocole MCP).
        Utile pour /health, /healthz, /ready qui ne nécessitent pas d'auth.
        """
        import httpx
        try:
            async with httpx.AsyncClient(timeout=10) as http:
                resp = await http.request(method, f"{self.base_url}{path}")
                try:
                    return resp.json()
                except Exception:
                    return {"status": "error", "message": resp.text, "status_code": resp.status_code}
        except httpx.ConnectError:
            return {"status": "error", "message": f"Serveur non accessible: {self.base_url}"}
        except Exception as e:
            return {"status": "error", "message": str(e)}
