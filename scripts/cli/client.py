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

        # Le SDK 2.1 remplace les erreurs HTTP non JSON-RPC par un message sans
        # code. Conserver uniquement les codes du POST de CET appel, sans lire
        # les corps (arguments/secrets) et sans interférer avec le transport.
        endpoint = httpx2.URL(f"{self.base_url}/mcp")
        failed_http_codes = set()

        async def observe_response(response):
            if (response.request.method == "POST" and response.request.url == endpoint
                    and response.status_code >= 400):
                failed_http_codes.add(response.status_code)

        try:
            timeout = httpx2.Timeout(self.timeout, connect=30)
            async with httpx2.AsyncClient(
                headers=headers,
                timeout=timeout,
                event_hooks={"response": [observe_response]},
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
            if failed_http_codes and self._lost_http_placeholder(e):
                if failed_http_codes == {401}:
                    msg = "Authentification refusée (401). Vérifiez MCP_TOKEN ou ADMIN_BOOTSTRAP_KEY dans .env"
                elif failed_http_codes == {403}:
                    msg = "Accès interdit (403). Token insuffisant."
                elif failed_http_codes == {503}:
                    msg = "Service indisponible ou réponse non confirmée (503)."
                else:
                    codes = ", ".join(str(code) for code in sorted(failed_http_codes))
                    msg = f"Réponse HTTP non confirmée ({codes})."
                return {"status": "error", "message": msg}
            msg = self._extract_error(e)
            return {"status": "error", "message": msg}

    @staticmethod
    def _lost_http_placeholder(exc: BaseException) -> bool:
        """Ne pas transformer un timeout d'appel en refus d'auth tardif."""
        if isinstance(exc, BaseExceptionGroup):
            return bool(exc.exceptions) and all(MCPClient._lost_http_placeholder(e)
                                                for e in exc.exceptions)
        return (getattr(exc, "code", None), str(exc)) in {
            (-32603, "Server returned an error response"),
            (-32601, "Not Found"),
            (-32600, "Session terminated"),
        }

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
