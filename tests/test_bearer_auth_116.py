# -*- coding: utf-8 -*-
"""
Issue #116 — en mode `bearer`, un appelant SANS identité atteignait les outils.

## Le défaut, tel qu'il a été relevé

Le mode `bearer` est le DÉFAUT. Le middleware y faisait :

    token_info = self._validate_token(token) if token else None

puis injectait et poursuivait. Un appelant sans en-tête `Authorization` — ou
avec un jeton invalide — atteignait donc les outils. Toutes les gardes en aval
répondent à la question « CETTE identité a-t-elle le droit ? » ; aucune ne
posait « y a-t-il seulement une identité ? » :

- `get_listing_filter(None)` → `visible: True`, aucun filtre → inventaire complet ;
- `check_policy(None)` → `None`, c'est-à-dire autorisé ;
- `enforce_mission_jwt_tool` / `enforce_wrap_only_token` → refusent des
  identités PARTICULIÈRES, n'exigent jamais d'être authentifié.

Relevé `curl` du déclarant sur une instance en service : `initialize`,
`tools/list`, `system_about`, `system_health`, `vault_list`, les quatre outils
PKI de lecture, `secret_types` et `secret_generate_password` répondaient à un
anonyme. **Aucun secret n'était lisible** (`secret_read`/`secret_list` passent
par `check_access`, qui refuse) : le défaut est une DIVULGATION — inventaire
des coffres, certificats émis donc noms de domaine du parc, nom du bucket,
adresse interne, versions.

## Pourquoi le correctif est au middleware, et pas dans les outils

Refuser au middleware ferme la surface des outils MCP d'un seul geste,
`initialize` et `tools/list` compris — et donc AUSSI tout outil ajouté plus
tard. Une correction outil par outil aurait rouvert le trou au prochain ajout,
tout en donnant l'impression d'exhaustivité.

## Ce que ces tests NE prétendent PAS

Restent publics par conception, et le vérifier fait partie du contrat :
`/health`, `/healthz`, `/ready`, `/favicon.ico`, `/` et les routes PKI/ACME.
La formule exacte est « toute la surface des OUTILS MCP », jamais « toute la
surface ».
"""

import asyncio
import json
from types import SimpleNamespace
from unittest.mock import patch

import pytest

BOOTSTRAP_KEY = "Test-Bootstrap-Key-2026-Pour-Tests-116!!"
SENTINELLE = "jeton-sentinelle-ne-doit-jamais-etre-journalise-9f3a"


def _run(coro):
    return asyncio.run(coro)


def _settings(mode="bearer"):
    return SimpleNamespace(
        mcp_auth_mode=mode,
        admin_bootstrap_key=BOOTSTRAP_KEY,
        resolved_mission_aud="vault-test",
        mcp_component_kind="vault",
        mission_token_leeway_seconds=10,
        mission_status_url="",
        mission_status_cache_ttl=5,
    )


class Harnais:
    """Monte `AuthMiddleware` sur une application factice qui ENREGISTRE son
    passage — c'est ce compteur qui prouve qu'un refus n'a rien laissé passer."""

    def __init__(self, mode="bearer"):
        from mcp_vault.auth.middleware import AuthMiddleware
        self.atteint = 0
        self.token_info = "<jamais atteint>"

        async def aval(scope, receive, send):
            from mcp_vault.auth.context import current_token_info
            self.atteint += 1
            self.token_info = current_token_info.get()
            await send({"type": "http.response.start", "status": 200, "headers": []})
            await send({"type": "http.response.body", "body": b"{}"})

        self.mw = AuthMiddleware(aval)
        self.settings = _settings(mode)

    def appel(self, token=None, path="/mcp", scope_type="http", store=None):
        headers = []
        if token is not None:
            headers.append((b"authorization", b"Bearer " + token.encode()))
        scope = {"type": scope_type, "path": path, "headers": headers,
                 "query_string": b""}
        events = []

        async def receive():
            return {"type": "http.request", "body": b"", "more_body": False}

        async def send(ev):
            events.append(ev)

        with patch("mcp_vault.auth.middleware.get_settings", return_value=self.settings), \
             patch("mcp_vault.auth.middleware.get_token_store", return_value=store):
            _run(self.mw(scope, receive, send))
        return events

    @staticmethod
    def statut(events):
        for ev in events:
            if ev["type"] == "http.response.start":
                return ev["status"]
        return None

    @staticmethod
    def entetes(events):
        for ev in events:
            if ev["type"] == "http.response.start":
                return {k.decode().lower(): v.decode() for k, v in ev["headers"]}
        return {}

    @staticmethod
    def corps(events):
        for ev in events:
            if ev["type"] == "http.response.body":
                return json.loads(ev["body"]) if ev["body"] else {}
        return None


# =============================================================================
# 1) Le refus lui-même
# =============================================================================

class TestRefusBearerStrict:

    def test_sans_jeton_refuse_et_naval_jamais_atteint(self):
        h = Harnais("bearer")
        events = h.appel(token=None)
        assert h.statut(events) == 401
        assert h.atteint == 0, (
            "l'application en aval a été atteinte : les outils MCP restent "
            "joignables sans identité"
        )

    def test_jeton_invalide_refuse_aussi(self):
        """Le point que le relevé d'origine souligne : ce n'est pas seulement
        l'absence de jeton. Un jeton INVALIDE produisait exactement le même
        `token_info=None`, donc le même passage."""
        h = Harnais("bearer")
        events = h.appel(token="jeton-inconnu-du-store", store=None)
        assert h.statut(events) == 401
        assert h.atteint == 0

    def test_entete_www_authenticate_presente(self):
        h = Harnais("bearer")
        entetes = h.entetes(h.appel(token=None))
        assert entetes.get("www-authenticate") == "Bearer"

    def test_corps_de_refus_generique(self):
        """Le motif précis reste côté serveur : la réponse ne distingue pas
        « jeton absent » de « jeton invalide » — sinon elle devient un oracle."""
        h = Harnais("bearer")
        sans = h.corps(h.appel(token=None))
        invalide = h.corps(h.appel(token="jeton-inconnu", store=None))
        assert sans == invalide, "la réponse distingue les deux causes de refus"
        assert sans["status"] == "error"

    def test_websocket_ferme_au_lieu_de_passer(self):
        h = Harnais("bearer")
        events = h.appel(token=None, scope_type="websocket")
        assert h.atteint == 0
        assert any(ev["type"] == "websocket.close" for ev in events)


# =============================================================================
# 2) Ce qui doit CONTINUER de fonctionner
# =============================================================================

class TestCeQuiResteAccessible:

    def test_cle_de_bootstrap_acceptee(self):
        """Break-glass : sans ça, une clé perdue rendrait le coffre
        inadministrable."""
        h = Harnais("bearer")
        events = h.appel(token=BOOTSTRAP_KEY)
        assert h.statut(events) == 200
        assert h.atteint == 1
        assert "admin" in h.token_info["permissions"]

    def test_jeton_valide_du_store_accepte(self):
        h = Harnais("bearer")
        store = SimpleNamespace(
            get_by_hash=lambda _h: {"client_name": "client-x",
                                    "permissions": ["read"],
                                    "allowed_resources": []},
        )
        events = h.appel(token="jeton-valide", store=store)
        assert h.statut(events) == 200
        assert h.atteint == 1
        assert h.token_info["client_name"] == "client-x"

    @pytest.mark.parametrize("chemin", ["/health", "/healthz", "/ready",
                                        "/favicon.ico"])
    def test_routes_publiques_restent_sans_jeton(self, chemin):
        h = Harnais("bearer")
        events = h.appel(token=None, path=chemin)
        assert h.statut(events) == 200
        assert h.atteint == 1, f"{chemin} doit rester joignable sans jeton"


# =============================================================================
# 3) Le mode d'exception explicite
# =============================================================================

class TestModeBearerAnonymous:

    def test_le_comportement_historique_reste_disponible(self):
        h = Harnais("bearer-anonymous")
        events = h.appel(token=None)
        assert h.statut(events) == 200
        assert h.atteint == 1
        assert h.token_info is None

    def test_jeton_invalide_passe_aussi(self):
        h = Harnais("bearer-anonymous")
        events = h.appel(token="jeton-inconnu", store=None)
        assert h.statut(events) == 200
        assert h.atteint == 1
        assert h.token_info is None

    def test_le_mode_est_accepte_sans_aucun_parametre_mission(self):
        """Le cœur du repli : s'il exigeait un JWKS, une audience et
        `ENFORCE_MISSION_TOKEN_VALIDATION`, l'exploitant dont un client casse
        n'aurait AUCUN geste utilisable. C'est le défaut trouvé en revue de
        plan : `pep_active = mode != "bearer"` rangeait ce mode du côté PEP."""
        from mcp_vault.config import Settings
        s = Settings(admin_bootstrap_key=BOOTSTRAP_KEY,
                     mcp_auth_mode="bearer-anonymous")
        assert s.mission_pep_active is False
        ok, msg = s.check_mission_pep_config()
        assert ok is True, f"le mode de repli est refusé par la validation : {msg}"

    @pytest.mark.parametrize("mode,attendu", [
        ("bearer", False), ("bearer-anonymous", False),
        ("jwt", True), ("dual-stack", True),
    ])
    def test_frontiere_du_pep_mission(self, mode, attendu):
        from mcp_vault.config import Settings
        s = Settings(admin_bootstrap_key=BOOTSTRAP_KEY, mcp_auth_mode=mode)
        assert s.mission_pep_active is attendu

    def test_les_modes_durcis_conservent_leurs_exigences(self):
        from mcp_vault.config import Settings
        for mode in ("jwt", "dual-stack"):
            s = Settings(admin_bootstrap_key=BOOTSTRAP_KEY, mcp_auth_mode=mode)
            ok, msg = s.check_mission_pep_config()
            assert ok is False, f"{mode} ne doit pas être valide sans config mission"

    def test_mode_inconnu_refuse_et_les_quatre_valeurs_listees(self):
        from mcp_vault.config import Settings
        s = Settings(admin_bootstrap_key=BOOTSTRAP_KEY, mcp_auth_mode="ouvert")
        ok, msg = s.check_mission_pep_config()
        assert ok is False
        for attendu in ("bearer", "bearer-anonymous", "jwt", "dual-stack"):
            assert attendu in msg, f"le message n'annonce pas '{attendu}'"


# =============================================================================
# 4) Le jeton refusé ne doit JAMAIS être journalisé
# =============================================================================

class TestNonDivulgationDuJetonRefuse:
    """Un jeton invalide ici est souvent un jeton VALIDE ailleurs (mauvais
    environnement, copier-coller). Le journaliser le divulguerait."""

    def test_sentinelle_absente_de_l_audit_et_des_logs(self, capfd):
        appels = []

        def _capture(*args, **kwargs):
            appels.append((args, kwargs))

        h = Harnais("bearer")
        with patch("mcp_vault.audit.log_audit", side_effect=_capture):
            events = h.appel(token=SENTINELLE, store=None)

        assert h.statut(events) == 401
        assert appels, "le refus n'a produit aucun enregistrement d'audit"

        trace_audit = json.dumps(appels, default=str)
        assert SENTINELLE not in trace_audit, "le jeton refusé apparaît dans l'audit"

        sortie, erreur = capfd.readouterr()
        assert SENTINELLE not in sortie and SENTINELLE not in erreur, (
            "le jeton refusé apparaît dans les logs"
        )

    def test_le_refus_est_bien_audite_avec_un_motif_ferme(self):
        appels = []
        h = Harnais("bearer")
        with patch("mcp_vault.audit.log_audit",
                   side_effect=lambda *a, **k: appels.append(k)):
            h.appel(token=None)
        motifs = " ".join(str(k.get("detail", "")) for k in appels)
        assert "missing_token" in motifs or "invalid_token" in motifs


# =============================================================================
# 5) L'avertissement de démarrage
# =============================================================================

class TestAvertissementDeDemarrage:
    """Placé dans `create_app()` : c'est le point commun à `main()` et au
    démarrage `uvicorn ...:create_app --factory`. Dans `main()` seul, il serait
    muet sur le second chemin — précisément un déploiement ASGI."""

    def _construire(self, mode, caplog):
        import logging
        from mcp_vault import server
        s = SimpleNamespace(
            admin_bootstrap_key=BOOTSTRAP_KEY, mcp_auth_mode=mode,
            mission_pep_active=mode in ("jwt", "dual-stack"),
        )
        with patch.object(server, "settings", s), \
             patch.object(server, "_install_vault_lifespan", lambda app: None), \
             patch("mcp_vault.openbao.crypto.validate_bootstrap_key",
                   return_value=(True, "")), \
             caplog.at_level(logging.CRITICAL, logger="mcp-vault"):
            try:
                server.create_app()
            except Exception:
                pass  # la construction complète de la stack n'est pas l'objet
        return [r for r in caplog.records
                if r.levelno >= logging.CRITICAL
                and "bearer-anonymous" in r.getMessage()]

    def test_un_seul_critical_par_construction(self, caplog):
        assert len(self._construire("bearer-anonymous", caplog)) == 1

    def test_aucun_avertissement_dans_le_mode_par_defaut(self, caplog):
        assert self._construire("bearer", caplog) == []
