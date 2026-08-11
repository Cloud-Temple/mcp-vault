# -*- coding: utf-8 -*-
"""
Configuration pytest partagée — isolation du harnais de test (issue #64).

## Problème corrigé

`hvac` (client Python d'OpenBao) n'est présent que dans l'image Docker, pas dans le venv
de dev / CI unitaire. Avant #64, `tests/test_pki.py` injectait un faux `hvac` dans
`sys.modules` **au niveau module** (donc au moment de son import). Cet effet de bord
**fuyait vers toute la session** pytest : le succès d'autres tests
(`test_service.py::test_06_permissions`, `test_integration.py::…test_check_access_allowed_space`)
dépendait de **l'ordre de collecte** — verts si `test_pki` était importé avant (faux hvac
présent), rouges sinon (`ModuleNotFoundError: hvac`).

## Correctif

On centralise ici un stub **déterministe** de `hvac`, installé AVANT toute collecte de test,
quel que soit l'ordre. L'injection cachée de `test_pki.py` est retirée. Ce stub :
- ne remplace **jamais** un vrai `hvac` (si installé — cas Docker — on l'utilise) ;
- expose `exceptions.Forbidden` / `.InvalidRequest` / `.InvalidPath` comme de vraies classes d'exception
  (catchables par le code de production, contrairement à un attribut MagicMock).

Ce n'est pas une fixture de complaisance : les tests unitaires ne doivent pas dépendre d'un
binaire OpenBao. Les chemins d'autorisation qui comptent sont testés soit sans toucher `hvac`
(allow-list `allowed_resources`), soit en patchant le seam applicatif `check_vault_owner`
(owner-based). Le vrai `hvac` est exercé par les tests e2e (`test_e2e.py`, image Docker).
"""

import os
import sys
from unittest.mock import MagicMock

# --- src sur sys.path, de façon DÉTERMINISTE (issue #64) ---
# Avant #64, seuls 20 des 26 fichiers de test faisaient `sys.path.insert(.../src)` à leur
# tête ; les 6 autres (dont test_integration.py) dépendaient d'un module tiers collecté
# AVANT eux pour rendre `mcp_vault` importable → `ModuleNotFoundError: mcp_vault` quand on
# les exécutait seuls ou dans un sous-ensemble. Le conftest racine est importé avant toute
# collecte : on garantit ici l'import pour TOUS les tests, quel que soit l'ordre.
_SRC = os.path.join(os.path.dirname(__file__), "..", "src")
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)


def _install_hvac_stub_if_absent():
    """Installe un stub hvac déterministe UNIQUEMENT si le vrai paquet est absent."""
    try:
        import hvac  # noqa: F401 — présent dans Docker : on garde le vrai module
        return
    except ModuleNotFoundError:
        pass

    stub = MagicMock(name="hvac_stub")

    # Vraies classes d'exception (un attribut MagicMock ne serait pas catchable par
    # `except hvac.exceptions.Forbidden`).
    #
    # ISSUE #98 : ces classes étaient des `Exception` NUES, alors que le vrai
    # `hvac.exceptions.VaultError` accepte `errors=[...]` et expose `.errors` —
    # attribut que la production LIT (`vault/secrets.py::_is_cas_conflict`, qui
    # distingue le conflit CAS d'un 400 générique). Deux tests de #92 étaient donc
    # rouges hors Docker sur un `TypeError: InvalidRequest() takes no keyword
    # arguments`, et la couverture du mapping CAS n'était jamais exercée. Un stub
    # qui diverge de la vraie signature ne teste pas le code réel : on reproduit
    # ici le constructeur de `hvac.exceptions.VaultError` à l'identique.
    class _StubVaultError(Exception):
        def __init__(self, message=None, errors=None, method=None, url=None,
                     text=None, json=None):
            if errors:
                message = ", ".join(errors)
            self.errors = errors
            self.method = method
            self.url = url
            self.text = text
            self.json = json
            super().__init__(message)

    stub.exceptions.VaultError = _StubVaultError
    stub.exceptions.Forbidden = type("Forbidden", (_StubVaultError,), {})
    stub.exceptions.InvalidRequest = type("InvalidRequest", (_StubVaultError,), {})
    stub.exceptions.InvalidPath = type("InvalidPath", (_StubVaultError,), {})

    # FAIL-CLOSE (issue #64, reco red team). `hvac.Client(...)` LÈVE au lieu de renvoyer un
    # MagicMock complaisant : sinon un health_check()/check_vault_owner() non patché renverrait
    # un truthy → FAUX VERT (un test « passe » sans OpenBao réel). Les tests qui exercent la
    # couche vault DOIVENT patcher explicitement get_hvac_client()/check_vault_owner() ; à défaut
    # ils échouent bruyamment ICI plutôt que de mentir.
    def _fail_close_client(*_a, **_k):
        raise RuntimeError(
            "hvac est stubbé pour les tests unitaires (issue #64) : patchez explicitement "
            "get_hvac_client() ou check_vault_owner() — aucun OpenBao réel dans ce contexte."
        )
    stub.Client = _fail_close_client
    sys.modules["hvac"] = stub


_install_hvac_stub_if_absent()


# test_cli_all.py est un AGRÉGATEUR : il ré-importe les fonctions de tests/cli/test_*.py pour un
# run standalone (`python tests/test_cli_all.py`). Collecté par pytest, il DUPLIQUE ces tests mais
# SANS la fixture d'enforcement de tests/cli/conftest.py (hors sous-répertoire) → FAUX VERTS
# (issue #64, reco red team : un sabotage passait par ce chemin). Les vrais tests tournent dans
# tests/cli/ (enforcés) ; on exclut donc la collecte pytest de l'agrégateur. Le run standalone
# (n'utilise pas pytest) reste inchangé.
collect_ignore = ["test_cli_all.py"]


# ── Contexte d'identité pour les primitives de wrapping (issue #115) ─────────
# Depuis #115, revoke_wrap/lookup_and_revoke_by_operation_id/status_by_operation_id
# filtrent les entrées du registre par l'identité courante (ContextVar
# current_token_info). Contexte ABSENT (None) = fail-close (rien de visible) —
# JAMAIS traité comme admin. Les tests historiques de primitives, écrits avant
# le scoping, s'exécutent donc sous une identité admin EXPLICITE via ce
# context manager (set/reset garantis, pas de fuite entre tests).
from contextlib import contextmanager


@contextmanager
def auth_context(token_info):
    """Injecte une identité dans current_token_info, reset garanti en sortie."""
    from mcp_vault.auth.context import current_token_info
    ctx_token = current_token_info.set(token_info)
    try:
        yield
    finally:
        current_token_info.reset(ctx_token)


@contextmanager
def admin_auth_context():
    """Identité admin de test (comportement pré-#115 des primitives)."""
    with auth_context({"client_name": "test-admin", "permissions": ["admin"],
                       "allowed_resources": []}):
        yield
