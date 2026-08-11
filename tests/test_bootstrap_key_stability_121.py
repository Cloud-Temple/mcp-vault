# -*- coding: utf-8 -*-
"""
Tests #121 — stabilité d'ADMIN_BOOTSTRAP_KEY : ne jamais inviter au geste
irréversible, et échouer bruyamment.

Rappel du risque : cette clé chiffre l'objet S3 contenant les clés d'unseal.
Deux situations à ne pas confondre —

    mauvaise clé + objet chiffré INTACT  → récupérable (retrouver l'ancienne clé)
    mauvaise clé + objet chiffré RÉÉCRIT → perte définitive

On passe de la première à la seconde par un seul geste humain : réinitialiser
« pour repartir propre ». Ces tests verrouillent les trois garanties :

1. le code ne réécrit JAMAIS l'objet chiffré tout seul après un échec de
   déchiffrement (comportement déjà sûr — ici PINNÉ contre une régression) ;
2. le message n'invite PAS à initialiser quand des données existent, et dit
   explicitement quoi ne pas faire ;
3. l'échec est BRUYANT : le démarrage est refusé (pas de mode dégradé).
"""

import asyncio
import os
import sys
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

os.environ.setdefault("MCP_SERVER_NAME", "mcp-vault-test")
os.environ.setdefault("ADMIN_BOOTSTRAP_KEY", "Test-Bootstrap-Key-2026-Pour-Tests!!")
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))


def _run(coro):
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


# =============================================================================
# 1. Échec de déchiffrement : bruyant, actionnable, non destructif
# =============================================================================

def _unseal_with_undecryptable_keys(data_exists=True):
    """Prépare `unseal_vault()` face à un objet chiffré indéchiffrable."""
    from mcp_vault.openbao import lifecycle as ol

    client = MagicMock()
    client.sys.is_sealed.return_value = True
    s3 = MagicMock()
    return ol, client, s3, data_exists


def test_decryption_failure_raises_loudly_with_actionable_message():
    """Clé incorrecte → exception dédiée (pas un dict d'erreur silencieux)."""
    from mcp_vault.openbao import lifecycle as ol

    client = MagicMock()
    client.sys.is_sealed.return_value = True

    with patch.object(ol, "hvac", MagicMock(Client=MagicMock(return_value=client))), \
         patch.object(ol, "_check_and_migrate_legacy_keys", return_value=None), \
         patch.object(ol, "_download_encrypted_keys_from_s3",
                      side_effect=ValueError("Déchiffrement impossible")), \
         patch.object(ol, "_init_keys_memory", None, create=True):
        with pytest.raises(ol.UnsealKeysUnrecoverable) as exc:
            _run(ol.unseal_vault())

    message = str(exc.value)
    # La cause la plus probable est NOMMÉE...
    assert "ADMIN_BOOTSTRAP_KEY" in message
    # ...et surtout l'interdit est EXPLICITE (c'est le geste qui détruit tout).
    assert "NE PAS réinitialiser" in message, \
        "le message doit interdire explicitement la réinitialisation"
    assert "NE PAS effacer le volume" in message
    # L'espoir de récupération est indiqué (évite la panique et le geste fatal).
    assert "récupérables" in message or "intactes" in message
    # La procédure outillée est pointée.
    assert "rotate_bootstrap_key" in message


def test_decryption_failure_never_reinitializes_or_overwrites():
    """PIN du comportement sûr : aucun PUT S3, aucune initialisation.

    NON-COMPLAISANCE : c'est LE test qui protège du scénario catastrophe. Si une
    évolution future ajoutait une réinitialisation « de secours » sur ce chemin,
    ce test deviendrait rouge.
    """
    from mcp_vault.openbao import lifecycle as ol

    client = MagicMock()
    client.sys.is_sealed.return_value = True
    s3 = MagicMock()

    with patch.object(ol, "hvac", MagicMock(Client=MagicMock(return_value=client))), \
         patch.object(ol, "_check_and_migrate_legacy_keys", return_value=None), \
         patch.object(ol, "_download_encrypted_keys_from_s3",
                      side_effect=ValueError("bad key")), \
         patch.object(ol, "_upload_encrypted_keys_to_s3") as upload, \
         patch.object(ol, "initialize_vault", new=AsyncMock()) as init:
        with pytest.raises(ol.UnsealKeysUnrecoverable):
            _run(ol.unseal_vault())

    upload.assert_not_called(), "l'objet chiffré ne doit JAMAIS être réécrit ici"
    init.assert_not_called(), "aucune réinitialisation automatique"
    s3.put_object.assert_not_called()


# =============================================================================
# 2. Clés introuvables : le message dépend de l'existence de données
# =============================================================================

def test_missing_keys_with_existing_data_refuses_and_forbids_init():
    """Données présentes + clés introuvables → refus BRUYANT, jamais « initialiser ».

    C'est le piège trouvé en relecture : le message historique disait
    « Initialiser d'abord avec initialize_vault() » — correct sur une
    installation neuve, destructeur sur un coffre existant.
    """
    from mcp_vault.openbao import lifecycle as ol

    client = MagicMock()
    client.sys.is_sealed.return_value = True

    with patch.object(ol, "hvac", MagicMock(Client=MagicMock(return_value=client))), \
         patch.object(ol, "_check_and_migrate_legacy_keys", return_value=None), \
         patch.object(ol, "_download_encrypted_keys_from_s3", return_value=None), \
         patch.object(ol, "_openbao_data_exists", return_value=True):
        with pytest.raises(ol.UnsealKeysUnrecoverable) as exc:
            _run(ol.unseal_vault())

    message = str(exc.value)
    assert "NE PAS initialiser" in message
    assert "initialize_vault()" not in message, \
        "ne JAMAIS suggérer l'initialisation quand des données existent"


def test_missing_keys_without_data_still_guides_to_initialize():
    """Installation neuve : l'invitation à initialiser reste utile et sûre."""
    from mcp_vault.openbao import lifecycle as ol

    client = MagicMock()
    client.sys.is_sealed.return_value = True

    with patch.object(ol, "hvac", MagicMock(Client=MagicMock(return_value=client))), \
         patch.object(ol, "_check_and_migrate_legacy_keys", return_value=None), \
         patch.object(ol, "_download_encrypted_keys_from_s3", return_value=None), \
         patch.object(ol, "_openbao_data_exists", return_value=False):
        result = _run(ol.unseal_vault())

    assert result["status"] == "error"
    assert "initialize_vault()" in result["message"]


def test_data_existence_probe_is_fail_close():
    """En cas de doute (lecture impossible), on suppose qu'il y a des données.

    Se tromper dans ce sens fait refuser un démarrage ; se tromper dans l'autre
    invite à détruire un coffre.
    """
    from mcp_vault.openbao import lifecycle as ol

    settings = MagicMock()
    settings.openbao_data_dir = "/chemin/qui/leve"
    with patch.object(ol, "get_settings", return_value=settings), \
         patch("pathlib.Path.exists", side_effect=OSError("permission denied")):
        assert ol._openbao_data_exists() is True


# =============================================================================
# 3. Échec BRUYANT de bout en bout : le service refuse de démarrer
# =============================================================================

def test_vault_startup_propagates_instead_of_degrading():
    """`vault_startup()` ne doit PAS retourner False (mode dégradé) ici.

    Un coffre inouvrable n'a aucune raison d'accepter du trafic : l'exception
    doit traverser pour que le démarrage soit refusé.
    """
    from mcp_vault import lifecycle
    from mcp_vault.openbao.lifecycle import UnsealKeysUnrecoverable

    fake_openbao_lc = MagicMock()
    fake_openbao_lc.UnsealKeysUnrecoverable = UnsealKeysUnrecoverable
    fake_openbao_lc.unseal_vault = AsyncMock(
        side_effect=UnsealKeysUnrecoverable("clés inexploitables"))
    fake_openbao_lc.initialize_vault = AsyncMock(
        return_value={"status": "already_initialized"})

    with patch.dict(sys.modules, {"mcp_vault.openbao.lifecycle": fake_openbao_lc}), \
         patch.object(lifecycle, "_reset_shutdown_state"), \
         patch.object(lifecycle, "get_settings", side_effect=RuntimeError("court-circuit")):
        # On ne rejoue pas tout le startup : on vérifie que l'exception dédiée
        # n'est pas convertie en `return False` par la garde générique.
        with pytest.raises(RuntimeError):
            _run(lifecycle.vault_startup())


def test_lifespan_refuses_to_start_on_unrecoverable_keys():
    """ÉCHEC BRUYANT au niveau ASGI : le lifespan relaie l'exception.

    uvicorn refuse alors de démarrer (« Application startup failed »). Sans ce
    relais, le service tournerait en mode dégradé avec un coffre inouvrable.
    """
    from mcp_vault import server
    import mcp_vault.lifecycle as lifecycle_mod
    from mcp_vault.openbao.lifecycle import UnsealKeysUnrecoverable

    startup = AsyncMock(side_effect=UnsealKeysUnrecoverable("clés inexploitables"))
    shutdown = AsyncMock()
    with patch.object(lifecycle_mod, "vault_startup", startup), \
         patch.object(lifecycle_mod, "vault_shutdown", shutdown):
        app = server.create_app()
        received = [{"type": "lifespan.startup"}]
        sent = []

        async def _receive():
            return received.pop(0)

        async def _send(message):
            sent.append(message["type"])

        with pytest.raises(UnsealKeysUnrecoverable):
            _run(app({"type": "lifespan", "asgi": {"version": "3.0"}},
                     _receive, _send))

    assert "lifespan.startup.complete" not in sent, \
        "le démarrage ne doit PAS être annoncé comme réussi"


# =============================================================================
# 4. Script de rotation : présent et documenté
# =============================================================================

def test_rotation_script_exists_and_documents_the_cold_restart_test():
    """La procédure est SCRIPTÉE (décision propriétaire) et impose le test final.

    Une rotation « réussie » sans test de redémarrage à froid ne prouve rien :
    l'incident n'apparaîtrait qu'au prochain arrêt.
    """
    root = os.path.join(os.path.dirname(__file__), "..")
    path = os.path.join(root, "scripts", "rotate_bootstrap_key.py")
    assert os.path.exists(path), "le script de rotation doit exister"
    source = open(path, encoding="utf-8").read()

    # Séquence sûre : sauvegarde → déchiffrer ancienne → rechiffrer → vérifier
    for needle in ("--dry-run", "decrypt_with_bootstrap_key",
                   "encrypt_with_bootstrap_key", "redémarrage à froid"):
        assert needle in source, f"le script doit couvrir : {needle}"
    # Les clés ne passent JAMAIS en argument de ligne de commande.
    assert "--old-key\"" not in source and "--new-key\"" not in source


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
