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
import json
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
         patch.object(ol, "_in_memory_keys", None):
        with pytest.raises(ol.UnsealKeysUnrecoverable) as exc:
            _run(ol.unseal_vault())

    message = str(exc.value)
    # La cause la plus probable est NOMMÉE...
    assert "ADMIN_BOOTSTRAP_KEY" in message
    # ...sans être présentée comme la SEULE (l'objet peut aussi être corrompu —
    # dans ce cas restaurer la clé ne suffit pas ; ne pas promettre l'inverse).
    assert "corrompu" in message
    # ...et surtout l'interdit est EXPLICITE (c'est le geste qui détruit tout).
    assert "NE PAS réinitialiser" in message, \
        "le message doit interdire explicitement la réinitialisation"
    assert "NE PAS effacer le volume" in message
    # Fait rassurant EXACT : le file backend n'a pas été touché par cet échec.
    assert "file backend n'a PAS été modifié" in message
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

@pytest.fixture
def _isolated_store_singletons():
    """Isole les singletons de stores autour d'un VRAI `vault_startup()`.

    `vault_startup()` réinitialise les singletons process-wide (TokenStore,
    PolicyStore, MissionBindingStore, WrapRegistry, AuditStore). Sans
    restauration, exercer le vrai startup dans un test contamine toute la
    session pytest — c'est précisément la classe de faux verts/faux rouges
    fermée par l'issue #64. On sauvegarde et on restaure.
    """
    import mcp_vault.audit as au
    import mcp_vault.auth.jwt_validator as jv
    import mcp_vault.auth.mission_bindings as mb
    import mcp_vault.auth.policies as pol
    import mcp_vault.auth.token_store as ts
    import mcp_vault.vault.wrapping as wr

    saved = (ts._token_store, pol._policy_store, mb._mission_binding_store,
             wr._wrap_registry, au._audit_store, jv._validator)
    try:
        yield
    finally:
        (ts._token_store, pol._policy_store, mb._mission_binding_store,
         wr._wrap_registry, au._audit_store, jv._validator) = saved


def test_vault_startup_propagates_instead_of_degrading(_isolated_store_singletons):
    """`vault_startup()` ne doit PAS retourner False (mode dégradé) ici.

    NON-COMPLAISANCE (revue du diff) : on exerce le VRAI `vault_startup()`
    jusqu'à l'appel d'`unseal_vault` mocké — une version antérieure de ce test
    court-circuitait avant, et serait donc restée verte si l'exception était de
    nouveau absorbée par la garde générique `except Exception: return False`.
    """
    import tempfile

    import mcp_vault.lifecycle as lifecycle
    import mcp_vault.openbao.lifecycle as ol
    import mcp_vault.openbao.manager as om
    import mcp_vault.s3_sync as s3_sync

    reached = {"unseal": False}

    async def _unseal():
        reached["unseal"] = True
        raise ol.UnsealKeysUnrecoverable("clés inexploitables")

    with tempfile.TemporaryDirectory() as tmp:
        # Settings SANS S3 : les initialisations de stores sont traversées mais
        # ne tentent aucun appel réseau (rapide et déterministe).
        settings = MagicMock()
        settings.admin_bootstrap_key = "Test-Bootstrap-Key-2026-Pour-Tests!!"
        settings.s3_endpoint_url = ""
        settings.s3_bucket_name = ""
        settings.openbao_data_dir = tmp
        settings.mission_jwks_url = ""
        settings.resolved_mission_aud = ""
        settings.mcp_auth_mode = "bearer"

        with patch.object(lifecycle, "get_settings", return_value=settings), \
             patch.object(ol, "unseal_vault", new=_unseal), \
             patch.object(ol, "initialize_vault",
                          new=AsyncMock(return_value={"status": "already_initialized"})), \
             patch.object(om, "start_openbao", new=AsyncMock(return_value=True)), \
             patch.object(s3_sync, "download_from_s3",
                          new=AsyncMock(return_value=s3_sync.RestoreResult.CONFIRMED_ABSENT)), \
             patch.object(lifecycle, "_reset_shutdown_state"):
            with pytest.raises(ol.UnsealKeysUnrecoverable):
                _run(lifecycle.vault_startup())

    assert reached["unseal"], \
        "le test doit atteindre unseal_vault — sinon il ne prouve rien"


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

# =============================================================================
# 4. Script de rotation : garanties EXERCÉES contre un faux S3
# =============================================================================
# NON-COMPLAISANCE (revue du diff) : chercher des chaînes dans le source ne
# prouve rien — une inversion des PUT, un --dry-run qui écrit, une absence de
# copie de retour arrière ou une relecture non vérifiée passeraient. Ces tests
# exécutent la vraie fonction `rotate()`.

_OLD_KEY = "Ancienne-Cle-Bootstrap-2026-Pour-Tests-121!!"
_NEW_KEY = "Nouvelle-Cle-Bootstrap-2026-Pour-Tests-121!!"


def _import_rotate():
    import importlib.util
    root = os.path.join(os.path.dirname(__file__), "..")
    path = os.path.join(root, "scripts", "rotate_bootstrap_key.py")
    spec = importlib.util.spec_from_file_location("rotate_bootstrap_key", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class _FakeS3:
    """Faux S3 minimal : mémorise l'ordre des écritures et permet d'injecter
    une modification concurrente ou un échec de PUT."""

    class _Shape:
        def __init__(self, members):
            self.members = members

    class _OpModel:
        def __init__(self, members):
            self.input_shape = _FakeS3._Shape(members)

    class _ServiceModel:
        def __init__(self, members):
            self._members = members

        def operation_model(self, name):
            return _FakeS3._OpModel(self._members)

    class _Meta:
        def __init__(self, members):
            self.service_model = _FakeS3._ServiceModel(members)

    def __init__(self, objects, fail_on_key=None, mutate_before_put=None,
                 mutate_in_toctou_window=None, etags=True,
                 supports_ifmatch=True):
        self.objects = dict(objects)          # key -> contenu str
        self.puts = []                        # ordre des écritures
        self.gets = 0
        self.fail_on_key = fail_on_key
        self.mutate_before_put = mutate_before_put
        # Modification survenant APRÈS la relecture de contrôle, dans la fenêtre
        # que seule une écriture conditionnelle (If-Match) peut fermer.
        self.mutate_in_toctou_window = mutate_in_toctou_window
        self.etags = etags
        # Capacité SDK : `PutObject.IfMatch` exposé ou non (issue #121, revue).
        members = {"Bucket": None, "Key": None, "Body": None}
        if supports_ifmatch:
            members["IfMatch"] = None
        self.meta = _FakeS3._Meta(members)

    def _etag(self, key):
        return f'"{hash(self.objects[key])}"' if self.etags else None

    def get_object(self, Bucket=None, Key=None):
        self.gets += 1
        # Simule une écriture concurrente entre deux lectures.
        if self.mutate_before_put and self.gets >= 2:
            self.objects[Key] = self.mutate_before_put
            self.mutate_before_put = None

        class _Body:
            def __init__(self, data):
                self._data = data

            def read(self):
                return self._data.encode("ascii")

        if Key not in self.objects:
            raise RuntimeError("NoSuchKey")
        return {"Body": _Body(self.objects[Key]), "ETag": self._etag(Key)}

    def put_object(self, Bucket=None, Key=None, Body=None, IfMatch=None, **kw):
        if self.fail_on_key == Key:
            raise RuntimeError("PUT refusé (test)")
        # Écriture concurrente glissée dans la fenêtre contrôle → écriture.
        if IfMatch and self.mutate_in_toctou_window:
            self.objects[Key] = self.mutate_in_toctou_window
            self.mutate_in_toctou_window = None
        if IfMatch is not None and Key in self.objects and IfMatch != self._etag(Key):
            from botocore.exceptions import ClientError
            raise ClientError(
                {"Error": {"Code": "PreconditionFailed", "Message": "etag mismatch"},
                 "ResponseMetadata": {"HTTPStatusCode": 412}},
                "PutObject")
        self.puts.append(Key)
        self.objects[Key] = Body.decode("ascii")


def _encrypted_payload(key):
    from mcp_vault.openbao.crypto import encrypt_with_bootstrap_key
    return encrypt_with_bootstrap_key(
        json.dumps({"keys": ["unseal-key-1"], "root_token": "s.root"}), key)


def test_rotation_dry_run_writes_absolutely_nothing(tmp_path):
    mod = _import_rotate()
    s3 = _FakeS3({mod._S3_INIT_KEY: _encrypted_payload(_OLD_KEY)})
    backup = str(tmp_path / "backup.bak")

    result = mod.rotate(s3, "bucket", _OLD_KEY, _NEW_KEY,
                        backup_path=backup, dry_run=True, stamp="STAMP")

    assert s3.puts == [], "un dry-run ne doit RIEN écrire sur S3"
    assert not os.path.exists(backup), "un dry-run ne doit RIEN écrire sur disque"
    assert result["rollback_key"] is None


def test_rotation_writes_rollback_copy_before_current_object(tmp_path):
    """ORDRE CRITIQUE : la copie de retour arrière AVANT l'objet courant."""
    mod = _import_rotate()
    original = _encrypted_payload(_OLD_KEY)
    s3 = _FakeS3({mod._S3_INIT_KEY: original})

    result = mod.rotate(s3, "bucket", _OLD_KEY, _NEW_KEY,
                        backup_path=str(tmp_path / "b.bak"),
                        dry_run=False, stamp="STAMP")

    assert s3.puts == [f"{mod._S3_INIT_KEY}.STAMP.bak", mod._S3_INIT_KEY], \
        f"ordre des écritures incorrect : {s3.puts}"
    # La copie contient bien l'ANCIEN contenu, l'objet courant le NOUVEAU.
    assert s3.objects[result["rollback_key"]] == original
    from mcp_vault.openbao.crypto import decrypt_with_bootstrap_key
    assert decrypt_with_bootstrap_key(s3.objects[mod._S3_INIT_KEY], _NEW_KEY)


def test_rotation_aborts_on_wrong_old_key_without_touching_s3(tmp_path):
    mod = _import_rotate()
    s3 = _FakeS3({mod._S3_INIT_KEY: _encrypted_payload(_OLD_KEY)})

    with pytest.raises(mod.RotationAborted) as exc:
        mod.rotate(s3, "bucket", "Mauvaise-Cle-2026-Pour-Tests-121!!!!", _NEW_KEY,
                   backup_path=str(tmp_path / "b.bak"), dry_run=False, stamp="S")

    assert "rien n'a été modifié sur S3" in str(exc.value)
    assert s3.puts == [], "aucune écriture ne doit avoir eu lieu"


def test_rotation_aborts_on_concurrent_modification(tmp_path):
    """CONFLIT : si l'objet change entre la lecture et l'écriture, on abandonne.

    Sinon on écraserait une version plus récente (initialisation, migration,
    autre rotation, instance encore vivante) dont le volume peut dépendre.
    """
    mod = _import_rotate()
    original = _encrypted_payload(_OLD_KEY)
    concurrent = _encrypted_payload(_OLD_KEY)  # autre ciphertext (nonce/sel neufs)
    s3 = _FakeS3({mod._S3_INIT_KEY: original}, mutate_before_put=concurrent)

    with pytest.raises(mod.RotationAborted) as exc:
        mod.rotate(s3, "bucket", _OLD_KEY, _NEW_KEY,
                   backup_path=str(tmp_path / "b.bak"), dry_run=False, stamp="S")

    assert "CONFLIT" in str(exc.value)
    # La copie de retour arrière a pu être écrite, mais JAMAIS l'objet courant.
    assert mod._S3_INIT_KEY not in s3.puts, \
        "l'objet courant ne doit pas être écrasé après un changement concurrent"
    assert s3.objects[mod._S3_INIT_KEY] == concurrent, \
        "la version concurrente doit rester intacte"


def test_rotation_aborts_if_rollback_copy_cannot_be_written(tmp_path):
    """Pas de filet de retour arrière → on ne touche pas à l'objet courant."""
    mod = _import_rotate()
    s3 = _FakeS3({mod._S3_INIT_KEY: _encrypted_payload(_OLD_KEY)},
                 fail_on_key=f"{mod._S3_INIT_KEY}.S.bak")

    with pytest.raises(mod.RotationAborted) as exc:
        mod.rotate(s3, "bucket", _OLD_KEY, _NEW_KEY,
                   backup_path=str(tmp_path / "b.bak"), dry_run=False, stamp="S")

    assert "AVANT modification de l'objet courant" in str(exc.value)
    assert s3.puts == []


def test_rotation_reports_restore_path_if_current_put_fails(tmp_path):
    """Échec du PUT courant → message pointant la copie de retour arrière."""
    mod = _import_rotate()
    s3 = _FakeS3({mod._S3_INIT_KEY: _encrypted_payload(_OLD_KEY)},
                 fail_on_key=mod._S3_INIT_KEY)

    with pytest.raises(mod.RotationAborted) as exc:
        mod.rotate(s3, "bucket", _OLD_KEY, _NEW_KEY,
                   backup_path=str(tmp_path / "b.bak"), dry_run=False, stamp="S")

    message = str(exc.value)
    assert ".S.bak" in message, "le message doit pointer la copie de retour arrière"
    assert "NE PAS réinitialiser" in message


def test_rotation_conditional_put_closes_the_toctou_window(tmp_path):
    """Une écriture concurrente DANS la fenêtre contrôle → écriture doit échouer.

    La relecture de contrôle ne suffit pas : seule l'écriture conditionnelle
    (If-Match) rend la vérification atomique côté stockage.
    """
    mod = _import_rotate()
    original = _encrypted_payload(_OLD_KEY)
    concurrent = _encrypted_payload(_OLD_KEY)
    s3 = _FakeS3({mod._S3_INIT_KEY: original},
                 mutate_in_toctou_window=concurrent)

    with pytest.raises(mod.RotationAborted) as exc:
        mod.rotate(s3, "bucket", _OLD_KEY, _NEW_KEY,
                   backup_path=str(tmp_path / "b.bak"), dry_run=False, stamp="S")

    assert "CONFLIT" in str(exc.value)
    assert mod._S3_INIT_KEY not in s3.puts, \
        "l'écriture conditionnelle aurait dû être refusée (412)"
    assert s3.objects[mod._S3_INIT_KEY] == concurrent, \
        "la version concurrente doit rester intacte"


def test_rotation_refuses_when_storage_gives_no_etag(tmp_path):
    """Sans ETag, l'écriture conditionnelle est impossible → refus explicite.

    Mieux vaut refuser que promettre une garantie qu'on ne peut pas tenir.
    """
    mod = _import_rotate()
    s3 = _FakeS3({mod._S3_INIT_KEY: _encrypted_payload(_OLD_KEY)}, etags=False)

    with pytest.raises(mod.RotationAborted) as exc:
        mod.rotate(s3, "bucket", _OLD_KEY, _NEW_KEY,
                   backup_path=str(tmp_path / "b.bak"), dry_run=False, stamp="S")

    assert "ETag" in str(exc.value) and "refusée" in str(exc.value)
    assert s3.puts == []


def test_rotation_verifies_by_rereading_from_storage(tmp_path):
    """La vérification finale doit RELIRE le stockage, pas se croire sur parole.

    NON-COMPLAISANCE : on fait diverger l'objet stocké au moment de la relecture
    finale ; si le script ne relisait pas, il conclurait à tort au succès.
    """
    mod = _import_rotate()
    s3 = _FakeS3({mod._S3_INIT_KEY: _encrypted_payload(_OLD_KEY)})

    original_get = s3.get_object
    state = {"puts_seen": False}

    def _get_with_corruption(Bucket=None, Key=None):
        # Après l'écriture de l'objet courant, le stockage renvoie autre chose.
        if state["puts_seen"] and Key == mod._S3_INIT_KEY:
            # Contenu DIFFÉRENT (autres clés d'unseal), chiffré avec la
            # nouvelle clé : déchiffrable, mais ≠ de l'original.
            from mcp_vault.openbao.crypto import encrypt_with_bootstrap_key
            s3.objects[Key] = encrypt_with_bootstrap_key(
                json.dumps({"keys": ["AUTRE-unseal"], "root_token": "s.autre"}),
                _NEW_KEY)
        return original_get(Bucket=Bucket, Key=Key)

    original_put = s3.put_object

    def _put(Bucket=None, Key=None, Body=None, **kw):
        original_put(Bucket=Bucket, Key=Key, Body=Body, **kw)
        if Key == mod._S3_INIT_KEY:
            state["puts_seen"] = True

    s3.get_object = _get_with_corruption
    s3.put_object = _put

    with pytest.raises(mod.RotationAborted) as exc:
        mod.rotate(s3, "bucket", _OLD_KEY, _NEW_KEY,
                   backup_path=str(tmp_path / "b.bak"), dry_run=False, stamp="S")

    assert "RESTAURER" in str(exc.value), \
        "une relecture incohérente doit exiger la restauration"


@pytest.mark.parametrize("artefact", [
    ".gitkeep", ".DS_Store", ".s3_sync_restore_staging",
])
def test_data_probe_ignores_known_artefacts(artefact, tmp_path):
    """Un artefact seul n'est PAS une donnée de coffre (#121, revue).

    Sinon un dossier fraîchement monté ferait refuser un démarrage légitime.
    """
    from mcp_vault.openbao import lifecycle as ol

    (tmp_path / artefact).touch()
    settings = MagicMock()
    settings.openbao_data_dir = str(tmp_path)
    with patch.object(ol, "get_settings", return_value=settings):
        assert ol._openbao_data_exists() is False, \
            f"{artefact} ne doit pas compter comme une donnée"
        # Un vrai fichier de données, lui, compte.
        (tmp_path / "core").mkdir()
        assert ol._openbao_data_exists() is True


def test_rotation_refuses_when_sdk_lacks_conditional_write(tmp_path):
    """SDK sans `PutObject.IfMatch` → refus explicite AVANT toute écriture.

    Le contrat de dépendances autorisait des versions de boto3 sans ce
    paramètre : l'appel aurait échoué à la validation botocore, après avoir
    écrit la copie de retour arrière. On refuse en amont, avec un message
    actionnable.
    """
    mod = _import_rotate()
    s3 = _FakeS3({mod._S3_INIT_KEY: _encrypted_payload(_OLD_KEY)},
                 supports_ifmatch=False)

    with pytest.raises(mod.RotationAborted) as exc:
        mod.rotate(s3, "bucket", _OLD_KEY, _NEW_KEY,
                   backup_path=str(tmp_path / "b.bak"), dry_run=False, stamp="S")

    assert "IfMatch" in str(exc.value) and "boto3" in str(exc.value)
    assert s3.puts == [], "aucune écriture avant de constater l'incapacité"


def test_concurrent_deletion_is_classified_as_a_conflict():
    """Suppression concurrente (404) → traitée comme un CONFLIT, pas une erreur floue."""
    from botocore.exceptions import ClientError

    mod = _import_rotate()
    err = ClientError(
        {"Error": {"Code": "NoSuchKey", "Message": "absent"},
         "ResponseMetadata": {"HTTPStatusCode": 404}}, "PutObject")
    assert mod._is_conflict(err) is True
    # Une erreur sans rapport ne doit PAS être classée conflit (anti-faux positif).
    other = ClientError(
        {"Error": {"Code": "AccessDenied", "Message": "nope"},
         "ResponseMetadata": {"HTTPStatusCode": 403}}, "PutObject")
    assert mod._is_conflict(other) is False


def test_requirements_floor_guarantees_conditional_write():
    """Le plancher boto3 doit exposer `PutObject.IfMatch` (issue #121, revue).

    Vérifié sur le SDK réellement installé : si le service model ne l'exposait
    pas, le script refuserait toute rotation — autant le savoir ici.
    """
    import boto3

    client = boto3.client("s3", region_name="us-east-1",
                          aws_access_key_id="x", aws_secret_access_key="y")
    members = client.meta.service_model.operation_model("PutObject").input_shape.members
    assert "IfMatch" in members, (
        f"boto3 {boto3.__version__} n'expose pas PutObject.IfMatch — "
        "relever le plancher dans requirements.txt")


def test_rotation_script_documents_exclusive_execution_and_cold_restart():
    """Garanties documentaires : exécution exclusive et test de redémarrage."""
    root = os.path.join(os.path.dirname(__file__), "..")
    source = open(os.path.join(root, "scripts", "rotate_bootstrap_key.py"),
                  encoding="utf-8").read()
    assert "EXCLUSIVE" in source, "l'exécution exclusive doit être imposée"
    assert "redémarrage à froid" in source
    # Les clés ne passent JAMAIS en argument de ligne de commande.
    assert '"--old-key"' not in source and '"--new-key"' not in source


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
