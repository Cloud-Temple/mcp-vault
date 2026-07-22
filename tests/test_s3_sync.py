# -*- coding: utf-8 -*-
"""
Tests de `s3_sync.py` — PUT S3 conditionnel à un changement réel de l'état source
(incident versions S3, 2026-07).

## Contexte de l'incident

Le bucket de production a le versioning S3 activé, sans lifecycle. Le sync
périodique faisait un PUT inconditionnel toutes les 60s → une version S3 par
cycle, 6000+ versions et 600+ Mo accumulés en quelques jours, même sans aucune
écriture OpenBao entre deux cycles.

## Propriétés de sûreté prouvées ici (non-complaisant — pas de couverture pour la
## couverture)

- **PUT évité seulement sur preuve positive d'égalité** : deux cycles consécutifs
  sans modification ⇒ exactement 1 PUT (le premier établit la référence). Toute
  modification (octet changé, fichier ajouté, fichier supprimé) déclenche un
  nouveau PUT.
- **Empreinte construite dans la MÊME passe que l'archive** (`_snapshot_and_archive`)
  — élimine par construction la fenêtre TOCTOU identifiée en revue de plan (une
  empreinte lue AVANT l'archive pouvait diverger du contenu réellement envoyé).
  Il n'existe plus de lecture séparée à faire diverger : ces tests portent donc
  sur la SENSIBILITÉ de l'empreinte (Q1 de la revue), pas sur la fenêtre de course
  (structurellement fermée).
- **Rejeu sur échec** : un PUT qui échoue n'avance jamais la référence — le cycle
  suivant retente un PUT réel (pas un skip).
- **État "incertain" après échec ambigu** (ex. timeout après envoi, où l'objet a
  pu être écrit côté S3 malgré l'exception locale) : AUCUN skip tant qu'un PUT
  n'a pas explicitement réussi ensuite, même si le contenu local redevient
  identique à l'ancienne référence.
- **Restauration à 3 états** : absence CONFIRMÉE par S3 (404/NoSuchKey) autorise
  une init à vide ; toute autre erreur (réseau, archive corrompue) est un échec
  AMBIGU qui ne doit jamais être traité comme une absence.
- **Aucun secret / clé S3 / chemin interne dans les logs**, y compris dans les
  messages d'exception (jamais `str(e)`, seulement `type(e).__name__`).
- **Le vrai point d'entrée périodique** (`_periodic_sync_tick`, câblé dans
  `start_periodic_sync`) est celui qui active la garde — pas seulement
  `upload_to_s3()` appelé directement dans un test isolé.
- **Marqueur durable de restauration incomplète** : la promotion par
  renommages individuels n'est PAS transactionnelle (un `rename()` est
  atomique unitairement, la BOUCLE ne l'est pas). Un crash ou une erreur I/O
  au milieu de la promotion laisse le marqueur `_RESTORE_MARKER_FILENAME` en
  place — il n'est retiré QUE sur une promotion intégralement réussie ou une
  absence confirmée (état terminal légitime).

HORS SCOPE explicite (documenté, pas fermé par ce fix) : la race d'écriture
multi-instance générale sur la clé S3 (dernier writer gagne, cf. #51/#13) — un
seul processus mcp-vault par préfixe S3 est supposé, comme pour PolicyStore/
TokenStore.

Aucune dépendance réseau : le client S3 est mocké (MagicMock), comme dans
`test_policy_store_availability.py`. `botocore.exceptions.ClientError` réel est
utilisé pour les cas de restauration (pas de simulation approximative par chaîne).
"""

import asyncio
import io
import os
import sys
import tarfile
import time
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

# Convention du projet : mcp_vault vit dans src/ (pas d'install du package)
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from mcp_vault import s3_sync
from mcp_vault.s3_sync import RestoreResult


# =============================================================================
# Fixtures & helpers
# =============================================================================

@pytest.fixture(autouse=True)
def _reset_module_state():
    """
    L'état de détection de changement (`_last_uploaded_fingerprint`,
    `_s3_state_uncertain`, `_last_sync_time`) est un singleton module — comme les
    clients S3 (`s3_client.reset_clients()`). Sans ce reset, l'ordre de collecte
    pytest changerait le résultat des tests (le bug exact que le conftest racine
    a déjà corrigé pour hvac, cf. issue #64) : on l'applique ici aussi, avant ET
    après chaque test.
    """
    s3_sync._reset_sync_state_for_tests()
    yield
    s3_sync._reset_sync_state_for_tests()


def _settings(data_dir):
    return SimpleNamespace(
        openbao_data_dir=str(data_dir),
        s3_bucket_name="test-bucket",
        vault_s3_prefix="_storage",
        vault_s3_sync_interval=60,
        s3_endpoint_url="http://localhost:0",
        s3_region_name="fr1",
    )


class _Body:
    def __init__(self, data: bytes):
        self._data = data

    def read(self) -> bytes:
        return self._data


def _fake_client(put_side_effect=None, get_return: bytes = None, get_side_effect=None):
    """MagicMock imitant le client boto3 SigV2 (put_object/get_object)."""
    client = MagicMock()
    if put_side_effect is not None:
        client.put_object.side_effect = put_side_effect
    else:
        client.put_object.return_value = {}
    if get_side_effect is not None:
        client.get_object.side_effect = get_side_effect
    elif get_return is not None:
        client.get_object.return_value = {"Body": _Body(get_return)}
    return client


def _client_error(code="NoSuchKey", status=404):
    """Vrai botocore ClientError — la détection d'absence ne se fie plus à str(e)."""
    from botocore.exceptions import ClientError
    return ClientError(
        {"Error": {"Code": code}, "ResponseMetadata": {"HTTPStatusCode": status}},
        "GetObject",
    )


def _patch_env(monkeypatch, data_dir, client):
    monkeypatch.setattr(s3_sync, "get_settings", lambda: _settings(data_dir))
    monkeypatch.setattr(s3_sync, "get_s3_data_client", lambda: client)


def _write(data_dir, rel_path, content: bytes):
    p = data_dir / rel_path
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(content)


def _valid_tar_gz(files: dict) -> bytes:
    """Construit un tar.gz minimal valide (pour les tests de restauration)."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for name, content in files.items():
            info = tarfile.TarInfo(name=name)
            info.size = len(content)
            tar.addfile(info, io.BytesIO(content))
    return buf.getvalue()


def _run(coro):
    return asyncio.run(coro)


# =============================================================================
# 1) Skip sur état inchangé — exactement 1 PUT sur 2 cycles (le coeur du fix)
# =============================================================================

class TestSkipOnUnchanged:
    def test_two_ticks_no_change_exactly_one_put(self, tmp_path, monkeypatch):
        """Deux cycles périodiques sans modification ⇒ exactement 1 PUT (le 1er
        établit la référence ; le 2e la trouve inchangée et saute)."""
        _write(tmp_path, "core/data.db", b"contenu-openbao-v1")
        client = _fake_client()
        _patch_env(monkeypatch, tmp_path, client)

        r1 = _run(s3_sync._periodic_sync_tick())
        r2 = _run(s3_sync._periodic_sync_tick())

        assert r1 is True and r2 is True
        assert client.put_object.call_count == 1, (
            "2e cycle sans modification : le PUT doit être SAUTÉ, pas rejoué "
            "(c'est exactement l'incident : sans la garde, ce compteur vaut 2)"
        )

    def test_sabotage_periodic_call_site_must_pass_skip_flag(self, tmp_path, monkeypatch):
        """
        SABOTAGE (bloquant #6 de la revue) : ce test ne porte PAS sur la logique
        de skip elle-même, mais sur le VRAI point d'entrée périodique. Il devient
        RED si `_periodic_sync_tick` (ou son câblage dans `_sync_loop`) oublie de
        passer `skip_if_unchanged=True` — un test qui n'appellerait que
        `upload_to_s3(skip_if_unchanged=True)` directement resterait GREEN même si
        la boucle réelle avait régressé vers l'appel sans argument.
        """
        fake_upload = AsyncMock(return_value=True)
        monkeypatch.setattr(s3_sync, "upload_to_s3", fake_upload)

        _run(s3_sync._periodic_sync_tick())

        fake_upload.assert_awaited_once_with(skip_if_unchanged=True)

    def test_background_loop_actually_invokes_periodic_tick(self, tmp_path, monkeypatch):
        """Câblage réel de `start_periodic_sync()` : la tâche de fond appelle bien
        `_periodic_sync_tick` (pas `upload_to_s3` directement) — ferme le doute
        "le test unitaire prouve la fonction, pas la boucle qui tourne en prod"."""
        tick = AsyncMock(return_value=True)
        monkeypatch.setattr(s3_sync, "_periodic_sync_tick", tick)
        monkeypatch.setattr(
            s3_sync, "get_settings",
            lambda: SimpleNamespace(vault_s3_sync_interval=0.02),
        )

        async def _scenario():
            await s3_sync.start_periodic_sync()
            await asyncio.sleep(0.08)  # borné, court — pas une boucle de charge
            await s3_sync.stop_periodic_sync()

        _run(_scenario())
        assert tick.await_count >= 1


# =============================================================================
# 2) Chaque type de modification déclenche exactement 1 PUT
# =============================================================================

class TestChangeDetection:
    def test_one_byte_modification_triggers_put(self, tmp_path, monkeypatch):
        _write(tmp_path, "core/data.db", b"contenu-openbao-v1")
        client = _fake_client()
        _patch_env(monkeypatch, tmp_path, client)
        _run(s3_sync._periodic_sync_tick())  # établit la référence
        assert client.put_object.call_count == 1

        _write(tmp_path, "core/data.db", b"contenu-openbao-v2")  # 1 octet différent, même taille
        _run(s3_sync._periodic_sync_tick())
        assert client.put_object.call_count == 2, "1 octet modifié doit déclencher un PUT"

    def test_file_creation_triggers_put(self, tmp_path, monkeypatch):
        _write(tmp_path, "core/data.db", b"contenu-openbao")
        client = _fake_client()
        _patch_env(monkeypatch, tmp_path, client)
        _run(s3_sync._periodic_sync_tick())
        assert client.put_object.call_count == 1

        _write(tmp_path, "core/nouveau.db", b"nouveau-fichier")
        _run(s3_sync._periodic_sync_tick())
        assert client.put_object.call_count == 2, "un fichier ajouté doit déclencher un PUT"

    def test_file_deletion_triggers_put(self, tmp_path, monkeypatch):
        _write(tmp_path, "core/data.db", b"contenu-openbao")
        _write(tmp_path, "core/ephemere.db", b"sera-supprime")
        client = _fake_client()
        _patch_env(monkeypatch, tmp_path, client)
        _run(s3_sync._periodic_sync_tick())
        assert client.put_object.call_count == 1

        (tmp_path / "core" / "ephemere.db").unlink()
        _run(s3_sync._periodic_sync_tick())
        assert client.put_object.call_count == 2, "un fichier supprimé doit déclencher un PUT"

    def test_mtime_only_change_does_not_trigger_put(self, tmp_path, monkeypatch):
        """LE bruit à l'origine de l'incident : toucher un fichier (mtime change,
        contenu identique) ne doit PAS déclencher de PUT — l'empreinte exclut
        volontairement mtime/permissions."""
        f = tmp_path / "core" / "data.db"
        _write(tmp_path, "core/data.db", b"contenu-stable")
        client = _fake_client()
        _patch_env(monkeypatch, tmp_path, client)
        _run(s3_sync._periodic_sync_tick())
        assert client.put_object.call_count == 1

        os.utime(f, (time.time() + 100, time.time() + 100))  # touche mtime seul
        _run(s3_sync._periodic_sync_tick())
        assert client.put_object.call_count == 1, "un touch (mtime seul) ne doit PAS re-uploader"


# =============================================================================
# 3) Échec d'upload — la référence n'avance pas, rejeu au cycle suivant
# =============================================================================

class TestUploadFailureReplay:
    def test_failed_put_does_not_advance_baseline_and_retries(self, tmp_path, monkeypatch):
        _write(tmp_path, "core/data.db", b"contenu-openbao")
        client = _fake_client(put_side_effect=[Exception("réseau coupé"), {}])
        _patch_env(monkeypatch, tmp_path, client)

        ok1 = _run(s3_sync._periodic_sync_tick())
        assert ok1 is False, "le premier PUT échoue"
        assert client.put_object.call_count == 1

        # Même contenu, aucune modification : si la baseline avait (à tort) avancé
        # sur l'échec, ce 2e cycle SAUTERAIT le PUT. Elle ne doit pas avoir avancé.
        ok2 = _run(s3_sync._periodic_sync_tick())
        assert ok2 is True, "le cycle suivant doit REJOUER un vrai PUT, pas sauter"
        assert client.put_object.call_count == 2, "rejeu prouvé : 2e tentative réelle"

    def test_ambiguous_failure_forbids_skip_even_if_content_reverts(self, tmp_path, monkeypatch):
        """
        Timeout/erreur AMBIGUË après envoi (Q5 de la revue) : l'objet a pu être
        écrit côté S3 malgré l'exception locale. Le cycle suivant ne doit JAMAIS
        sauter tant qu'un PUT n'a pas explicitement réussi — même si le contenu
        local est strictement identique à ce qu'il était avant l'échec.
        """
        _write(tmp_path, "core/data.db", b"contenu-openbao")
        client = _fake_client(put_side_effect=[TimeoutError("timeout après envoi"), {}])
        _patch_env(monkeypatch, tmp_path, client)

        ok1 = _run(s3_sync._periodic_sync_tick())
        assert ok1 is False
        assert s3_sync._s3_state_uncertain is True

        # Contenu STRICTEMENT inchangé — seule la garde "état incertain" empêche
        # un skip erroné ici (l'empreinte, elle, correspondrait à la référence si
        # celle-ci avait été mise à jour par erreur sur l'échec précédent).
        ok2 = _run(s3_sync._periodic_sync_tick())
        assert ok2 is True
        assert client.put_object.call_count == 2, (
            "un skip ici serait dangereux : l'état S3 réel après le timeout est "
            "inconnu, on ne peut pas supposer qu'aucune écriture n'a eu lieu"
        )
        assert s3_sync._s3_state_uncertain is False, "un PUT confirmé lève l'incertitude"

        # 3e cycle, toujours inchangé : la référence est maintenant fiable → skip.
        ok3 = _run(s3_sync._periodic_sync_tick())
        assert ok3 is True
        assert client.put_object.call_count == 2, "après confirmation, le skip reprend normalement"


# =============================================================================
# 4) Redémarrage / restauration — aucune perte de sauvegarde
# =============================================================================

class TestRestartAndRestoreSafety:
    def test_restart_resets_baseline_first_tick_always_uploads(self, tmp_path, monkeypatch):
        """La référence est en mémoire uniquement (pas persistée sur disque/S3).
        Après un redémarrage simulé, le 1er cycle DOIT uploader — jamais sauter,
        même si le contenu est identique à ce qu'il était avant l'arrêt (on ne
        peut pas prouver que S3 a bien la dernière version)."""
        _write(tmp_path, "core/data.db", b"contenu-openbao")
        client = _fake_client()
        _patch_env(monkeypatch, tmp_path, client)
        _run(s3_sync._periodic_sync_tick())
        assert client.put_object.call_count == 1

        s3_sync._reset_sync_state_for_tests()  # simule un redémarrage du process

        _run(s3_sync._periodic_sync_tick())
        assert client.put_object.call_count == 2, "1er cycle post-redémarrage : jamais un skip"

    def test_forced_upload_ignores_unchanged_state(self, tmp_path, monkeypatch):
        """Les appelants d'upload forcé (arrêt, opérations PKI) laissent le défaut
        `skip_if_unchanged=False` : ils uploadent TOUJOURS, même état inchangé —
        comportement historique préservé à l'identique sur ces 5 call sites."""
        _write(tmp_path, "core/data.db", b"contenu-openbao")
        client = _fake_client()
        _patch_env(monkeypatch, tmp_path, client)
        _run(s3_sync._periodic_sync_tick())
        assert client.put_object.call_count == 1

        ok = _run(s3_sync.upload_to_s3())  # défaut = False = upload forcé
        assert ok is True
        assert client.put_object.call_count == 2, "un upload forcé ne doit JAMAIS être sauté"

    def test_restore_confirmed_absent_first_run(self, tmp_path, monkeypatch):
        client = _fake_client(get_side_effect=_client_error("NoSuchKey", 404))
        _patch_env(monkeypatch, tmp_path, client)
        result = _run(s3_sync.download_from_s3())
        assert result is RestoreResult.CONFIRMED_ABSENT

    def test_restore_ambiguous_network_error_is_failed_not_absent(self, tmp_path, monkeypatch):
        """Bloquant #3 de la revue : une panne réseau ne doit JAMAIS être traitée
        comme une absence confirmée (sinon lifecycle.py initialiserait un coffre
        vide par-dessus une sauvegarde distante valide)."""
        client = _fake_client(get_side_effect=ConnectionError("réseau injoignable"))
        _patch_env(monkeypatch, tmp_path, client)
        result = _run(s3_sync.download_from_s3())
        assert result is RestoreResult.FAILED

    def test_restore_access_denied_is_failed_not_absent(self, tmp_path, monkeypatch):
        """Un 403 (droits) n'est pas non plus une absence confirmée."""
        client = _fake_client(get_side_effect=_client_error("AccessDenied", 403))
        _patch_env(monkeypatch, tmp_path, client)
        result = _run(s3_sync.download_from_s3())
        assert result is RestoreResult.FAILED

    def test_restore_corrupted_archive_is_failed(self, tmp_path, monkeypatch):
        client = _fake_client(get_return=b"ceci-n-est-pas-un-tar-gz-valide")
        _patch_env(monkeypatch, tmp_path, client)
        result = _run(s3_sync.download_from_s3())
        assert result is RestoreResult.FAILED

    def test_restore_success_extracts_files(self, tmp_path, monkeypatch):
        archive = _valid_tar_gz({"core/data.db": b"contenu-restaure"})
        client = _fake_client(get_return=archive)
        _patch_env(monkeypatch, tmp_path, client)
        result = _run(s3_sync.download_from_s3())
        assert result is RestoreResult.RESTORED
        assert (tmp_path / "core" / "data.db").read_bytes() == b"contenu-restaure"


# =============================================================================
# 5) Sensibilité de l'empreinte (Q1 de la revue) — construite dans la même passe
#    que l'archive : plus de fenêtre TOCTOU à tester séparément (fermée par
#    construction), on prouve ici qu'elle capture bien tout changement métier.
# =============================================================================

class TestFingerprintSensitivity:
    def _fp(self, data_dir):
        _, fingerprint = s3_sync._snapshot_and_archive(data_dir)
        return fingerprint

    def test_deterministic_across_calls(self, tmp_path):
        _write(tmp_path, "a.db", b"x")
        _write(tmp_path, "sub/b.db", b"y")
        assert self._fp(tmp_path) == self._fp(tmp_path)

    def test_rename_changes_fingerprint(self, tmp_path):
        _write(tmp_path, "a.db", b"contenu")
        fp_before = self._fp(tmp_path)
        (tmp_path / "a.db").rename(tmp_path / "b.db")
        assert self._fp(tmp_path) != fp_before

    def test_empty_directory_changes_fingerprint(self, tmp_path):
        _write(tmp_path, "a.db", b"contenu")
        fp_before = self._fp(tmp_path)
        (tmp_path / "empty_dir").mkdir()
        assert self._fp(tmp_path) != fp_before, "un répertoire vide créé doit changer l'empreinte"

    def test_symlink_creation_and_target_change_affect_fingerprint(self, tmp_path):
        _write(tmp_path, "target_a.db", b"a")
        _write(tmp_path, "target_b.db", b"b")
        fp_before = self._fp(tmp_path)

        link = tmp_path / "link.db"
        link.symlink_to(tmp_path / "target_a.db")
        fp_with_link_a = self._fp(tmp_path)
        assert fp_with_link_a != fp_before

        link.unlink()
        link.symlink_to(tmp_path / "target_b.db")
        fp_with_link_b = self._fp(tmp_path)
        assert fp_with_link_b != fp_with_link_a, "changer la CIBLE du symlink doit changer l'empreinte"

    def test_swap_contents_between_two_files_changes_fingerprint(self, tmp_path):
        """Prouve que l'empreinte n'est pas un simple multi-ensemble de hashs de
        contenu (qui serait insensible à un échange A<->B)."""
        _write(tmp_path, "a.db", b"contenu-A")
        _write(tmp_path, "b.db", b"contenu-B")
        fp_before = self._fp(tmp_path)

        _write(tmp_path, "a.db", b"contenu-B")
        _write(tmp_path, "b.db", b"contenu-A")
        assert self._fp(tmp_path) != fp_before

    def test_mtime_and_permissions_excluded_from_fingerprint(self, tmp_path):
        f = tmp_path / "a.db"
        _write(tmp_path, "a.db", b"contenu-stable")
        fp_before = self._fp(tmp_path)
        os.utime(f, (time.time() + 1000, time.time() + 1000))
        os.chmod(f, 0o600)
        assert self._fp(tmp_path) == fp_before, "mtime/permissions ne doivent PAS influencer l'empreinte"

    def test_archive_content_matches_source_files(self, tmp_path):
        """L'archive produite reste fidèle (restaurable) même si l'empreinte, elle,
        ignore mtime/permissions — les deux ne portent pas sur les mêmes axes."""
        _write(tmp_path, "core/data.db", b"contenu-a-restaurer")
        archive_bytes, _ = s3_sync._snapshot_and_archive(tmp_path)
        with tarfile.open(fileobj=io.BytesIO(archive_bytes), mode="r:gz") as tar:
            member = tar.getmember("core/data.db")
            extracted = tar.extractfile(member).read()
        assert extracted == b"contenu-a-restaurer"


# =============================================================================
# 6) Aucun secret / clé S3 / chemin interne dans les logs (contrainte 4)
# =============================================================================

class TestNoSensitiveLogging:
    MARKER = "LEAK-MARKER-bucket=prod-secrets-key=_storage/openbao-data.tar.gz"

    def test_upload_failure_message_not_logged_verbatim(self, tmp_path, monkeypatch, caplog):
        _write(tmp_path, "core/data.db", b"contenu")
        client = _fake_client(put_side_effect=Exception(self.MARKER))
        _patch_env(monkeypatch, tmp_path, client)

        with caplog.at_level("ERROR"):
            _run(s3_sync.upload_to_s3())

        for record in caplog.records:
            assert self.MARKER not in record.getMessage()

    def test_download_failure_message_not_logged_verbatim(self, tmp_path, monkeypatch, caplog):
        client = _fake_client(get_side_effect=Exception(self.MARKER))
        _patch_env(monkeypatch, tmp_path, client)

        with caplog.at_level("ERROR"):
            _run(s3_sync.download_from_s3())

        for record in caplog.records:
            assert self.MARKER not in record.getMessage()

    def test_s3_key_never_logged_on_upload(self, tmp_path, monkeypatch, caplog):
        _write(tmp_path, "core/data.db", b"contenu")
        client = _fake_client()
        _patch_env(monkeypatch, tmp_path, client)

        with caplog.at_level("DEBUG"):
            _run(s3_sync.upload_to_s3())

        for record in caplog.records:
            assert "_storage/openbao-data.tar.gz" not in record.getMessage()

    def test_connectivity_check_failure_no_str_exception(self, tmp_path, monkeypatch, caplog):
        monkeypatch.setattr(s3_sync, "get_settings", lambda: _settings(tmp_path))
        client = MagicMock()
        client.head_bucket.side_effect = Exception(self.MARKER)
        monkeypatch.setattr(s3_sync, "get_s3_meta_client", lambda: client)

        ok, detail = _run(s3_sync.check_s3_connectivity())
        assert ok is False
        assert self.MARKER not in detail


# =============================================================================
# 7) _is_confirmed_absent — détection structurée, pas de correspondance sur str(e)
# =============================================================================

class TestConfirmedAbsentDetection:
    def test_nosuchkey_client_error_is_confirmed_absent(self):
        assert s3_sync._is_confirmed_absent(_client_error("NoSuchKey", 404)) is True

    def test_404_client_error_is_confirmed_absent(self):
        assert s3_sync._is_confirmed_absent(_client_error("404", 404)) is True

    def test_access_denied_is_not_confirmed_absent(self):
        assert s3_sync._is_confirmed_absent(_client_error("AccessDenied", 403)) is False

    def test_generic_exception_is_not_confirmed_absent(self):
        assert s3_sync._is_confirmed_absent(Exception("boom")) is False

    def test_malformed_error_field_does_not_crash(self):
        """
        BLOQUANT mineur (revue de diff round 1) : un `ClientError` dont
        `response["Error"]` vaut `None` (au lieu d'un dict ou d'être absent)
        levait `AttributeError` au lieu de retourner `False` proprement — un
        cas malformé doit être fail-closed silencieusement, jamais planter
        l'appelant.
        """
        exc = Exception("réponse malformée")
        exc.response = {"Error": None}
        assert s3_sync._is_confirmed_absent(exc) is False

    def test_response_without_error_key_does_not_crash(self):
        exc = Exception("réponse incomplète")
        exc.response = {}
        assert s3_sync._is_confirmed_absent(exc) is False


# =============================================================================
# 8) TOCTOU intra-entrée (bloquant round 1) — les métadonnées et le contenu
#    archivés d'un fichier régulier doivent venir du MÊME descripteur ouvert,
#    jamais d'un second stat() par CHEMIN séparé (qui pourrait observer un état
#    différent si l'entité change entre-temps — reproduit et prouvé par la
#    revue de diff : fichier remplacé par un symlink entre deux stats
#    successifs par chemin produisait une archive et une empreinte
#    incohérentes entre elles).
# =============================================================================

class TestPerEntrySingleObservation:
    def test_regular_file_metadata_comes_from_open_fd_not_a_second_path_stat(
        self, tmp_path, monkeypatch
    ):
        _write(tmp_path, "a.db", b"contenu")
        real_lstat = Path.lstat
        sentinel_mtime = 111111.0

        def fake_lstat(self, *a, **kw):
            result = real_lstat(self, *a, **kw)
            if self.name == "a.db":
                # Simule un stat PAR CHEMIN qui observerait un état DIFFÉRENT
                # de celui du descripteur ouvert ensuite pour la lecture (un
                # mtime impossible, facilement détectable) — reproduit
                # l'écart temporel entre deux observations séparées du même
                # chemin que l'ancienne implémentation exploitait.
                return os.stat_result((
                    result.st_mode, result.st_ino, result.st_dev,
                    result.st_nlink, result.st_uid, result.st_gid,
                    result.st_size, 0, sentinel_mtime, 0,
                ))
            return result

        monkeypatch.setattr(Path, "lstat", fake_lstat)
        archive_bytes, _ = s3_sync._snapshot_and_archive(tmp_path)
        with tarfile.open(fileobj=io.BytesIO(archive_bytes), mode="r:gz") as tar:
            member = tar.getmember("a.db")

        assert member.mtime != int(sentinel_mtime), (
            "le mtime archivé d'un FICHIER doit venir du fstat() sur le "
            "descripteur ouvert pour la lecture, jamais d'un second lstat() "
            "par chemin (potentiellement désynchronisé)"
        )

    def test_no_separate_gettarinfo_path_restat_for_files(self, tmp_path, monkeypatch):
        """Preuve complémentaire : `tarfile.TarFile.gettarinfo` (qui refait son
        propre stat du CHEMIN) n'est plus appelée du tout pour construire
        l'entrée d'un fichier régulier."""
        _write(tmp_path, "a.db", b"contenu")
        calls = []
        real_gettarinfo = tarfile.TarFile.gettarinfo

        def spy(self, *a, **kw):
            calls.append((a, kw))
            return real_gettarinfo(self, *a, **kw)

        monkeypatch.setattr(tarfile.TarFile, "gettarinfo", spy)
        s3_sync._snapshot_and_archive(tmp_path)
        assert calls == [], "gettarinfo() ne doit plus être appelée (TarInfo construit depuis un stat déjà obtenu)"


# =============================================================================
# 9) Restauration ATOMIQUE (bloquant round 1) — une extraction qui échoue
#    APRÈS avoir déjà écrit certains membres (archive corrompue ou membre
#    rejeté par filter='data' après des membres valides) ne doit JAMAIS
#    laisser de résidu partiel dans data_dir lui-même.
# =============================================================================

class TestAtomicRestore:
    def test_partial_extraction_failure_leaves_data_dir_untouched(self, tmp_path, monkeypatch):
        """
        Reproduction exacte du bloquant : archive avec un membre VALIDE suivi
        d'un membre rejeté par `filter='data'` (path traversal). Avant le
        correctif, `extractall()` écrivait directement dans data_dir : le
        membre valide restait sur disque malgré l'échec global, et le
        prochain démarrage l'aurait pris pour une "vraie" donnée locale.
        """
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz") as tar:
            good = tarfile.TarInfo(name="good.db")
            good_content = b"contenu-valide"
            good.size = len(good_content)
            tar.addfile(good, io.BytesIO(good_content))

            evil = tarfile.TarInfo(name="../evil.db")  # rejeté par filter='data'
            evil_content = b"traversal"
            evil.size = len(evil_content)
            tar.addfile(evil, io.BytesIO(evil_content))
        archive = buf.getvalue()

        client = _fake_client(get_return=archive)
        _patch_env(monkeypatch, tmp_path, client)

        result = _run(s3_sync.download_from_s3())

        assert result is RestoreResult.FAILED
        remaining = [p.name for p in tmp_path.iterdir()]
        assert "good.db" not in remaining, (
            "le membre valide ne doit PAS apparaître dans data_dir après un "
            "échec d'extraction global — il ne doit exister QUE dans un "
            "staging jeté en bloc, jamais promu"
        )
        assert s3_sync._RESTORE_STAGING_DIRNAME not in remaining, (
            "le staging doit être entièrement nettoyé après un échec"
        )

    def test_successful_restore_leaves_no_staging_residue(self, tmp_path, monkeypatch):
        archive = _valid_tar_gz({"core/data.db": b"contenu"})
        client = _fake_client(get_return=archive)
        _patch_env(monkeypatch, tmp_path, client)

        result = _run(s3_sync.download_from_s3())

        assert result is RestoreResult.RESTORED
        assert not (tmp_path / s3_sync._RESTORE_STAGING_DIRNAME).exists()
        assert (tmp_path / "core" / "data.db").read_bytes() == b"contenu"

    def test_restore_clears_preexisting_gitkeep_before_promotion(self, tmp_path, monkeypatch):
        """`.gitkeep` (ignoré par `has_local_data`) ne doit pas faire échouer
        la promotion atomique (qui exige un répertoire cible vide côté POSIX)."""
        (tmp_path / ".gitkeep").write_bytes(b"")
        archive = _valid_tar_gz({"core/data.db": b"contenu"})
        client = _fake_client(get_return=archive)
        _patch_env(monkeypatch, tmp_path, client)

        result = _run(s3_sync.download_from_s3())

        assert result is RestoreResult.RESTORED
        assert (tmp_path / "core" / "data.db").read_bytes() == b"contenu"


# =============================================================================
# 9b) Marqueur durable de restauration incomplète (bloquant round 2) — la
#     promotion par renommages individuels n'est PAS transactionnelle : un
#     crash ou une erreur I/O au milieu peut laisser data_dir dans un état
#     MIXTE (certaines entrées promues, d'autres non). Sans un signal
#     explicite et durable, cet état mixte est indiscernable d'une "vraie"
#     donnée locale légitime — reproduit et prouvé en revue de diff round 2.
# =============================================================================

class TestRestoreMarker:
    def test_extraction_failure_leaves_marker_present(self, tmp_path, monkeypatch):
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz") as tar:
            evil = tarfile.TarInfo(name="../evil.db")
            evil_content = b"traversal"
            evil.size = len(evil_content)
            tar.addfile(evil, io.BytesIO(evil_content))
        client = _fake_client(get_return=buf.getvalue())
        _patch_env(monkeypatch, tmp_path, client)

        result = _run(s3_sync.download_from_s3())

        assert result is RestoreResult.FAILED
        assert (tmp_path / s3_sync._RESTORE_MARKER_FILENAME).exists(), (
            "un échec d'extraction doit laisser le marqueur en place — le "
            "prochain démarrage ne doit jamais faire confiance à data_dir"
        )

    def test_successful_restore_removes_marker(self, tmp_path, monkeypatch):
        archive = _valid_tar_gz({"core/data.db": b"contenu"})
        client = _fake_client(get_return=archive)
        _patch_env(monkeypatch, tmp_path, client)

        result = _run(s3_sync.download_from_s3())

        assert result is RestoreResult.RESTORED
        assert not (tmp_path / s3_sync._RESTORE_MARKER_FILENAME).exists()

    def test_confirmed_absent_removes_marker(self, tmp_path, monkeypatch):
        """
        État terminal légitime : si le marqueur restait après une absence
        CONFIRMÉE, le prochain démarrage forcerait indéfiniment une nouvelle
        restauration même après qu'OpenBao ait été initialisé et ait écrit de
        vraies données — au risque de les écraser en boucle.
        """
        client = _fake_client(get_side_effect=_client_error("NoSuchKey", 404))
        _patch_env(monkeypatch, tmp_path, client)

        result = _run(s3_sync.download_from_s3())

        assert result is RestoreResult.CONFIRMED_ABSENT
        assert not (tmp_path / s3_sync._RESTORE_MARKER_FILENAME).exists()

    def test_partial_promotion_failure_leaves_mixed_state_but_marker_present(
        self, tmp_path, monkeypatch
    ):
        """
        Reproduction EXACTE du bloquant round 2 : le renommage de la 2e entrée
        échoue après que la 1re ait déjà réussi. data_dir se retrouve dans un
        état MIXTE (1 entrée réellement promue, l'autre non) — mais le
        marqueur reste présent, ce qui est la SEULE chose qui protège le
        prochain démarrage de traiter cet état mixte comme une donnée locale
        valide (vérifié directement via `_check_local_data_status`, cf.
        test_lifecycle.py pour la preuve côté lifecycle).
        """
        archive = _valid_tar_gz({"a.db": b"contenu-a", "b.db": b"contenu-b"})
        client = _fake_client(get_return=archive)
        _patch_env(monkeypatch, tmp_path, client)

        real_rename = Path.rename
        call_count = {"n": 0}

        def flaky_rename(self, target):
            call_count["n"] += 1
            if call_count["n"] == 2:
                raise OSError("panne I/O simulée sur le 2e renommage")
            return real_rename(self, target)

        monkeypatch.setattr(Path, "rename", flaky_rename)

        result = _run(s3_sync.download_from_s3())

        assert result is RestoreResult.FAILED
        assert (tmp_path / s3_sync._RESTORE_MARKER_FILENAME).exists(), (
            "promotion partielle : le marqueur DOIT rester en place"
        )
        promoted = [p.name for p in tmp_path.iterdir() if not p.name.startswith(".")]
        assert len(promoted) == 1, (
            "état mixte reproduit : exactement une entrée a été promue avant l'échec"
        )

        # La preuve qui compte : même avec un contenu réel et partiel présent,
        # _check_local_data_status doit refuser de le traiter comme fiable.
        from mcp_vault.lifecycle import _check_local_data_status
        assert _check_local_data_status(tmp_path) is False

    def test_confirmed_absent_after_partial_promotion_purges_leftover(
        self, tmp_path, monkeypatch
    ):
        """
        Reproduction EXACTE du bloquant round 3 : une promotion partielle
        échoue (marqueur posé, 1 entrée orpheline promue). Un SECOND appel
        tombe ensuite sur une absence CONFIRMÉE par S3 (ex. objet supprimé
        entre les deux tentatives). Avant le correctif, le marqueur était
        retiré SANS purger le résidu — l'entrée orpheline redevenait alors
        "donnée locale valide" aux yeux de `_check_local_data_status`, alors
        qu'elle ne représente qu'un fragment d'une restauration jamais
        aboutie. Le nettoyage doit désormais avoir lieu AVANT de lever le
        marqueur sur CE chemin aussi.
        """
        archive = _valid_tar_gz({"a.db": b"contenu-a", "b.db": b"contenu-b"})
        client = _fake_client(get_return=archive)
        _patch_env(monkeypatch, tmp_path, client)

        real_rename = Path.rename
        call_count = {"n": 0}

        def flaky_rename(self, target):
            call_count["n"] += 1
            if call_count["n"] == 2:
                raise OSError("panne I/O simulée sur le 2e renommage")
            return real_rename(self, target)

        monkeypatch.setattr(Path, "rename", flaky_rename)
        first = _run(s3_sync.download_from_s3())
        assert first is RestoreResult.FAILED
        assert len([p for p in tmp_path.iterdir() if not p.name.startswith(".")]) == 1

        # Simule le VRAI redémarrage suivant : vault_startup() réévalue
        # _check_local_data_status() AVANT tout nouvel appel à
        # download_from_s3() — ce qui nettoie déjà le staging résiduel de la
        # tentative précédente (download_from_s3() n'est jamais rappelée sans
        # cette étape entre deux, cf. contrat documenté sur la fonction).
        from mcp_vault.lifecycle import _check_local_data_status
        assert _check_local_data_status(tmp_path) is False  # marqueur encore présent

        monkeypatch.undo()  # restaure Path.rename réel pour la 2e tentative
        client_absent = _fake_client(get_side_effect=_client_error("NoSuchKey", 404))
        _patch_env(monkeypatch, tmp_path, client_absent)

        second = _run(s3_sync.download_from_s3())

        assert second is RestoreResult.CONFIRMED_ABSENT
        assert not (tmp_path / s3_sync._RESTORE_MARKER_FILENAME).exists()
        remaining = [p.name for p in tmp_path.iterdir()]
        assert remaining == [], (
            "l'entrée orpheline de la tentative précédente doit être purgée "
            "AVANT de lever le marqueur — sinon elle redevient une donnée "
            "locale 'valide' au prochain calcul de _check_local_data_status"
        )

        assert _check_local_data_status(tmp_path) is False, (
            "data_dir vide et sans marqueur : pas de donnée locale, cohérent "
            "avec CONFIRMED_ABSENT (première exécution légitime)"
        )

    def test_confirmed_absent_purges_preexisting_nonempty_staging(self, tmp_path, monkeypatch):
        """
        Reproduction du bloquant round 4 : `_clear_data_dir_leftovers()`
        ignorait TOUJOURS le staging par nom, y compris depuis le chemin
        CONFIRMED_ABSENT où AUCUNE session de staging n'est active dans CET
        appel. Un staging résiduel NON VIDE — tel que le laisserait une
        tentative précédente dont le nettoyage immédiat aurait lui-même
        échoué (permission, I/O persistante ; reproduit par le reviewer avec
        un vrai répertoire en lecture seule) — y survivait donc au retrait du
        marqueur, et pouvait ensuite être compté comme donnée locale "valide".
        Construit ici directement l'état résiduel plutôt que d'orchestrer
        l'échec en cascade qui le produirait en conditions réelles.
        """
        staging = tmp_path / s3_sync._RESTORE_STAGING_DIRNAME
        staging.mkdir()
        (staging / "leftover.db").write_bytes(b"residu-d-une-tentative-precedente")
        (tmp_path / s3_sync._RESTORE_MARKER_FILENAME).touch()

        client = _fake_client(get_side_effect=_client_error("NoSuchKey", 404))
        _patch_env(monkeypatch, tmp_path, client)

        result = _run(s3_sync.download_from_s3())

        assert result is RestoreResult.CONFIRMED_ABSENT
        assert not staging.exists(), (
            "le staging résiduel (non vide) doit être purgé sur ce chemin "
            "aussi — sinon il survit au retrait du marqueur et redevient "
            "'donnée locale valide' au prochain calcul"
        )
        assert not (tmp_path / s3_sync._RESTORE_MARKER_FILENAME).exists()
        assert list(tmp_path.iterdir()) == []

        from mcp_vault.lifecycle import _check_local_data_status
        assert _check_local_data_status(tmp_path) is False


# =============================================================================
# 10) Cas non couvert signalé en revue (Q8, mineur) — un upload FORCÉ réussi
#     doit faire sauter le tick périodique immédiatement suivant s'il retrouve
#     un état identique (la référence est bien celle du snapshot promu par
#     l'upload forcé, pas seulement par les ticks).
# =============================================================================

class TestForcedUploadUpdatesBaselineForPeriodicTick:
    def test_forced_upload_then_unchanged_tick_is_skipped(self, tmp_path, monkeypatch):
        _write(tmp_path, "core/data.db", b"contenu-openbao")
        client = _fake_client()
        _patch_env(monkeypatch, tmp_path, client)

        ok_forced = _run(s3_sync.upload_to_s3())  # ex. opération PKI, shutdown
        assert ok_forced is True
        assert client.put_object.call_count == 1

        ok_tick = _run(s3_sync._periodic_sync_tick())
        assert ok_tick is True
        assert client.put_object.call_count == 1, (
            "le tick périodique suivant, état inchangé, doit sauter — la "
            "référence posée par l'upload FORCÉ doit être utilisable par le "
            "tick périodique, pas seulement par un autre tick"
        )
