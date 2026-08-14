# -*- coding: utf-8 -*-
"""
Issue #78, finding 4 — le binding de mission exigé AUX DEUX BOUTS en mode durci.

Le binding C18 repose sur `tenant_id` ET `expected_aud`. Seul `expected_aud`
était exigé : le contrôle d'appartenance au locataire ne s'appliquait donc jamais
quand le champ manquait.

- à la CONSOMMATION, une entrée sans `tenant_id` passait la garde ;
- à la CRÉATION, `expected_aud` était complété depuis la configuration mais pas
  `tenant_id` — aucune source serveur ne peut le suppléer. Le coffre fabriquait
  des provisions qu'il refuse ensuite.

Hors mode durci, comportement INCHANGÉ : les wraps historiques sans binding
restent consommables.

⚠️ `ENFORCE_MISSION_TOKEN_VALIDATION` est une porte INDÉPENDANTE du PEP
transport : elle peut être active en mode `bearer`.

Tests mockés (pas de conteneur). Stub hvac : `tests/conftest.py`.
"""
import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest

OP = "op-bind-78"
MISSION = "mission-bind-78"
AUD = "mcp-vault:prod"
TENANT = "tenant-42"


def run(coro):
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


# =============================================================================
# Bout 1 — CONSOMMATION : une entrée sans tenant_id est refusée en mode durci
# =============================================================================

def _registre(tenant_id: str, expected_aud: str):
    """
Registre en mémoire portant une entrée `active` au binding choisi."""
    from mcp_vault.vault.wrapping import WrapRegistry

    class EnMemoire(WrapRegistry):
        def __init__(self):
            self._wraps = []
            self._cache_time = float("inf")
            self._last_load_ok = True

        def load(self):
            pass

        def _maybe_refresh(self):
            pass

        def _save(self) -> bool:
            return True

    r = EnMemoire()
    r.register_pending(OP, MISSION, "vault-a", "chemin/cle", 300,
                       tenant_id=tenant_id, expected_aud=expected_aud)
    r.mark_active(OP, MISSION, "accessor-xyz")
    return r


class _ClientCompteur:
    """Compte les unwrap : prouve qu'un refus intervient AVANT l'appel OpenBao."""

    def __init__(self):
        self.unwraps = 0

    def __call__(self, url=None, token=None, **_kw):
        return SimpleNamespace(sys=SimpleNamespace(unwrap=self._unwrap))

    def _unwrap(self):
        self.unwraps += 1
        return {"data": {"data": {"password": "s3cr3t"}, "metadata": {}}}


def _consommer(registre, client, *, tenant_id, expected_aud, enforce):
    from mcp_vault.vault import wrapping
    import hvac

    settings = SimpleNamespace(openbao_addr="http://127.0.0.1:8200")
    with patch.object(wrapping, "get_wrap_registry", return_value=registre), \
         patch.object(wrapping, "_get_config", return_value=settings), \
         patch.object(wrapping, "_get_client", return_value=object()), \
         patch.object(hvac, "Client", client):
        return run(wrapping.consume_wrap_secret(
            wrap_token="wt-xxx", operation_id=OP, mission_id=MISSION,
            tenant_id=tenant_id, expected_aud=expected_aud, enforce=enforce))


def _statut(registre):
    return next(e["status"] for e in registre._wraps if e["operation_id"] == OP)


class TestConsommationBindingIncomplet:

    def test_sans_tenant_id_le_mode_durci_refuse(self):
        """
        CŒUR DU FINDING 4. seul `expected_aud` était
        exigé, donc une entrée sans `tenant_id` était consommée sans que
        l'appartenance au locataire soit jamais vérifiée.
        """
        registre = _registre(tenant_id="", expected_aud=AUD)
        client = _ClientCompteur()
        r = _consommer(registre, client, tenant_id=TENANT,
                       expected_aud=AUD, enforce=True)

        assert r["status"] == "error", r
        assert r["error_type"] == "binding_incomplete", r
        assert "tenant_id" in r["message"], (
            f"le message doit nommer le champ manquant : {r['message']!r}")
        assert client.unwraps == 0, (
            "refus tardif : OpenBao a été appelé, le jeton est brûlé pour rien")
        assert _statut(registre) == "active", (
            "un refus de binding ne doit PAS consommer l'entrée — le wrap reste "
            "utilisable par le bon appelant")

    def test_sans_expected_aud_le_refus_existant_est_preserve(self):
        """Anti-régression : le refus déjà en place ne doit pas disparaître."""
        registre = _registre(tenant_id=TENANT, expected_aud="")
        client = _ClientCompteur()
        r = _consommer(registre, client, tenant_id=TENANT,
                       expected_aud=AUD, enforce=True)

        assert r["error_type"] == "binding_incomplete", r
        assert "expected_aud" in r["message"], r
        assert client.unwraps == 0

    def test_une_entree_historique_a_champ_BLANC_dit_incomplet_pas_mismatch(self):
        """Question de DIAGNOSTIC : un champ d'espaces blancs sortait en
        `binding_mismatch`, ce qui fait chercher une erreur d'appel alors que
        l'entrée n'atteste rien et qu'il faut REPROVISIONNER."""
        registre = _registre(tenant_id="   ", expected_aud=AUD)
        client = _ClientCompteur()
        r = _consommer(registre, client, tenant_id=TENANT,
                       expected_aud=AUD, enforce=True)

        assert r["error_type"] == "binding_incomplete", (
            f"diagnostic trompeur : {r.get('error_type')!r} au lieu de "
            f"binding_incomplete — {r!r}")
        assert "reprovisionner" in r["message"].lower(), (
            f"le message doit dire quoi faire : {r['message']!r}")
        assert client.unwraps == 0

    def test_les_deux_manquants_sont_refuses(self):
        registre = _registre(tenant_id="", expected_aud="")
        client = _ClientCompteur()
        r = _consommer(registre, client, tenant_id="", expected_aud="",
                       enforce=True)

        assert r["error_type"] == "binding_incomplete", r
        assert client.unwraps == 0

    def test_binding_complet_passe_en_mode_durci(self):
        """
        ANTI-COMPLAISANCE : le durcissement ne doit pas casser le cas nominal.
        Sans ce test, refuser TOUT en mode durci passerait les trois ci-dessus.
        """
        registre = _registre(tenant_id=TENANT, expected_aud=AUD)
        client = _ClientCompteur()
        r = _consommer(registre, client, tenant_id=TENANT,
                       expected_aud=AUD, enforce=True)

        assert r["status"] == "ok", r
        assert client.unwraps == 1
        assert _statut(registre) == "consumed"

    def test_hors_mode_durci_le_wrap_legacy_reste_consommable(self):
        """
        RÉTROCOMPATIBILITÉ EXPLICITE : hors `enforce`, une entrée sans binding
        reste consommable. C'est un choix, pas un oubli — le durcissement est la
        contrepartie du mode durci.
        """
        registre = _registre(tenant_id="", expected_aud="")
        client = _ClientCompteur()
        r = _consommer(registre, client, tenant_id="", expected_aud="",
                       enforce=False)

        assert r["status"] == "ok", r
        assert client.unwraps == 1


# =============================================================================
# Bout 2 — CRÉATION : le coffre ne fabrique plus de provision au binding boiteux
# =============================================================================

def _appeler_secret_wrap(*, tenant_id, enforce, jwks="https://jwks.example/keys",
                         expected_aud="", instance=AUD):
    """Appelle l'outil `secret_wrap` et observe si le cœur a été atteint."""
    from tests.conftest import admin_auth_context
    from mcp_vault import server as srv

    coeur = AsyncMock(return_value={"status": "ok", "wrap_token": "s.SECRET",
                                    "operation_id": OP})
    with admin_auth_context(), \
         patch.object(srv.settings, "enforce_mission_token_validation", enforce), \
         patch.object(srv.settings, "mission_jwks_url", jwks), \
         patch.object(srv.settings, "mission_token_aud", instance), \
         patch.object(srv.settings, "mcp_instance_id", instance), \
         patch("mcp_vault.auth.context.check_access", return_value=None), \
         patch("mcp_vault.auth.context.check_path_policy", return_value=None), \
         patch("mcp_vault.vault.wrapping.wrap_secret", new=coeur):
        r = run(srv.secret_wrap(vault_id="vault-a", secret_path="chemin/cle",
                                mission_id=MISSION, operation_id=OP,
                                tenant_id=tenant_id, expected_aud=expected_aud))
    return r, coeur


class TestCreationBindingIncomplet:

    def test_en_mode_durci_sans_tenant_id_la_creation_est_refusee(self):
        """
        CŒUR DU SECOND BOUT. `expected_aud` était
        complété automatiquement, `tenant_id` restait vide, et le coffre créait
        une provision qu'il refusera lui-même à la consommation.
        """
        r, coeur = _appeler_secret_wrap(tenant_id="", enforce=True)

        assert r["status"] == "error", r
        assert r["error_type"] == "binding_incomplete", r
        assert "tenant_id" in r["message"], r
        coeur.assert_not_called()

    def test_le_tenant_id_n_est_jamais_devine(self):
        """
        Un `tenant_id` déduit d'une configuration serveur serait un FAUX
        binding : il attesterait une appartenance que le coffre a inventée.
        Seul l'appelant connaît le locataire. Le refus est donc la seule
        réponse correcte — pas un défaut de commodité.
        """
        r, coeur = _appeler_secret_wrap(tenant_id="   ", enforce=True)

        assert r["status"] == "error", (
            "un tenant_id d'espaces blancs a été accepté comme binding")
        assert r["error_type"] == "binding_incomplete", r
        coeur.assert_not_called()

    def test_avec_tenant_id_la_creation_aboutit(self):
        """ANTI-COMPLAISANCE : le cas nominal du mode durci doit passer."""
        r, coeur = _appeler_secret_wrap(tenant_id=TENANT, enforce=True)

        assert r["status"] == "ok", r
        coeur.assert_called_once()
        assert coeur.call_args.kwargs["tenant_id"] == TENANT

    def test_hors_mode_durci_la_creation_sans_tenant_id_reste_permise(self):
        """Rétrocompatibilité : le durcissement est borné au mode durci."""
        r, coeur = _appeler_secret_wrap(tenant_id="", enforce=False)

        assert r["status"] == "ok", r
        coeur.assert_called_once()

    @pytest.mark.parametrize("aud_fourni", ["", "   ", "\t\n"])
    def test_une_audience_d_espaces_blancs_est_traitee_comme_ABSENTE(self, aud_fourni):
        """Une audience d'espaces blancs stockée telle quelle rend le wrap
        inconsommable. Le bon traitement n'est PAS un refus : l'audience a une
        source serveur, donc elle est ENRICHIE — seul le locataire n'en a
        aucune."""
        r, coeur = _appeler_secret_wrap(tenant_id=TENANT, enforce=True,
                                        expected_aud=aud_fourni)

        assert r["status"] == "ok", r
        coeur.assert_called_once()
        assert coeur.call_args.kwargs["expected_aud"] == AUD, (
            f"audience {aud_fourni!r} non enrichie — stockée telle quelle, le "
            f"wrap sera inconsommable : {coeur.call_args.kwargs!r}")

    def test_une_audience_visant_une_AUTRE_instance_est_refusee(self):
        """`secret_consume` compare toujours l'audience stockée à celle de CETTE
        instance : une autre valeur rend le wrap définitivement inconsommable.
        Le refus à la création est donc le seul comportement honnête — l'écraser
        en silence attesterait une audience non demandée."""
        r, coeur = _appeler_secret_wrap(tenant_id=TENANT, enforce=True,
                                        expected_aud="autre-instance")

        assert r["status"] == "error", (
            f"une audience visant une autre instance a été acceptée : le wrap "
            f"sera inconsommable — {r!r}")
        assert r["error_type"] == "binding_mismatch", r
        coeur.assert_not_called()

    def test_une_audience_egale_a_cette_instance_est_acceptee(self):
        """
        ANTI-COMPLAISANCE du test précédent : refuser TOUTE audience explicite
        passerait le cas ci-dessus. Une audience qui désigne bien cette instance
        doit être acceptée, et transmise telle quelle.
        """
        r, coeur = _appeler_secret_wrap(tenant_id=TENANT, enforce=True,
                                        expected_aud=AUD)

        assert r["status"] == "ok", r
        coeur.assert_called_once()
        assert coeur.call_args.kwargs["expected_aud"] == AUD

    @pytest.mark.parametrize("tenant", ["", TENANT])
    def test_enforce_sans_jwks_refuse_car_la_provision_serait_morte_nee(self, tenant):
        """Avec `ENFORCE=true` et JWKS vide, `secret_consume` refuse
        SYSTÉMATIQUEMENT en `misconfigured` : créer le wrap fabriquerait une
        provision inconsommable à chaque appel. Le verdict doit être le même que
        celui de la consommation, même quand le locataire est fourni — c'est la
        configuration qui est en cause, pas l'appel."""
        r, coeur = _appeler_secret_wrap(tenant_id=tenant, enforce=True, jwks="")

        assert r["status"] == "error", (
            f"provision morte-née acceptée (tenant={tenant!r}) : "
            f"secret_consume la refusera toujours — {r!r}")
        assert r["error_type"] == "misconfigured", r
        assert "MISSION_JWKS_URL" in r["message"], (
            f"le message doit nommer la variable à corriger : {r['message']!r}")
        coeur.assert_not_called()

    def test_une_config_invalide_PRIME_sur_l_entree_de_l_appelant(self):
        """Audience serveur non résoluble ET locataire absent : le verdict doit
        être `misconfigured`, sinon on envoie l'appelant vérifier SES paramètres
        alors que le serveur est incohérent."""
        r, coeur = _appeler_secret_wrap(tenant_id="", enforce=True, instance="")

        assert r["status"] == "error", r
        assert r["error_type"] == "misconfigured", (
            f"la cause serveur doit primer : {r!r}")
        coeur.assert_not_called()

    def test_hors_enforce_sans_jwks_reste_permis(self):
        """
        ANTI-COMPLAISANCE du test précédent : le refus doit être borné au mode
        durci. Sans ce test, « refuser dès que JWKS est vide » passerait et
        casserait tout déploiement autonome.
        """
        r, coeur = _appeler_secret_wrap(tenant_id="", enforce=False, jwks="")

        assert r["status"] == "ok", r
        coeur.assert_called_once()
