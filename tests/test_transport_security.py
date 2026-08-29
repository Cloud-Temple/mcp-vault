# -*- coding: utf-8 -*-
"""
Tests unitaires pour la protection anti-DNS-rebinding du transport MCP.

Régression de l'issue #3 : /mcp renvoyait HTTP 421 « Invalid Host header » sur
le FQDN public car le SDK MCP auto-active la protection avec uniquement le loopback
en allowed_hosts. Le correctif construit explicitement les TransportSecuritySettings
à partir de MCP_ALLOWED_HOSTS (loopback toujours inclus).

Ces tests vérifient :
    1. La protection reste ACTIVE (sécurité conservée).
    2. Les FQDN publics configurés sont acceptés.
    3. Le loopback (localhost/127.0.0.1, avec ou sans port) reste accepté (tests e2e via WAF).
    4. La variante avec port explicite du FQDN est acceptée.
    5. Les origins https://<fqdn> sont dérivées automatiquement.
    6. Un host non autorisé est rejeté (la protection mord toujours).
    7. La config est bien pilotée par MCP_ALLOWED_HOSTS (override).
"""

import os
import sys

# Ajouter le répertoire source au path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from mcp_vault.config import Settings
from mcp_vault.server import _build_transport_security


def _middleware_for(ts):
    """Instancie le TransportSecurityMiddleware du SDK avec des settings donnés."""
    from mcp.server.transport_security import TransportSecurityMiddleware

    m = TransportSecurityMiddleware.__new__(TransportSecurityMiddleware)
    m.settings = ts
    return m


def _cfg(hosts: str, origins: str = ""):
    """Settings isolé (sans lecture du .env ambiant) pour des tests déterministes."""
    return Settings(
        _env_file=None,
        mcp_allowed_hosts=hosts,
        mcp_allowed_origins=origins,
    )


def test_protection_stays_enabled():
    """La protection anti-DNS-rebinding doit rester active."""
    ts = _build_transport_security(_cfg("vault.example.com"))
    assert ts.enable_dns_rebinding_protection is True, "La protection ne doit pas être désactivée"
    print("  ✅ Protection anti-DNS-rebinding active")


def test_public_fqdn_accepted():
    """Les FQDN configurés via MCP_ALLOWED_HOSTS sont acceptés."""
    ts = _build_transport_security(_cfg("vault.mcp.cloud-temple.app,my.vault.mcp.cloud-temple.app"))
    m = _middleware_for(ts)
    assert m._validate_host("vault.mcp.cloud-temple.app"), "FQDN public 1 doit être accepté"
    assert m._validate_host("my.vault.mcp.cloud-temple.app"), "FQDN public 2 doit être accepté"
    print("  ✅ FQDN publics configurés acceptés")


def test_loopback_always_accepted():
    """Le loopback reste accepté même si non listé (health checks, e2e via WAF localhost)."""
    ts = _build_transport_security(_cfg("vault.example.com"))
    m = _middleware_for(ts)
    for h in ("localhost", "127.0.0.1", "localhost:8085", "127.0.0.1:8030"):
        assert m._validate_host(h), f"Loopback {h} doit être accepté"
    print("  ✅ Loopback (avec/sans port) toujours accepté")


def test_fqdn_with_explicit_port_accepted():
    """La variante avec port explicite (fqdn:*) est acceptée."""
    ts = _build_transport_security(_cfg("vault.mcp.cloud-temple.app"))
    m = _middleware_for(ts)
    assert m._validate_host("vault.mcp.cloud-temple.app:443"), "FQDN avec port doit être accepté"
    print("  ✅ FQDN avec port explicite accepté")


def test_origin_derived_from_fqdn():
    """L'origin https://<fqdn> est dérivée automatiquement pour chaque FQDN."""
    ts = _build_transport_security(_cfg("vault.mcp.cloud-temple.app"))
    assert "https://vault.mcp.cloud-temple.app" in ts.allowed_origins, "Origin HTTPS doit être dérivée"
    m = _middleware_for(ts)
    assert m._validate_origin("https://vault.mcp.cloud-temple.app"), "Origin du FQDN doit être acceptée"
    print("  ✅ Origin https://<fqdn> dérivée et acceptée")


def test_unknown_host_rejected():
    """Un host non autorisé doit être rejeté (la protection mord toujours)."""
    ts = _build_transport_security(_cfg("vault.mcp.cloud-temple.app"))
    m = _middleware_for(ts)
    assert not m._validate_host("evil.example.com"), "Host inconnu doit être rejeté"
    assert not m._validate_host(None), "Host absent doit être rejeté"
    print("  ✅ Host inconnu / absent rejeté")


def test_explicit_origins_added():
    """MCP_ALLOWED_ORIGINS ajoute des origins explicites supplémentaires."""
    ts = _build_transport_security(_cfg("vault.example.com", origins="https://app.example.com"))
    m = _middleware_for(ts)
    assert m._validate_origin("https://app.example.com"), "Origin explicite doit être acceptée"
    print("  ✅ Origins explicites (MCP_ALLOWED_ORIGINS) ajoutées")


def test_empty_hosts_still_protects_loopback():
    """Sans FQDN configuré, le loopback reste accepté et le reste rejeté."""
    ts = _build_transport_security(_cfg(""))
    m = _middleware_for(ts)
    assert m._validate_host("localhost:8085"), "Loopback doit rester accepté"
    assert not m._validate_host("vault.mcp.cloud-temple.app"), "FQDN non configuré doit être rejeté"
    print("  ✅ Sans FQDN : loopback OK, reste rejeté")


def test_host_case_insensitive():
    """Un FQDN saisi en majuscules est normalisé (DNS insensible à la casse)."""
    ts = _build_transport_security(_cfg("Vault.MCP.Cloud-Temple.App"))
    m = _middleware_for(ts)
    # Le Host arrive en minuscules en pratique ; la config majuscule doit quand même matcher.
    assert m._validate_host("vault.mcp.cloud-temple.app"), "FQDN doit matcher quelle que soit la casse"
    print("  ✅ FQDN normalisé en minuscules (insensible à la casse)")


def test_no_duplicate_entries():
    """Pas de doublons dans allowed_hosts/allowed_origins (dédup en préservant l'ordre)."""
    # localhost est implicite ET fourni explicitement → ne doit apparaître qu'une fois.
    ts = _build_transport_security(_cfg("localhost,vault.example.com,vault.example.com"))
    assert len(ts.allowed_hosts) == len(set(ts.allowed_hosts)), f"Doublons dans hosts : {ts.allowed_hosts}"
    assert len(ts.allowed_origins) == len(set(ts.allowed_origins)), f"Doublons dans origins : {ts.allowed_origins}"
    print("  ✅ Aucun doublon dans hosts/origins")


def test_ipv6_loopback_accepted():
    """Le loopback IPv6 [::1] (avec et sans port) est accepté."""
    ts = _build_transport_security(_cfg("vault.example.com"))
    m = _middleware_for(ts)
    assert m._validate_host("[::1]"), "Loopback IPv6 nu doit être accepté"
    assert m._validate_host("[::1]:8030"), "Loopback IPv6 avec port doit être accepté"
    print("  ✅ Loopback IPv6 [::1] accepté (avec/sans port)")


if __name__ == "__main__":
    tests = [
        test_protection_stays_enabled,
        test_public_fqdn_accepted,
        test_loopback_always_accepted,
        test_fqdn_with_explicit_port_accepted,
        test_origin_derived_from_fqdn,
        test_unknown_host_rejected,
        test_explicit_origins_added,
        test_empty_hosts_still_protects_loopback,
        test_host_case_insensitive,
        test_no_duplicate_entries,
        test_ipv6_loopback_accepted,
    ]

    print(f"\n🧪 Tests transport_security — anti-DNS-rebinding / issue #3 ({len(tests)} tests)\n")

    passed = 0
    failed = 0
    for test in tests:
        name = test.__name__
        try:
            test()
            passed += 1
        except Exception as e:
            print(f"  ❌ {name} : {e}")
            failed += 1

    print(f"\n{'=' * 50}")
    if failed == 0:
        print(f"  ✅ {passed}/{passed} tests passent")
    else:
        print(f"  ❌ {failed}/{passed + failed} tests échouent")
    print(f"{'=' * 50}")
    sys.exit(0 if failed == 0 else 1)
