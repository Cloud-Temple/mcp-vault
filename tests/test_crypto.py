# -*- coding: utf-8 -*-
"""
Tests unitaires pour openbao/crypto.py — Chiffrement des clés unseal (Option C).

Ces tests vérifient :
    1. Roundtrip encrypt → decrypt (données récupérées identiques)
    2. Clé incorrecte → erreur
    3. Données corrompues → erreur
    4. Bootstrap key trop courte → erreur
    5. Données vides / edge cases
    6. Unicité du chiffrement (sel + nonce aléatoires)
    7. Validation de l'entropie de la bootstrap key
    8. Zeroing mémoire des clés dérivées
"""

import json
import sys
import os

# Ajouter le répertoire source au path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

# Clé de test conforme aux nouvelles exigences :
# ≥ 32 chars, 3+ classes (majuscules, minuscules, chiffres, symboles)
_TEST_KEY = "Test-Bootstrap-Key-2026-Pour-Crypto!!"
_TEST_KEY_ALT = "Another-Secure-Key-9876-For-Tests!!"


def test_roundtrip_simple():
    """Chiffrer puis déchiffrer retourne le texte original."""
    from mcp_vault.openbao.crypto import encrypt_with_bootstrap_key, decrypt_with_bootstrap_key

    plaintext = "Hello, World! 🔐"

    encrypted = encrypt_with_bootstrap_key(plaintext, _TEST_KEY)
    decrypted = decrypt_with_bootstrap_key(encrypted, _TEST_KEY)

    assert decrypted == plaintext, f"Roundtrip échoué : {decrypted!r} != {plaintext!r}"
    print("  ✅ Roundtrip simple OK")


def test_roundtrip_json_keys():
    """Roundtrip avec une structure JSON réaliste (clés unseal)."""
    from mcp_vault.openbao.crypto import encrypt_with_bootstrap_key, decrypt_with_bootstrap_key

    init_data = {
        "root_token": "hvs.CAESIPx1234567890abcdef",
        "keys": ["abc123def456ghi789jkl012mno345pqr678stu901vwx234yz"],
        "keys_base64": ["q7wTN...base64...=="],
    }
    plaintext = json.dumps(init_data)

    encrypted = encrypt_with_bootstrap_key(plaintext, _TEST_KEY)
    decrypted = decrypt_with_bootstrap_key(encrypted, _TEST_KEY)
    recovered = json.loads(decrypted)

    assert recovered == init_data, f"JSON roundtrip échoué"
    assert recovered["root_token"] == init_data["root_token"]
    assert recovered["keys"] == init_data["keys"]
    print("  ✅ Roundtrip JSON (clés unseal) OK")


def test_wrong_key_fails():
    """Déchiffrer avec une mauvaise clé doit lever ValueError."""
    from mcp_vault.openbao.crypto import encrypt_with_bootstrap_key, decrypt_with_bootstrap_key

    plaintext = "secret data"

    encrypted = encrypt_with_bootstrap_key(plaintext, _TEST_KEY)

    try:
        decrypt_with_bootstrap_key(encrypted, _TEST_KEY_ALT)
        assert False, "Aurait dû lever ValueError"
    except ValueError as e:
        assert "incorrecte" in str(e).lower() or "corrompue" in str(e).lower()
        print(f"  ✅ Mauvaise clé → ValueError : {e}")


def test_corrupted_data_fails():
    """Données corrompues doivent lever ValueError."""
    from mcp_vault.openbao.crypto import decrypt_with_bootstrap_key

    # Base64 valide mais données trop courtes
    try:
        decrypt_with_bootstrap_key("AAAA", _TEST_KEY)
        assert False, "Aurait dû lever ValueError (données trop courtes)"
    except ValueError as e:
        print(f"  ✅ Données trop courtes → ValueError : {e}")

    # Base64 invalide
    try:
        decrypt_with_bootstrap_key("!!!pas-du-base64!!!", _TEST_KEY)
        assert False, "Aurait dû lever ValueError (base64 invalide)"
    except ValueError as e:
        print(f"  ✅ Base64 invalide → ValueError : {e}")


def test_short_key_fails():
    """Bootstrap key trop courte doit lever ValueError."""
    from mcp_vault.openbao.crypto import encrypt_with_bootstrap_key

    try:
        encrypt_with_bootstrap_key("data", "Short-Key-1!")
        assert False, "Aurait dû lever ValueError (clé trop courte)"
    except ValueError as e:
        assert "32" in str(e) or "trop courte" in str(e).lower()
        print(f"  ✅ Clé trop courte → ValueError : {e}")


def test_empty_key_fails():
    """Bootstrap key vide doit lever ValueError."""
    from mcp_vault.openbao.crypto import encrypt_with_bootstrap_key, decrypt_with_bootstrap_key

    try:
        encrypt_with_bootstrap_key("data", "")
        assert False, "Aurait dû lever ValueError (clé vide pour encrypt)"
    except ValueError:
        print("  ✅ Clé vide (encrypt) → ValueError")

    try:
        decrypt_with_bootstrap_key("AAAA", "")
        assert False, "Aurait dû lever ValueError (clé vide pour decrypt)"
    except ValueError:
        print("  ✅ Clé vide (decrypt) → ValueError")


def test_unique_ciphertext():
    """Deux chiffrements du même texte donnent des résultats différents (sel + nonce aléatoires)."""
    from mcp_vault.openbao.crypto import encrypt_with_bootstrap_key

    plaintext = "même texte"

    enc1 = encrypt_with_bootstrap_key(plaintext, _TEST_KEY)
    enc2 = encrypt_with_bootstrap_key(plaintext, _TEST_KEY)

    assert enc1 != enc2, "Deux chiffrements identiques ! Le sel/nonce n'est pas aléatoire"
    print(f"  ✅ Unicité OK (enc1={enc1[:20]}... != enc2={enc2[:20]}...)")


def test_large_payload():
    """Chiffrement d'un payload de 10 KB (réaliste pour des clés Shamir multiples)."""
    from mcp_vault.openbao.crypto import encrypt_with_bootstrap_key, decrypt_with_bootstrap_key

    plaintext = "x" * 10_000

    encrypted = encrypt_with_bootstrap_key(plaintext, _TEST_KEY)
    decrypted = decrypt_with_bootstrap_key(encrypted, _TEST_KEY)

    assert decrypted == plaintext
    assert len(decrypted) == 10_000
    print(f"  ✅ Payload 10 KB OK (encrypted={len(encrypted)} chars base64)")


def test_unicode_content():
    """Chiffrement de contenu Unicode (emojis, accents, CJK)."""
    from mcp_vault.openbao.crypto import encrypt_with_bootstrap_key, decrypt_with_bootstrap_key

    plaintext = '{"note": "Clé générée le 18/03/2026 🔐", "accents": "éàü", "cjk": "漢字"}'

    encrypted = encrypt_with_bootstrap_key(plaintext, _TEST_KEY)
    decrypted = decrypt_with_bootstrap_key(encrypted, _TEST_KEY)

    assert decrypted == plaintext
    print("  ✅ Unicode (emojis, accents, CJK) OK")


# ─── Nouveaux tests de sécurité ───────────────────────────────────────────────


def test_validate_bootstrap_key_good():
    """Clés valides doivent passer la validation."""
    from mcp_vault.openbao.crypto import validate_bootstrap_key

    # Clé avec 4 classes (maj, min, chiffres, symboles) — 32+ chars
    ok, msg = validate_bootstrap_key("My-Super-Secure-Key-2026-Prod!!!")
    assert ok, f"Devrait être valide : {msg}"

    # Clé générée par secrets.token_urlsafe (3 classes : maj, min, chiffres + _-)
    ok, msg = validate_bootstrap_key("aBcDeFgHiJkLmNoPqRsTuVwXyZ012345-_")
    assert ok, f"Devrait être valide : {msg}"

    print("  ✅ validate_bootstrap_key — clés valides OK")


def test_validate_bootstrap_key_default_rejected():
    """La valeur par défaut 'change_me_in_production' doit être rejetée."""
    from mcp_vault.openbao.crypto import validate_bootstrap_key

    ok, msg = validate_bootstrap_key("change_me_in_production")
    assert not ok, "La valeur par défaut devrait être rejetée"
    assert "par défaut" in msg.lower() or "change_me" in msg
    print(f"  ✅ Valeur par défaut rejetée : {msg}")


def test_validate_bootstrap_key_too_short():
    """Clés trop courtes doivent être rejetées."""
    from mcp_vault.openbao.crypto import validate_bootstrap_key

    ok, msg = validate_bootstrap_key("Short-1!")
    assert not ok, "Clé courte devrait être rejetée"
    assert "32" in msg or "trop courte" in msg.lower()
    print(f"  ✅ Clé courte rejetée : {msg}")


def test_validate_bootstrap_key_low_diversity():
    """Clés sans diversité de caractères doivent être rejetées."""
    from mcp_vault.openbao.crypto import validate_bootstrap_key

    # Que des minuscules et tirets — 2 classes seulement
    ok, msg = validate_bootstrap_key("abcdefghijklmnopqrstuvwxyz-abcdefg")
    assert not ok, "Clé sans diversité devrait être rejetée"
    assert "diversité" in msg.lower() or "classes" in msg.lower()
    print(f"  ✅ Clé faible diversité rejetée : {msg}")


def test_validate_bootstrap_key_repetitive():
    """Clés avec trop de répétitions doivent être rejetées."""
    from mcp_vault.openbao.crypto import validate_bootstrap_key

    # Même caractère répété (passe longueur et classes mais échoue en diversité unique)
    ok, msg = validate_bootstrap_key("aaAAaaAAaaAAaaAAaaAAaaAAaaAAaaAA11")
    # Ce cas a 3 classes mais seulement 3 caractères uniques sur 32
    assert not ok, "Clé répétitive devrait être rejetée"
    assert "répétition" in msg.lower()
    print(f"  ✅ Clé répétitive rejetée : {msg}")


def test_zero_fill():
    """Le zeroing mémoire doit effacer tous les bytes d'un bytearray."""
    from mcp_vault.openbao.crypto import _zero_fill

    buf = bytearray(b"\xff" * 32)
    assert all(b == 0xff for b in buf), "Buffer initial mal rempli"

    _zero_fill(buf)
    assert all(b == 0 for b in buf), "Zero-fill n'a pas tout effacé"
    assert len(buf) == 32, "Longueur modifiée par zero-fill"
    print("  ✅ _zero_fill — effacement mémoire OK")


def test_derive_key_returns_bytearray():
    """_derive_key doit retourner un bytearray (mutable pour zeroing)."""
    from mcp_vault.openbao.crypto import _derive_key

    key = _derive_key("test-passphrase", b"\x00" * 16)
    assert isinstance(key, bytearray), f"Attendu bytearray, obtenu {type(key)}"
    assert len(key) == 32, f"Attendu 32 bytes, obtenu {len(key)}"
    print("  ✅ _derive_key retourne bytearray (32 bytes)")


def test_aad_legacy_fallback():
    """Données chiffrées SANS AAD (pré-v0.4.5) doivent être déchiffrables via fallback."""
    import base64, os
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from mcp_vault.openbao.crypto import (
        decrypt_with_bootstrap_key, _derive_key, _SALT_LENGTH, _NONCE_LENGTH, _zero_fill,
    )

    # Simuler un chiffrement legacy SANS AAD (comme le faisait v0.4.0)
    plaintext = '{"root_token": "hvs.legacy-test"}'
    salt = os.urandom(_SALT_LENGTH)
    nonce = os.urandom(_NONCE_LENGTH)
    key = _derive_key(_TEST_KEY, salt)
    try:
        aesgcm = AESGCM(bytes(key))
        ciphertext_with_tag = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), None)  # PAS d'AAD
    finally:
        _zero_fill(key)

    encrypted_b64 = base64.b64encode(salt + nonce + ciphertext_with_tag).decode("ascii")

    # Le déchiffrement doit fonctionner via le fallback legacy
    decrypted = decrypt_with_bootstrap_key(encrypted_b64, _TEST_KEY)
    assert decrypted == plaintext, f"Fallback legacy échoué : {decrypted!r} != {plaintext!r}"
    print("  ✅ AAD legacy fallback (pré-v0.4.5) OK")


def test_aad_context_binding():
    """Le chiffrement avec AAD empêche le déchiffrement avec un AAD différent."""
    import base64, os
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from mcp_vault.openbao.crypto import (
        _derive_key, _SALT_LENGTH, _NONCE_LENGTH, _AAD, _zero_fill,
    )

    plaintext = "secret-data"
    salt = os.urandom(_SALT_LENGTH)
    nonce = os.urandom(_NONCE_LENGTH)
    key = _derive_key(_TEST_KEY, salt)
    try:
        aesgcm = AESGCM(bytes(key))
        ciphertext = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), _AAD)
    finally:
        _zero_fill(key)

    # Tenter de déchiffrer avec un AAD différent → doit échouer
    key2 = _derive_key(_TEST_KEY, salt)
    try:
        aesgcm2 = AESGCM(bytes(key2))
        try:
            aesgcm2.decrypt(nonce, ciphertext, b"wrong-context")
            assert False, "Aurait dû lever une exception (AAD différent)"
        except Exception:
            pass  # Attendu : InvalidTag
    finally:
        _zero_fill(key2)

    print("  ✅ AAD context binding — AAD différent → rejet OK")


if __name__ == "__main__":
    tests = [
        test_roundtrip_simple,
        test_roundtrip_json_keys,
        test_wrong_key_fails,
        test_corrupted_data_fails,
        test_short_key_fails,
        test_empty_key_fails,
        test_unique_ciphertext,
        test_large_payload,
        test_unicode_content,
        test_validate_bootstrap_key_good,
        test_validate_bootstrap_key_default_rejected,
        test_validate_bootstrap_key_too_short,
        test_validate_bootstrap_key_low_diversity,
        test_validate_bootstrap_key_repetitive,
        test_zero_fill,
        test_derive_key_returns_bytearray,
        test_aad_legacy_fallback,
        test_aad_context_binding,
    ]

    print(f"\n🧪 Tests crypto.py — Option C + Sécurité + AAD ({len(tests)} tests)\n")

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
