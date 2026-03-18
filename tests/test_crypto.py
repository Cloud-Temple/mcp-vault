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
"""

import json
import sys
import os

# Ajouter le répertoire source au path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))


def test_roundtrip_simple():
    """Chiffrer puis déchiffrer retourne le texte original."""
    from mcp_vault.openbao.crypto import encrypt_with_bootstrap_key, decrypt_with_bootstrap_key

    plaintext = "Hello, World! 🔐"
    key = "ma-super-clé-bootstrap-64-caractères-minimum-pour-la-production!!"

    encrypted = encrypt_with_bootstrap_key(plaintext, key)
    decrypted = decrypt_with_bootstrap_key(encrypted, key)

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
    key = "test-bootstrap-key-assez-longue-pour-passer-la-validation"

    encrypted = encrypt_with_bootstrap_key(plaintext, key)
    decrypted = decrypt_with_bootstrap_key(encrypted, key)
    recovered = json.loads(decrypted)

    assert recovered == init_data, f"JSON roundtrip échoué"
    assert recovered["root_token"] == init_data["root_token"]
    assert recovered["keys"] == init_data["keys"]
    print("  ✅ Roundtrip JSON (clés unseal) OK")


def test_wrong_key_fails():
    """Déchiffrer avec une mauvaise clé doit lever ValueError."""
    from mcp_vault.openbao.crypto import encrypt_with_bootstrap_key, decrypt_with_bootstrap_key

    plaintext = "secret data"
    good_key = "the-correct-bootstrap-key-1234567890"
    bad_key = "the-WRONG-bootstrap-key-9876543210!!"

    encrypted = encrypt_with_bootstrap_key(plaintext, good_key)

    try:
        decrypt_with_bootstrap_key(encrypted, bad_key)
        assert False, "Aurait dû lever ValueError"
    except ValueError as e:
        assert "incorrecte" in str(e).lower() or "corrompue" in str(e).lower()
        print(f"  ✅ Mauvaise clé → ValueError : {e}")


def test_corrupted_data_fails():
    """Données corrompues doivent lever ValueError."""
    from mcp_vault.openbao.crypto import decrypt_with_bootstrap_key

    key = "bootstrap-key-pour-test-corruption"

    # Base64 valide mais données trop courtes
    try:
        decrypt_with_bootstrap_key("AAAA", key)
        assert False, "Aurait dû lever ValueError (données trop courtes)"
    except ValueError as e:
        print(f"  ✅ Données trop courtes → ValueError : {e}")

    # Base64 invalide
    try:
        decrypt_with_bootstrap_key("!!!pas-du-base64!!!", key)
        assert False, "Aurait dû lever ValueError (base64 invalide)"
    except ValueError as e:
        print(f"  ✅ Base64 invalide → ValueError : {e}")


def test_short_key_fails():
    """Bootstrap key trop courte doit lever ValueError."""
    from mcp_vault.openbao.crypto import encrypt_with_bootstrap_key

    try:
        encrypt_with_bootstrap_key("data", "short")
        assert False, "Aurait dû lever ValueError (clé trop courte)"
    except ValueError as e:
        assert "16 caractères" in str(e)
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
    key = "bootstrap-key-pour-test-unicité-1234"

    enc1 = encrypt_with_bootstrap_key(plaintext, key)
    enc2 = encrypt_with_bootstrap_key(plaintext, key)

    assert enc1 != enc2, "Deux chiffrements identiques ! Le sel/nonce n'est pas aléatoire"
    print(f"  ✅ Unicité OK (enc1={enc1[:20]}... != enc2={enc2[:20]}...)")


def test_large_payload():
    """Chiffrement d'un payload de 10 KB (réaliste pour des clés Shamir multiples)."""
    from mcp_vault.openbao.crypto import encrypt_with_bootstrap_key, decrypt_with_bootstrap_key

    plaintext = "x" * 10_000
    key = "bootstrap-key-pour-test-grande-taille!"

    encrypted = encrypt_with_bootstrap_key(plaintext, key)
    decrypted = decrypt_with_bootstrap_key(encrypted, key)

    assert decrypted == plaintext
    assert len(decrypted) == 10_000
    print(f"  ✅ Payload 10 KB OK (encrypted={len(encrypted)} chars base64)")


def test_unicode_content():
    """Chiffrement de contenu Unicode (emojis, accents, CJK)."""
    from mcp_vault.openbao.crypto import encrypt_with_bootstrap_key, decrypt_with_bootstrap_key

    plaintext = '{"note": "Clé générée le 18/03/2026 🔐", "accents": "éàü", "cjk": "漢字"}'
    key = "bootstrap-key-unicode-test-1234567!"

    encrypted = encrypt_with_bootstrap_key(plaintext, key)
    decrypted = decrypt_with_bootstrap_key(encrypted, key)

    assert decrypted == plaintext
    print("  ✅ Unicode (emojis, accents, CJK) OK")


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
    ]

    print(f"\n🧪 Tests crypto.py — Option C ({len(tests)} tests)\n")

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
