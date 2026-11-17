# -*- coding: utf-8 -*-
"""
Doublure OpenBao PKI réaliste pour les tests unitaires (issue #206).

Depuis #206, le setup et la rotation CONTRÔLENT l'intermédiaire signé avant de
l'importer, et `pki_issue_cert` contrôle le certificat émis : un certificat plus
court que demandé est refusé (jamais de troncature silencieuse). Les anciennes
doublures rendaient `"certificate": ""` ou un PEM factice — réponses qu'OpenBao
ne produit jamais, et que le contrôle refuse, à juste titre.

`pki_write(base)` rend une fonction à brancher en `side_effect` de `client.write` :
- `.../sign-intermediate` → un VRAI intermédiaire X.509 de la durée demandée ;
- `.../issue/<rôle>`      → la réponse `base` dont le certificat est un VRAI
                            certificat feuille de la durée demandée ;
- tout autre chemin       → `base`, inchangé.
Les assertions des bancs (chemins appelés, kwargs) restent celles d'origine.
"""
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

_UNITS = {"s": 1, "m": 60, "h": 3600, "d": 86400}
_KEY = ec.generate_private_key(ec.SECP256R1())


def _seconds(ttl) -> int:
    ttl = str(ttl).strip()
    return int(ttl[:-1]) * _UNITS[ttl[-1]]


def make_cert(ttl_seconds: int, *, ca: bool, cn: str = "double") -> str:
    """Certificat PEM signé par une racine factice (sujet ≠ émetteur), valide `ttl_seconds`."""
    now = datetime.now(timezone.utc)
    cert = (x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)]))
            .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Double Root")]))
            .public_key(_KEY.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(seconds=30))
            .not_valid_after(now + timedelta(seconds=ttl_seconds))
            .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
            .sign(_KEY, hashes.SHA256()))
    return cert.public_bytes(serialization.Encoding.PEM).decode()


def pki_write(base: dict):
    """Fonction `side_effect` réaliste pour `client.write` (voir docstring du module)."""
    def write(path, **kwargs):
        if path.endswith("/sign-intermediate"):
            return {"data": {"certificate": make_cert(_seconds(kwargs["ttl"]), ca=True,
                                                      cn="Double Intermediate")}}
        if "/issue/" in path:
            data = dict((base or {}).get("data") or {})
            data["certificate"] = make_cert(_seconds(kwargs["ttl"]), ca=False,
                                            cn=kwargs.get("common_name", "leaf"))
            return {"data": data}
        return base
    return write
