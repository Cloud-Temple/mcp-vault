# Rapport d'Audit de Sécurité — MCP Vault

**Date de l'audit initial :** 23 Mars 2026 (v0.2.0)
**Date de mise à jour :** 24 Mars 2026 (v0.3.3)
**Auditeur :** Cline (Opus)
**Fichiers analysés :** 19 fichiers source critiques
**Objectif :** Analyse complète de la posture de sécurité (Authentification, Cryptographie, Architecture, WAF)

---

## 🟢 1. Points Forts de l'Architecture

### 1.1 Architecture de Sécurité (Zero Trust Policy)
- **Zero-Trust par défaut :** Un token sans policy n'a pas accès total par défaut. Les contrôles sont appliqués à chaque niveau.
- **Défense en Profondeur (DiD) :** L'application utilise 3 niveaux d'isolation : Owner-based (Vault), Policy-based (Tools), Path-based (Wildcards).
- **Audit Logging Intégré :** Toutes les actions MCP génèrent des événements d'audit détaillés avec catégorisation et statut explicite, renforçant la traçabilité.

### 1.2 Cryptographie
- **Algorithmes Robustes :** Le chiffrement des clés d'unseal d'OpenBao est réalisé avec **AES-256-GCM**, offrant confidentialité et intégrité.
- **Dérivation de clé (KDF) :** L'utilisation de **PBKDF2-HMAC-SHA256 (600 000 itérations)** protège efficacement la master key contre les attaques par force brute.
- **Génération CSPRNG :** Le générateur de mots de passe (`types.py`) utilise `secrets.choice`, un générateur de nombres pseudo-aléatoires cryptographiquement sûr.
- **Zeroing mémoire :** Les clés dérivées sont stockées en `bytearray` (mutable) et effacées explicitement après usage via `_zero_fill()`.

### 1.3 Authentification & Tokens
- **Stockage sous forme de hash :** Les tokens de l'API (bearer tokens) sont stockés sous forme de hash (SHA-256). Une éventuelle fuite de la base/S3 ne compromet pas les jetons d'accès réels.
- **Bearer-only :** Seul le header `Authorization: Bearer <token>` est accepté. L'auth par query string a été supprimée (v0.3.1).
- **Validation de la bootstrap key :** Complexité validée au démarrage (32+ chars, 3/4 classes de caractères, patterns faibles détectés).

### 1.4 WAF Opérationnel
- **Caddy + Coraza** compilé via `xcaddy` avec `coraza-caddy v2.2.0`.
- **OWASP CRS v4.7.0** chargé en mode blocking complet.
- **Headers de sécurité :** CSP, X-Frame-Options DENY, X-Content-Type-Options nosniff, Referrer-Policy.
- **Fine-tuning :** 2 exclusions ciblées documentées (règles 920540, 932120) pour les faux positifs JSON-RPC.

---

## 📋 2. Historique — Audit v0.2.0 (23 Mars 2026)

Les 5 vulnérabilités identifiées lors du premier audit ont **toutes été corrigées** dans les versions v0.3.1 à v0.3.3 :

| #   | Sévérité     | Vulnérabilité                                    | Statut     | Version |
| --- | ------------ | ------------------------------------------------ | ---------- | ------- |
| 2.1 | 🔴 Critique | LFI dans `admin/middleware.py` — chemins absolus | ✅ Corrigé | v0.3.1  |
| 2.2 | 🔴 Élevé    | Faux WAF — Coraza absent du Dockerfile           | ✅ Corrigé | v0.3.1  |
| 3.1 | 🟠 Moyen    | Fuite de token via `?token=` query string        | ✅ Corrigé | v0.3.1  |
| 3.2 | 🟠 Moyen    | Zeroing mémoire insuffisant (types immuables)    | ✅ Corrigé | v0.3.1  |
| 3.3 | 🟡 Faible   | Entropie bootstrap key non validée               | ✅ Corrigé | v0.3.1  |

**Correctifs appliqués :**
- LFI : `Path.resolve()` + vérification `startswith(static_dir.resolve())`
- WAF : multi-stage build `xcaddy` + coraza-caddy + OWASP CRS v4
- Auth : suppression du fallback `?token=`, Bearer-only
- Zeroing : `bytearray` + `_zero_fill()` dans `crypto.py`
- Entropie : `validate_bootstrap_key()` (32 chars min, 3/4 classes, patterns faibles)

---

## 🔴 3. Vulnérabilités Critiques — Audit v0.3.3

### 3.1 Admin API contourne les contrôles d'accès vault
**Localisation :** `src/mcp_vault/admin/api.py` — routes `_api_vault_detail`, `_api_read_secret`, `_api_write_secret`, `_api_delete_secret`
**Sévérité :** 🔴 Critique

**Détails :**
Les routes de l'API REST admin vérifient les *permissions* du token (read/write/admin) mais **ne vérifient PAS** `check_access(vault_id)`. Les contrôles d'isolation (owner-based, `allowed_resources`, policies) sont totalement contournés.

Exemple : un token avec `allowed_resources=["vault-a"]` peut lire les secrets de `vault-b` via `GET /admin/api/vaults/vault-b/secrets/my-secret`.

Seul `vault_list` filtre correctement par propriétaire/ressources autorisées.

**Impact :** Escalade de privilèges horizontale. Tout agent IA avec un token restreint peut accéder à **tous** les coffres via l'API admin.

**Remédiation :**
Ajouter la vérification `check_access(vault_id)` et `check_path_policy()` dans chaque route vault/secret de l'API admin, similaire aux outils MCP dans `server.py`.

### 3.2 Timing attack sur la comparaison de la bootstrap key
**Localisation :** 3 occurrences :
- `src/mcp_vault/auth/middleware.py` L145 : `if token == settings.admin_bootstrap_key`
- `src/mcp_vault/admin/api.py` L308 : `if token == settings.admin_bootstrap_key`
- `src/mcp_vault/admin/api.py` L322 : `if token == settings.admin_bootstrap_key`

**Sévérité :** 🔴 Critique

**Détails :**
La comparaison de chaînes `==` en Python n'est **pas constant-time**. Elle s'arrête au premier caractère différent. Un attaquant peut mesurer les temps de réponse pour déduire la bootstrap key caractère par caractère (attaque côté canal temporel).

**Impact :** Compromission potentielle de la clé maîtresse admin si l'attaquant peut effectuer des mesures fines (réseau local, pas de WAF avec jitter).

**Remédiation :**
Remplacer par `hmac.compare_digest(token, settings.admin_bootstrap_key)` (constant-time).

### 3.3 Path traversal via tarfile dans le S3 sync
**Localisation :** `src/mcp_vault/s3_sync.py` L49

**Sévérité :** 🔴 Critique

**Détails :**
```python
with tarfile.open(fileobj=io.BytesIO(archive_bytes), mode="r:gz") as tar:
    tar.extractall(path=str(data_dir))
```
`tarfile.extractall()` sans filtre est un pattern CVE bien connu (CVE-2007-4559). Si le bucket S3 est compromis, une archive malveillante peut contenir des entrées comme `../../etc/cron.d/backdoor`, écrivant des fichiers arbitraires en dehors du `data_dir`.

**Impact :** Exécution de code arbitraire si le bucket S3 est compromis.

**Remédiation :**
Python 3.12+ : utiliser `tar.extractall(path=..., filter='data')` qui bloque les chemins dangereux, les symlinks et les devices.

---

## 🟠 4. Vulnérabilités Élevées — Audit v0.3.3

### 4.1 CORS wildcard sur toute l'API admin
**Localisation :** `src/mcp_vault/admin/api.py` (toutes les réponses), `src/mcp_vault/admin/middleware.py` (preflight)
**Sévérité :** 🟠 Élevé

**Détails :**
Le header `Access-Control-Allow-Origin: *` est présent sur **toutes** les réponses de l'API admin. Cela permet à n'importe quel site web de faire des requêtes authentifiées (cross-origin) vers l'API si l'utilisateur/agent possède un token.

**Impact :** Un site malveillant visité par un administrateur pourrait exfiltrer des secrets ou créer des tokens via JavaScript.

**Remédiation :**
Supprimer le header CORS des réponses API, ou le restreindre à l'origine exacte du SPA admin.

### 4.2 Aucun rate limiting
**Localisation :** `waf/Caddyfile`, middlewares ASGI
**Sévérité :** 🟠 Élevé

**Détails :**
Aucune limitation de débit n'est configurée — ni dans le WAF Caddy, ni dans les middlewares applicatifs. Un attaquant peut :
- Brute-forcer la bootstrap key sans limite
- Tenter des tokens par dictionnaire
- Lancer un DoS applicatif par requêtes massives

**Remédiation :**
Ajouter `rate_limit` dans le Caddyfile (ex: 100 req/s par IP) et/ou un middleware applicatif pour les endpoints sensibles.

### 4.3 Fail-open sur policy supprimée
**Localisation :** `src/mcp_vault/auth/policies.py` — `is_tool_allowed()` retourne `True` si policy inexistante
**Sévérité :** 🟠 Élevé

**Détails :**
Si un admin supprime une policy référencée par des tokens existants, ces tokens deviennent **totalement non-restreints** (plus de limitation d'outils). Aucun avertissement n'est émis, aucune invalidation des tokens liés.

**Impact :** Élévation silencieuse de privilèges pour tous les tokens qui référencent la policy supprimée.

**Remédiation :**
Option A : Fail-close (bloquer les tokens avec policy invalide).
Option B : Empêcher la suppression d'une policy si des tokens la référencent.
Option C : Logger un événement d'audit critique et notifier l'admin.

### 4.4 Lecture du body HTTP sans limite de taille
**Localisation :** `src/mcp_vault/admin/api.py` — `_read_body()`
**Sévérité :** 🟠 Élevé

**Détails :**
```python
async def _read_body(receive) -> bytes:
    body = b""
    while True:
        message = await receive()
        body += message.get("body", b"")
        if not message.get("more_body", False):
            break
    return body
```
Le body est accumulé en mémoire sans plafond. Un attaquant peut envoyer un body de plusieurs GB.

**Impact :** Out-Of-Memory (OOM) du processus, déni de service.

**Remédiation :**
Ajouter une limite (ex: 10 MB max) et retourner 413 Payload Too Large si dépassée.

---

## 🟡 5. Vulnérabilités Moyennes — Audit v0.3.3

### 5.1 Aucune validation de `vault_id` dans l'Admin API
**Localisation :** `src/mcp_vault/admin/api.py` — `_api_create_vault()`
**Sévérité :** 🟡 Moyen

Le `vault_id` est passé directement comme mount path OpenBao sans validation de format. Des caractères spéciaux ou des chemins relatifs pourraient créer des mount paths dangereux.

**Remédiation :** Valider le format (alphanumérique + tirets, max 64 chars) avant de le passer à OpenBao.

### 5.2 CSP permet `unsafe-inline`
**Localisation :** `waf/Caddyfile`
**Sévérité :** 🟡 Moyen

`script-src 'self' 'unsafe-inline'` et `style-src 'self' 'unsafe-inline'` affaiblissent significativement la Content Security Policy. Un XSS stocké pourrait exécuter des scripts inline.

**Remédiation :** Migrer vers des nonces ou hashes CSP pour les scripts/styles inline du SPA.

### 5.3 Aucune limite de ressources Docker
**Localisation :** `docker-compose.yml`
**Sévérité :** 🟡 Moyen

Pas de `mem_limit` ni `cpus` dans la configuration Docker Compose. Un DoS peut consommer toutes les ressources de l'hôte.

**Remédiation :** Ajouter `deploy.resources.limits` (ex: 2 GB RAM, 2 CPUs).

### 5.4 Race conditions sur les stores S3
**Localisation :** `src/mcp_vault/auth/token_store.py`, `src/mcp_vault/auth/policies.py`
**Sévérité :** 🟡 Moyen

Les opérations `_save()` concurrentes (deux requêtes modifiant des tokens simultanément) peuvent provoquer une perte de données (last-writer-wins sur S3).

**Remédiation :** Ajouter un verrou asyncio (`asyncio.Lock`) ou utiliser le versioning S3 avec des conditions ETags.

### 5.5 Clés unseal (strings) restent en mémoire après déréférencement
**Localisation :** `src/mcp_vault/openbao/lifecycle.py`
**Sévérité :** 🟡 Moyen

`_in_memory_keys = None` ne fait que déréférencer le dict. Les strings Python (`root_token`, clés unseal) sont immuables et restent en RAM jusqu'au garbage collector. Le zeroing `bytearray` dans `crypto.py` est correct, mais les clés dans le dict sont des `str` non effaçables.

**Remédiation :** Limitation inhérente à Python — documenter comme risque résiduel. Envisager un wrapper C/ctypes pour le stockage en mémoire sécurisée.

---

## ℹ️ 6. Vulnérabilités Informationnelles — Audit v0.3.3

| #   | Problème                                                                             | Localisation                           |
| --- | ------------------------------------------------------------------------------------ | -------------------------------------- |
| 6.1 | Logs d'audit (JSONL) non synchronisés vers S3 — perte si volume Docker détruit       | `audit.py`                             |
| 6.2 | Pas de TLS entre WAF et MCP dans le réseau Docker interne                            | `docker-compose.yml`                   |
| 6.3 | Shamir shares=1, threshold=1 — pas de secret sharing réel (acceptable pour embedded) | `config.py`                            |
| 6.4 | Messages d'erreur exposent des détails internes OpenBao via `str(e)`                 | `secrets.py`, `spaces.py`, `ssh_ca.py` |
| 6.5 | SSH CA `allowed_users="*"` par défaut — trop permissif                               | `ssh_ca.py`                            |
| 6.6 | Bootstrap key faible : le service démarre quand même (warning non bloquant)          | `lifecycle.py`                         |

---

## 📊 7. Synthèse

### Matrice des vulnérabilités

| Sévérité     | Audit v0.2.0 | Corrigé  | Audit v0.3.3 |
| ------------ | :----------: | :------: | :----------: |
| 🔴 Critique |      2       |   2 ✅   |    **3**     |
| 🟠 Élevé    |      1       |   1 ✅   |    **4**     |
| 🟡 Moyen    |      2       |   2 ✅   |    **5**     |
| ℹ️ Info     |      0       |    —     |    **6**     |
| **Total**    |    **5**     | **5 ✅** |    **18**    |

### Plan d'action recommandé

| Priorité | Action                               | Effort |
| -------- | ------------------------------------ | ------ |
| 🔴 P0   | Corriger l'Admin API bypass (§3.1)   | ~1h    |
| 🔴 P0   | Corriger le timing attack (§3.2)     | ~15min |
| 🔴 P0   | Corriger le tarfile traversal (§3.3) | ~10min |
| 🟠 P1   | Restreindre CORS (§4.1)              | ~15min |
| 🟠 P1   | Ajouter rate limiting WAF (§4.2)     | ~30min |
| 🟠 P1   | Fail-close sur policies (§4.3)       | ~30min |
| 🟠 P1   | Limiter la taille du body (§4.4)     | ~10min |
| 🟡 P2   | Valider vault_id (§5.1)              | ~15min |
| 🟡 P2   | Limites Docker (§5.3)                | ~5min  |
| 🟡 P2   | Verrou asyncio stores (§5.4)         | ~30min |
