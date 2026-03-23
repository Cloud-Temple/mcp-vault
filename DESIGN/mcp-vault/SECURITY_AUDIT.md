# Rapport d'Audit de Sécurité — MCP Vault

**Date:** 23 Mars 2026
**Version de l'application:** 0.2.0
**Objectif:** Analyse complète de la posture de sécurité (Authentification, Cryptographie, Architecture, WAF)

---

## 🟢 1. Points Forts de l'Architecture

### 1.1 Architecture de Sécurité (Zero Trust Policy)
- **Zero-Trust par défaut:** Un token sans policy n'a pas accès total par défaut. Les contrôles sont appliqués à chaque niveau.
- **Défense en Profondeur (DiD):** L'application utilise 3 niveaux d'isolation : Owner-based (Vault), Policy-based (Tools), Path-based (Wildcards).
- **Audit Logging Intégré:** Toutes les actions MCP génèrent des événements d'audit détaillés avec catégorisation et statut explicite, renforçant la traçabilité.

### 1.2 Cryptographie
- **Algorithmes Robustes:** Le chiffrement des clés d'unseal d'OpenBao est réalisé avec **AES-256-GCM**, offrant confidentialité et intégrité.
- **Dérivation de clé (KDF):** L'utilisation de **PBKDF2-HMAC-SHA256 (600 000 itérations)** protège efficacement la master key contre les attaques par force brute.
- **Génération CSPRNG:** Le générateur de mots de passe (`types.py`) utilise `secrets.choice`, un générateur de nombres pseudo-aléatoires cryptographiquement sûr.

### 1.3 Authentification & Tokens
- **Stockage sous forme de hash:** Les tokens de l'API (bearer tokens) sont stockés sous forme de hash (SHA-256). Une éventuelle fuite de la base/S3 ne compromet pas les jetons d'accès réels.

---

## 🔴 2. Vulnérabilités Critiques (High/Critical)

### 2.1 Arbitrary File Read (Local File Inclusion - LFI) 
**Localisation:** `src/mcp_vault/admin/middleware.py` (Lignes 44-48)
**Sévérité:** 🔴 Critique

**Détails:**
La route de traitement des fichiers statiques d'administration (`/admin/static/`) empêche le directory traversal basique (`..`), mais reste vulnérable aux chemins absolus.
```python
rel = path[len("/admin/static/"):]
if ".." in rel:
    return await self._error(send, 403, "Forbidden")
return await self._serve_file(send, rel)

# Plus loin dans _serve_file :
filepath = self.static_dir / filename # où filename est rel
```
En Python `pathlib`, concaténer un chemin de base avec un chemin absolu annule le chemin de base.
Exemple : `Path("/app/static") / "/etc/passwd"` résout directement vers `/etc/passwd`.
**Impact:** Un attaquant distant non authentifié peut lire n'importe quel fichier sur le système, y compris `.env`, code source ou clés SSH.

**Remédiation:**
Appliquer `Path.resolve()` et vérifier que le fichier résultant est un enfant direct du répertoire `static_dir`.
```python
filepath = (self.static_dir / filename).resolve()
if not str(filepath).startswith(str(self.static_dir.resolve())):
    return await self._error(send, 403, "Forbidden")
```

### 2.2 Faux sentiment de sécurité sur le WAF (Coraza manquant)
**Localisation:** `waf/Dockerfile`, `waf/Caddyfile`
**Sévérité:** 🔴 Élevé

**Détails:**
Bien que la documentation et les commentaires de l'infrastructure parlent de "WAF Caddy + Coraza (OWASP CRS)", le Dockerfile utilise uniquement l'image de base `caddy:2-alpine`. Coraza n'est ni installé via `xcaddy` ni configuré dans le `Caddyfile`. L'application est en réalité exposée sans pare-feu applicatif.
**Impact:** L'application est sans protection contre les attaques L7 courantes (SQLi, Injection, DDoS applicatif) prévues initialement dans le design.

**Remédiation:**
Utiliser un conteneur Caddy builder (avec `xcaddy`) pour compiler Caddy avec le plugin `coraza-caddy`, ou utiliser une image pré-compilée, et inclure les directives `coraza_waf` dans le Caddyfile.

---

## 🟠 3. Vulnérabilités Moyennes (Medium)

### 3.1 Risques de fuite de Token via Query Parameter
**Localisation:** `src/mcp_vault/auth/middleware.py`
**Sévérité:** 🟠 Moyen

**Détails:**
Le middleware d'authentification vérifie à la fois l'en-tête `Authorization` ET les paramètres d'URL (ex: `?token=...`).
Les URLs sont souvent journalisées en clair dans l'infrastructure (logs Caddy, CloudTrail, Proxy tiers, historique navigateur).
**Impact:** Un jeton d'accès peut être intercepté passivament par la lecture des logs.

**Remédiation:**
Supprimer l'authentification par paramètre d'URL (`query_string`). Seul l'en-tête `Authorization: Bearer <token>` doit être autorisé.

### 3.2 Défaut de nettoyage mémoire des Clés Maîtresses (Zeroing)
**Localisation:** `src/mcp_vault/openbao/crypto.py`
**Sévérité:** 🟠 Moyen

**Détails:**
La clé `bootstrap_key`, ainsi que les clés dérivées, sont manipulées en tant que `str` et `bytes` (types immuables en Python). Le garbage collector de Python ne permet pas le nettoyage cryptographique (zeroing) immédiat de la mémoire RAM une fois les clés utilisées.
**Impact:** En cas de dump de la mémoire RAM (par ex. exploit ou crash dump d'une attaque annexe), la clé de déchiffrement des secrets OpenBao peut être récupérée.

**Remédiation:**
Utiliser un `bytearray` pour stocker les clés et effectuer un écrasement (zero-fill) mémoire explicite une fois la cryptographie appliquée (ex: `for i in range(len(key)): key[i] = 0`), bien que l'implémentation CPython puisse rendre cela complexe sans bibliothèque externe comme `ctypes` ou une lib C.

### 3.3 Faible validation d'entropie de la clé Bootstrap
**Localisation:** `src/mcp_vault/openbao/crypto.py`
**Sévérité:** 🟡 Faible (mais crucial pour la robustesse crypto)

**Détails:**
La méthode `encrypt_with_bootstrap_key` vérifie que la taille de la clé est au moins de 16 caractères (`len(bootstrap_key) < 16`), mais n'évalue pas l'entropie ni la complexité de celle-ci (ex: une clé "1111111111111111" passera ce contrôle).
**Impact:** Le chiffrement AES-GCM-256 repose sur un KDF PBKDF2. Si la passphrase est faible, elle reste vulnérable à des attaques par dictionnaire ciblées sur S3.

**Remédiation:**
Implémenter une vérification stricte de l'entropie de la passphrase au démarrage du service (ex: via la bibliothèque `zxcvbn` ou un regex exigeant des majuscules/minuscules/chiffres/symboles).

---

## 📝 4. Résumé et Plan d'Action Recommandé

L'architecture conceptuelle de `MCP Vault` est excellente et répond aux standards zero-trust avec une gestion pointue des politiques (Policies/Paths/Owner).

Cependant, l'implémentation actuelle souffre de défauts qui doivent être corrigés immédiatement (avant de quitter l'étape `rc1`) :
1. **[URGENT]** Patcher le `AdminMiddleware` pour bloquer la vulnérabilité Arbitrary File Read (LFI).
2. **[URGENT]** Mettre à jour l'image Docker WAF pour inclure et activer réellement Coraza.
3. **[IMPORTANT]** Supprimer l'authentification `?token=` du `AuthMiddleware`.
4. Évaluer l'intégration de variables d'environnement restrictives pour assurer l'entropie des clés de base.

Le projet est en très bonne voie, la sécurité architecturale est présente, la surface d'attaque identifiée est liée à des détails d'implémentation corrigibles rapidement.