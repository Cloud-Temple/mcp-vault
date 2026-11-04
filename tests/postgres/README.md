# Contrats publics PostgreSQL de Vault

Les tests logiciels s'exécutent sans service :

```sh
python -m pytest tests/test_postgres_metadata_178.py tests/test_consume_hygiene_78.py
```

Pour les tests réels, installer le produit public et son infrastructure décrite
dans [la documentation](../../docs/postgres-metadata.md). Le compose PostgreSQL
de ce dossier est facultatif ; un serveur externe peut être configuré.
OpenBao, son auth native et sa sauvegarde doivent fonctionner avant SQL.

Les contrats publics ne démarrent ni ne nettoient les services. Fournir
`VAULT_PG_URL`, `VAULT_PG_HTTP_CA`, `VAULT_PG_ADMIN_FILE`,
`VAULT_PG_BOOTSTRAP_FILE`, `VAULT_PG_RESERVED_MOUNT`, `VAULT_PG_RUN_ID` et
`VAULT_PG_PRIVATE_EVIDENCE` (chemin neuf, privé). Les fichiers de tokens et
de preuve restent hors Git. `VAULT_PG_ADMITTED=yes` sélectionne ces tests.

```sh
python -m pytest tests/postgres/test_public_interfaces.py -k 'not final_after_new_process'
```

Après redémarrage réel puis restauration du domaine dans l'infrastructure de
test, relancer dans un processus neuf avec `VAULT_PG_FINAL=yes` :

```sh
python -m pytest tests/postgres/test_public_interfaces.py -k final_after_new_process
```

Constater aussi l'état SQL final, les droits du rôle applicatif et les erreurs
de connexion. Le profil HA exige un standby synchrone réellement obligatoire ;
relire sur celui-ci les mutations confirmées. Couper PG et constater les refus,
puis restaurer Vault/unseal avant de restaurer PG. Un état local après timeout
ne lève aucune incertitude de COMMIT. Aucun service ou dépôt Mission n'est
nécessaire au parcours standalone ; qualifier le profil flotte séparément.
