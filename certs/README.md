Ce répertoire ne contient aucun certificat ni secret.

Le montage par défaut conserve le démarrage S3 existant ; il n'est pas une CA
PostgreSQL. Pour PostgreSQL, préparer la vraie CA en dehors du dépôt et définir
`PG_CA_FILE` dans le fichier d'interpolation Compose. Le lecteur applicatif
utilise `METADATA_PG_CA_FILE=/run/pg-ca.crt` dans son propre fichier Settings.
