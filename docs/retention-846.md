# Protection de rétention Mission #846 — tranche SQL préparatoire

Extension explicite pour un domaine neuf : `AUDIT_MISSION_RETENTION_ENABLED=true`
avec profil PostgreSQL et politique d'audit d'au moins365jours. L'opérateur
schema-init installe001,002 puis003 dans sa transaction owner. L'app ne fait aucun
DDL. Le profil par défaut reste v2 ; activer ce réglage sur une v2 déjà installée
refuse la disponibilité plutôt que prétendre une protection absente.

V3 inscrit une protection `(instance,tenant,Mission)` avant le succès d'une
admission audit corrélée. Inconnue/active, elle protège l'audit même au-delà de son
expires_at brut. Les dates d'origine restent immuables. Une corrélation incomplète
reste protégée, jamais standalone. Les appels sans Mission gardent179 autonome.

Seul le LOGIN de maintenance peut exécuter clôture/statut/purge bornée. L'app n'a
aucun droit direct sur la table des protections ni EXECUTE sur ces fonctions ;
maintenance n'a aucun DML direct. Admission, clôture et purge prennent le même
verrou de scope, puis les lignes, avec horloge PG fraîche après attente. La clôture
est immuable, au moins fin canonique+365j. L'autorité courte expire au plus30s,
recontrôlée après les verrous ; son hash stable est distinct du JWT en vol. Une
nouvelle admission sur la corrélation fermée est refusée. La tombstone reste.

La purge sélectionne d'abord ses candidats admissibles pour qu'un appel ancien
protégé n'affame pas les scopes autonomes. Le reçu179 est créé dans la même
transaction ; un statut lu ne reconstruit jamais l'ACK perdu. Le wrapper historique
audit_expire conserve son contrat ; bound cible exactement un tenant/Mission.
La désactivation de la coordination ne retire pas les gardes SQL installées.

**Non livré :** signature/vérification/callback du reçu Mission, raccord opérateur
public, tests PG neufs/locks/ACL, puis flotte après livraison390/845. Aucun bearer
app/hub ne reçoit une capacité maintenance. Aucun GC OpenBao ni domaine activé.
