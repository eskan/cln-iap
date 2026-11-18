# Performances

[Guide utilisateur](../README.md)

CAS est sollicité à la connexion, puis la session reste utilisable sans nouvel appel jusqu’à son expiration. Si LDAP est activé, il est consulté au premier accès et au renouvellement de l’autorisation, selon `authorizationTTL`.

Une durée d’autorisation LDAP plus courte prend en compte les retraits de droits plus rapidement, mais augmente les appels à l’annuaire.

Pour mesurer les requêtes avec une session CAS valide, suivre le [guide de mesure](../benchmarks/README.md). Les temps de connexion CAS et de contrôle LDAP sont distincts.
