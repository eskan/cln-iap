# Performances

[Guide utilisateur](../README.md)

CAS est sollicité à la connexion, puis la session reste utilisable sans nouvel appel jusqu’à son expiration. Si LDAP est activé, il est consulté au premier accès et au renouvellement de l’autorisation, selon `authorizationTTL`.

Une durée d’autorisation LDAP plus courte prend en compte les retraits de droits plus rapidement, mais augmente les appels à l’annuaire.

## Mesurer les requêtes authentifiées

Le benchmark compare le téléchargement d’une même réponse avec et sans protection CAS, sur une session déjà connectée. Il permet d’évaluer le coût du middleware dans votre environnement ; il ne mesure ni la connexion initiale ni les contrôles LDAP.

Avec Go et Docker disponibles, lancer depuis la racine du dépôt :

```sh
RUN_TRAEFIK_BENCH=1 go test -run '^$' -bench '^BenchmarkTraefik$' -benchtime=2s -count=3 .
```

| Résultat | Mesure |
| --- | --- |
| `without_plugin` | Téléchargement HTTPS d’une réponse de 100 Kio sans middleware. |
| `with_plugin` | Même téléchargement avec une session CAS valide, sans restriction LDAP. |

Les deux scénarios utilisent la même instance Traefik et la même application. Les résultats reflètent l’environnement local et le téléchargement complet de la réponse, pas le chargement d’une page entière.
