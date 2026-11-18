# Mesurer les requêtes authentifiées

[Performances](../docs/benchmark.md)

Cette mesure compare le téléchargement d’une même réponse avec et sans protection CAS, sur une session déjà connectée. Elle aide à évaluer le coût du middleware dans votre environnement ; elle ne mesure ni la connexion initiale ni les contrôles LDAP.

Avec Go et Docker disponibles, lancer depuis la racine du dépôt :

```sh
RUN_TRAEFIK_BENCH=1 go test -run '^$' -bench '^BenchmarkTraefik$' -benchtime=2s -count=3 .
```

| Résultat | Mesure |
| --- | --- |
| `without_plugin` | Téléchargement HTTPS d’une réponse de 100 Kio sans middleware. |
| `with_plugin` | Même téléchargement avec une session CAS valide, sans restriction LDAP. |

Les deux scénarios utilisent la même instance Traefik et la même application. La connexion CAS initiale est exclue. Les résultats reflètent l’environnement local et le téléchargement complet de la réponse, pas le chargement d’une page entière.
