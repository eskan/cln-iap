# Mesurer les requêtes authentifiées

Avec Docker disponible :

```sh
RUN_TRAEFIK_BENCH=1 go test -run '^$' -bench '^BenchmarkTraefik$' -benchtime=2s -count=3 .
```

Les résultats `without_plugin` et `with_plugin` indiquent le temps de téléchargement complet d’une réponse de 100 Kio via HTTPS, respectivement sans middleware et avec une session valide. Les deux scénarios utilisent la même instance Traefik 3.7.17 et la même application.

Les connexions CAS initiales sont exclues de la mesure. Les résultats concernent l’environnement de la commande et ne représentent pas le chargement d’une page entière.
