# Docker Compose

[Guide utilisateur](../README.md)

Sur le service Traefik existant, ajouter ces volumes en adaptant les chemins sources :

```yaml
volumes:
  - ./cln-iap:/plugins-local/src/github.com/eskan/cln-iap:ro
  - ./cln-iap.json:/etc/traefik/cln-iap.json:ro
  - ./cln_iap_jwt:/run/secrets/cln_iap_jwt:ro
```

Ajouter l’option statique `--experimental.localplugins.cln-iap.modulename=github.com/eskan/cln-iap` aux options existantes, puis redémarrer Traefik. Conserver ses fournisseurs, réseaux, entrypoints et certificats HTTPS.

Sur le service de l’application :

```yaml
labels:
  - "traefik.http.middlewares.mon-app-iap.plugin.cln-iap.allowedLogins=alice,bob"
  - "traefik.http.routers.mon-app.middlewares=mon-app-iap"
```

Le routeur `mon-app` doit exister et couvrir le callback sur le domaine de l’application. Utiliser un nom de middleware distinct par politique d’accès. Voir également [compose.yaml](../compose.yaml), un fragment à intégrer à vos services existants.
