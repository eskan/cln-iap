# Docker Compose

[Guide utilisateur](../README.md)

Sur le service Traefik existant, ajouter ces volumes en adaptant les chemins sources :

```yaml
volumes:
  - ./cln-iap:/plugins-local/src/github.com/eskan/cln-iap:ro
  - ./cln_iap_jwt:/run/secrets/cln_iap_jwt:ro
```

Définir les variables communes sur le service Traefik :

```yaml
environment:
  CLN_IAP_CAS_URL: "https://cas.example.org/cas"
  CLN_IAP_COOKIE_DOMAIN: "example.org"
  CLN_IAP_ALLOWED_HOSTS: "app.example.org,outils.example.org"
  CLN_IAP_JWT_SECRET_FILE: "/run/secrets/cln_iap_jwt"
  CLN_IAP_JWT_TTL: "4h"
  CLN_IAP_LOG_LEVEL: "info"
```

Ajouter l’option statique `--experimental.localplugins.cln-iap.modulename=github.com/eskan/cln-iap` aux options existantes, puis redémarrer Traefik. Conserver ses fournisseurs, réseaux, entrypoints et certificats HTTPS.

Sur le service de l’application :

```yaml
labels:
  - "traefik.http.middlewares.mon-app-iap.plugin.cln-iap.allowedLogins=alice,bob"
  - "traefik.http.routers.mon-app.middlewares=mon-app-iap"
```

Le routeur `mon-app` doit exister et couvrir le callback sur le domaine de l’application. Utiliser un nom de middleware distinct par politique d’accès. Voir également [compose.yaml](../compose.yaml), un fragment à intégrer à vos services existants.
