# Docker Compose

[Guide utilisateur](../README.md) · [Paramètres communs](configuration.md)

## Traefik

Traefik a besoin du répertoire du plugin et du fichier secret qui protège les sessions. Préparer ces fichiers comme indiqué dans le [guide utilisateur](../README.md) ; les volumes ci-dessous les rendent accessibles dans le conteneur, sans les fournir aux applications.

Ajouter ces montages au service Traefik existant, en adaptant les chemins sources :

```yaml
volumes:
  - ./cln-iap:/plugins-local/src/github.com/eskan/cln-iap:ro
  - ./cln_iap_jwt:/run/secrets/cln_iap_jwt:ro
```

Les variables d’environnement indiquent le serveur CAS, les sites partageant la session et l’emplacement du secret dans le conteneur. Adapter ces valeurs au déploiement :

```yaml
environment:
  CLN_IAP_CAS_URL: "https://cas.example.org/cas"
  CLN_IAP_COOKIE_DOMAIN: "example.org"
  CLN_IAP_ALLOWED_HOSTS: "app.example.org,outils.example.org"
  CLN_IAP_JWT_SECRET_FILE: "/run/secrets/cln_iap_jwt"
  CLN_IAP_JWT_TTL: "4h"
  CLN_IAP_LOG_LEVEL: "info"
```

Ajouter `--experimental.localplugins.cln-iap.modulename=github.com/eskan/cln-iap` aux options existantes et redémarrer Traefik. Conserver ses réseaux, fournisseurs et paramètres HTTPS.

## Application

Les labels définissent la règle d’accès puis l’appliquent au routeur. Cet exemple réserve `mon-app` aux logins CAS `alice` et `bob`. Ajouter aux labels du service :

```yaml
labels:
  - "traefik.http.middlewares.mon-app-iap.plugin.cln-iap.allowedLogins=alice,bob"
  - "traefik.http.routers.mon-app.middlewares=mon-app-iap"
```

Le routeur HTTPS doit couvrir `/__cln_iap/callback`. Placer cln-iap avant les réécritures de chemin. Le [fragment Compose](../compose.yaml) regroupe ces réglages ; les [règles LDAP](ldap.md) sont facultatives.
