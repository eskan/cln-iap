# Nomad

[Guide utilisateur](../README.md) · [Paramètres communs](configuration.md)

## Traefik

La tâche Traefik reçoit le plugin, les paramètres CAS et le secret commun aux sessions. Dans cet exemple, le secret est conservé dans le champ `jwt_secret` de la variable Nomad `nomad/jobs/traefik`, puis fourni à Traefik sous forme de fichier.

Préparer le plugin et le secret selon le [guide utilisateur](../README.md), puis renseigner cette variable avec un accès réservé à la tâche Traefik.

Dans la tâche Traefik, monter le plugin en lecture seule dans `/plugins-local/src/github.com/eskan/cln-iap` et ajouter l’option `--experimental.localplugins.cln-iap.modulename=github.com/eskan/cln-iap`.

Définir les paramètres et fournir le secret avec une variable Nomad réservée à Traefik :

```hcl
env {
  CLN_IAP_CAS_URL         = "https://cas.example.org/cas"
  CLN_IAP_COOKIE_DOMAIN   = "example.org"
  CLN_IAP_ALLOWED_HOSTS   = "app.example.org,outils.example.org"
  CLN_IAP_JWT_SECRET_FILE = "/secrets/cln_iap_jwt"
  CLN_IAP_JWT_TTL         = "4h"
  CLN_IAP_LOG_LEVEL       = "info"
}

template {
  destination          = "secrets/cln_iap_jwt"
  perms                = "0400"
  change_mode          = "restart"
  error_on_missing_key = true
  data                 = "{{ with nomadVar \"nomad/jobs/traefik\" }}{{ .jwt_secret }}{{ end }}"
}
```

Rendre `/secrets/cln_iap_jwt` accessible dans le conteneur Traefik. Redéployer après modification de l’environnement ; un changement du secret redémarre la tâche.

## Application

Les tags déclarent le middleware et l’associent au routeur de l’application. Cet exemple limite l’accès aux logins CAS `alice` et `bob`.

Dans le bloc `service` enregistré avec `provider = "nomad"`, ajouter aux tags :

```hcl
tags = [
  "traefik.http.middlewares.mon-app-iap.plugin.cln-iap.allowedLogins=alice,bob",
  "traefik.http.routers.mon-app.middlewares=mon-app-iap",
]
```

Le routeur HTTPS doit couvrir `/__cln_iap/callback`, avec cln-iap avant les réécritures de chemin. Pour une application sous un préfixe, adapter la [règle de routage](traefik.md). Les [règles LDAP](ldap.md) sont facultatives.
