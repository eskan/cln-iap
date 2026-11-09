# Nomad

[Guide utilisateur](../README.md)

Dans la tâche Traefik existante, activer le plugin avec `--experimental.localplugins.cln-iap.modulename=github.com/eskan/cln-iap` et monter :

- Le répertoire du plugin dans `/plugins-local/src/github.com/eskan/cln-iap`.
- Le secret dans `/secrets/cln_iap_jwt`.

Définir les paramètres communs dans le bloc `env` de la tâche Traefik :

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

Le template fournit le secret à `/secrets/cln_iap_jwt` dans le conteneur Traefik. Réserver l’accès à la variable Nomad à la tâche Traefik. Redéployer Traefik après modification de son environnement ; un changement du secret redémarre la tâche. Conserver le fournisseur et les paramètres HTTPS existants. Aucun secret n’est fourni aux applications.

Dans le bloc `service` de l’application, enregistré avec `provider = "nomad"`, ajouter aux tags existants :

```hcl
tags = [
  "traefik.http.middlewares.mon-app-iap.plugin.cln-iap.allowedLogins=alice,bob",
  "traefik.http.routers.mon-app.middlewares=mon-app-iap",
]
```

Le service applicatif ne reçoit aucun secret cln-iap. Le routeur doit couvrir le domaine de l’application et son callback `/__cln_iap/callback`. Pour une application sous un préfixe, ajouter le routeur de callback décrit dans le guide utilisateur.
