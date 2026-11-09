# Nomad

[Guide utilisateur](../README.md)

Dans la tâche Traefik existante, activer le plugin avec `--experimental.localplugins.cln-iap.modulename=github.com/eskan/cln-iap` et monter :

- Le répertoire du plugin dans `/plugins-local/src/github.com/eskan/cln-iap`.
- La configuration administrateur dans `/etc/traefik/cln-iap.json`.
- Le secret dans `/run/secrets/cln_iap_jwt`.

Distribuer la configuration et le secret uniquement à la tâche Traefik, avec les permissions Nomad/Vault de l’administrateur. `jwtSecretFile` référence le chemin du secret à l’intérieur de Traefik. Conserver les options du fournisseur Nomad et les paramètres HTTPS.

Dans le bloc `service` de l’application, enregistré avec `provider = "nomad"`, ajouter aux tags existants :

```hcl
tags = [
  "traefik.http.middlewares.mon-app-iap.plugin.cln-iap.allowedLogins=alice,bob",
  "traefik.http.routers.mon-app.middlewares=mon-app-iap",
]
```

Le service applicatif ne reçoit aucun secret cln-iap. Le routeur doit couvrir le domaine de l’application et son callback `/__cln_iap/callback`. Pour une application sous un préfixe, ajouter le routeur de callback décrit dans le guide utilisateur.
