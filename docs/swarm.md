# Docker Swarm

[Guide utilisateur](../README.md) · [Paramètres communs](configuration.md)

## Traefik

Chaque réplica Traefik doit disposer du plugin, des mêmes paramètres CAS et d’un secret commun pour protéger les sessions. Préparer le répertoire du plugin et le fichier `cln_iap_jwt` selon le [guide utilisateur](../README.md).

Monter le plugin en lecture seule dans `/plugins-local/src/github.com/eskan/cln-iap` sur chaque nœud pouvant accueillir Traefik. Ajouter l’option `--experimental.localplugins.cln-iap.modulename=github.com/eskan/cln-iap`.

Créer le secret à partir du fichier administrateur :

```sh
docker secret create cln_iap_jwt ./cln_iap_jwt
```

L’attacher uniquement au service Traefik, à `/run/secrets/cln_iap_jwt`, et définir `CLN_IAP_JWT_SECRET_FILE` avec ce chemin. Intégrer les variables et montages du [fragment de stack](../deploy/swarm.yaml) à la configuration existante.

Activer le fournisseur Swarm et HTTPS. Après modification des variables ou remplacement du secret, redéployer tous les réplicas avec les mêmes paramètres.

## Application

Les règles d’accès sont déclarées sur le service applicatif et associées à son routeur. Cet exemple autorise seulement les logins CAS `alice` et `bob`. Placer les labels sous `deploy.labels` :

```yaml
deploy:
  labels:
    - "traefik.http.middlewares.mon-app-iap.plugin.cln-iap.allowedLogins=alice,bob"
    - "traefik.http.routers.mon-app.middlewares=mon-app-iap"
```

Conserver les labels de routage et de port. Le routeur HTTPS doit couvrir `/__cln_iap/callback`, avec cln-iap avant les réécritures de chemin. Les [règles LDAP](ldap.md) sont facultatives.
