# Docker Swarm

[Guide utilisateur](../README.md)

Activer le plugin sur chaque réplica Traefik. Monter ses fichiers à `/plugins-local/src/github.com/eskan/cln-iap` et le fichier administrateur à `/etc/traefik/cln-iap.json`. Les fichiers doivent être disponibles sur chaque nœud pouvant accueillir Traefik.

Créer un secret Swarm depuis le fichier administrateur de secret :

```sh
docker secret create cln_iap_jwt ./cln_iap_jwt
```

Attacher ce secret au service Traefik, à `/run/secrets/cln_iap_jwt`, et renseigner ce chemin dans `jwtSecretFile`. Les services applicatifs ne reçoivent pas ce secret.

Sur le service applicatif existant, placer les labels dans `deploy.labels` :

```yaml
deploy:
  labels:
    - "traefik.http.middlewares.mon-app-iap.plugin.cln-iap.allowedLogins=alice,bob"
    - "traefik.http.routers.mon-app.middlewares=mon-app-iap"
```

Conserver les labels de routage et de port existants. Le fournisseur Swarm et HTTPS doivent être activés dans Traefik. Adapter le [fragment de stack](../deploy/swarm.yaml) ; ajouter l’option statique du plugin sans remplacer les options Traefik existantes.
