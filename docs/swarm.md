# Installer avec Docker Swarm

[← README](../README.md) · [Variables](configuration.md)

Prérequis : Traefik avec le fournisseur Swarm, un réseau overlay partagé `proxy` et HTTPS configuré.

1. Récupérer [swarm.yaml](../deploy/swarm.yaml). Adapter les domaines, les variables, le réseau et l’entrypoint `websecure`. L’adresse `iap_cln-iap` correspond à la stack `iap` utilisée ci-dessous.
2. Sur un manager, créer le secret une seule fois, puis déployer :

```sh
openssl rand 32 | docker secret create cln_iap_jwt -
docker stack deploy --with-registry-auth -c swarm.yaml iap
docker service logs --tail=50 iap_cln-iap
```

Swarm télécharge `ghcr.io/eskan/cln-iap:latest`. La stack déclare les routes de connexion et le middleware `cas`.

3. Dans les `deploy.labels` du service concerné, ajouter ce label en remplaçant `mon-routeur` par son nom Traefik :

```yaml
- "traefik.http.routers.mon-routeur.middlewares=cas@swarm"
```

Conserver les middlewares existants après `cas@swarm`, puis redéployer la stack de ce service. Ouvrir le site pour vérifier la connexion CAS.
