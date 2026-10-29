# Installer avec Docker Compose

[← README](../README.md) · [Variables](configuration.md)

Prérequis : Traefik avec le fournisseur Docker, un réseau partagé `proxy` et HTTPS configuré.

1. Récupérer [compose.yaml](../compose.yaml). Adapter les domaines, les variables, le réseau `proxy` et l’entrypoint `websecure`.
2. Dans le même répertoire, créer le secret une seule fois :

```sh
mkdir -m 700 secrets
openssl rand -out secrets/jwt_secret 32
chmod 444 secrets/jwt_secret
```

Le répertoire privé protège le fichier ; les droits permettent au conteneur de le lire. Ne pas le versionner.

3. Télécharger l’image et démarrer cln-iap :

```sh
docker compose pull
docker compose up -d
docker compose logs --tail=50 cln-iap
```

Le fichier déclare déjà les routes de connexion et le middleware `cas`. Dans les labels du service concerné, ajouter ce label en remplaçant `mon-routeur` par son nom Traefik :

```yaml
- "traefik.http.routers.mon-routeur.middlewares=cas@docker"
```

Conserver les middlewares existants après `cas@docker`, puis relancer `docker compose up -d` pour ce service. Ouvrir le site pour vérifier la connexion CAS.
