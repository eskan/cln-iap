# Configuration de cln-iap

[← README](../README.md)

Les fichiers de déploiement utilisent `ghcr.io/eskan/cln-iap:latest`. Adapter ces variables avant installation :

| Variable | Valeur d’exemple / rôle |
| --- | --- |
| `CAS_URL` | `https://cas.example.org/cas` — serveur CAS |
| `AUTH_URL` | `https://auth.example.org` — adresse publique de cln-iap |
| `COOKIE_DOMAIN` | `example.org` — domaine commun aux sites et à cln-iap |
| `ALLOWED_HOSTS` | `site.example.org,*.dev.example.org` — sites autorisés |
| `JWT_SECRET_FILE` | `/run/secrets/jwt_secret` — fichier contenant au moins 32 octets aléatoires, lisible par le service |

On peut utiliser `JWT_SECRET` à la place du fichier, mais pas les deux. Garder le même secret sur tous les réplicas. Options : `JWT_TTL=4h`, `LOG_LEVEL=info`.

cln-iap écoute sur le port **8080**, accessible à Traefik sur le réseau interne. Les domaines doivent partager `COOKIE_DOMAIN`. Prévoir le DNS et le certificat HTTPS du domaine d’authentification. Si Traefik utilise un resolver de certificats, renseigner son nom dans le label/tag `traefik.http.routers.cln-iap.tls.certresolver` ou dans `spec.tls.certResolver` de l’IngressRoute.

Les fichiers fournis routent uniquement `/login` et `/callback` du domaine `auth.example.org` vers cln-iap, en HTTPS et **sans middleware d’authentification**. Ne pas exposer `/verify` publiquement. Dans CAS, autoriser `https://auth.example.org/callback` avec son paramètre `state` variable.

Une fois le middleware ajouté, ouvrir un site concerné : la connexion CAS doit ramener à la page demandée.
