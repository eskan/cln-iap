# Configuration

Les [paramètres administrateur et les autorisations par service](../README.md) sont décrits dans le guide utilisateur.

Le fichier `/etc/traefik/cln-iap.json` et le secret doivent être montés dans chaque instance Traefik. Les labels des applications ne contiennent que `allowedLogins` et l’attachement du middleware au routeur.
