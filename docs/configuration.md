# Configuration

Les [variables d’environnement administrateur et les autorisations par service](../README.md) sont décrites dans le guide utilisateur.

Définir les variables `CLN_IAP_*` uniquement sur Traefik. Monter le secret dans chaque instance et renseigner `CLN_IAP_JWT_SECRET_FILE`, ou utiliser `CLN_IAP_JWT_SECRET` seul. Les labels des applications ne contiennent que `allowedLogins` et l’attachement du middleware au routeur.

Redémarrer Traefik après toute modification des variables ou du secret. Garder les mêmes paramètres de session et les mêmes octets de secret sur tous les réplicas.
