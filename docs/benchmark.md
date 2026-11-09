# Performances

[Guide utilisateur](../README.md)

Une requête avec une session valide est contrôlée dans Traefik, sans appel à CAS. CAS est sollicité lors de la connexion.

Le coût dépend de la charge, des ressources allouées à Traefik et des réponses de l’application. Aucun chiffre de latence n’est publié ici. Les durées de connexion à CAS sont distinctes de celles des requêtes déjà authentifiées.
