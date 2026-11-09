# Configuration par fichier Traefik

[Guide utilisateur](../README.md)

Activer le plugin dans la configuration statique et monter les fichiers administrateur décrits dans le guide. Dans un fichier dynamique déjà chargé par Traefik :

```yaml
http:
  middlewares:
    mon-app-iap:
      plugin:
        cln-iap:
          allowedLogins: "alice,bob"
```

Sur le routeur HTTPS de l’application, ajouter `mon-app-iap@file` en premier dans `middlewares`, avant les réécritures de chemin. Ne pas supprimer les autres middlewares.

Le routeur doit couvrir `/__cln_iap/callback`. Consulter le guide pour les applications exposées sous un préfixe.
