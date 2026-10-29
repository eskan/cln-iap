# Ajouter le middleware par fichier YAML

[← README](../README.md) · [Variables et routes de connexion](configuration.md)

Un middleware est une étape exécutée par Traefik avant de transmettre la requête. Ici, il appelle `/verify` sur cln-iap pour vérifier la connexion de l’utilisateur.

Ajouter ce bloc dans un fichier de configuration dynamique déjà chargé par Traefik (fournisseur `file`) :

```yaml
http:
  middlewares:
    cas:
      forwardAuth:
        address: http://cln-iap:8080/verify
        trustForwardHeader: false
        authRequestHeaders: [Cookie]
```

Dans le routeur existant, ajouter `cas@file` à la liste `middlewares`, avant les éventuelles réécritures de chemin :

```yaml
middlewares:
  - cas@file
```

Adapter `cln-iap:8080` à l’adresse interne du service. Garder l’appel ForwardAuth en GET et ne pas appliquer ce middleware aux routes `/login` et `/callback`.
