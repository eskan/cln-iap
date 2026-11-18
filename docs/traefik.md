# Configuration par fichier Traefik

[Guide utilisateur](../README.md) · [Paramètres communs](configuration.md)

La configuration statique active le plugin au démarrage de Traefik. La configuration dynamique définit ensuite les règles d’accès de chaque application et les routeurs qui les utilisent.

Installer le plugin et configurer les paramètres CAS selon le [guide utilisateur](../README.md). Ajouter ensuite cet exemple dans un fichier dynamique chargé par Traefik : le middleware `mon-app-iap` autorise les logins CAS `alice` et `bob`, et le routeur `mon-app` l’applique aux requêtes vers `app.example.org`.

```yaml
http:
  middlewares:
    mon-app-iap:
      plugin:
        cln-iap:
          allowedLogins: "alice,bob"
  routers:
    mon-app:
      rule: Host(`app.example.org`)
      entryPoints:
        - websecure
      middlewares:
        - mon-app-iap@file
      service: mon-app
      tls: {}
```

Adapter `websecure` au nom de l’entrypoint HTTPS et `mon-app` au service Traefik de l’application. Garder les autres middlewares après cln-iap, notamment ceux qui réécrivent les chemins. Les [règles LDAP](ldap.md) sont facultatives.

CAS termine la connexion sur `/__cln_iap/callback`, à la racine du site. Si l’application est limitée au préfixe `/outils`, son routeur doit donc accepter aussi cette adresse de retour :

```yaml
rule: Host(`app.example.org`) && (PathPrefix(`/outils`) || Path(`/__cln_iap/callback`))
```

Les changements de règles sont chargés par le fournisseur de fichiers. Après modification des variables administrateur, des fichiers privés ou du secret, redémarrer Traefik.
