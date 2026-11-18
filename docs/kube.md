# Kubernetes

[Guide utilisateur](../README.md) · [Paramètres communs](configuration.md)

## Traefik

Le déploiement Traefik reçoit le plugin, les paramètres CAS et le secret qui protège les sessions. Ce secret est conservé dans un Secret Kubernetes, accessible uniquement aux pods Traefik. Préparer le répertoire du plugin et le fichier `cln_iap_jwt` selon le [guide utilisateur](../README.md).

Monter le plugin en lecture seule dans `/plugins-local/src/github.com/eskan/cln-iap` et ajouter l’argument `--experimental.localplugins.cln-iap.modulename=github.com/eskan/cln-iap` au déploiement Traefik.

Créer le Secret dans son namespace :

```sh
kubectl -n traefik create secret generic cln-iap-jwt --from-file=cln_iap_jwt
```

Intégrer le [fragment administrateur](../deploy/kube-traefik.yaml) pour les variables communes et le montage du Secret à `/run/secrets/cln_iap_jwt`. Réserver l’accès au Secret à Traefik et définir `CLN_IAP_JWT_SECRET_FILE` avec ce chemin. Redémarrer les pods après modification.

## Application

La ressource Middleware contient les règles d’accès ; l’IngressRoute les applique au trafic de l’application. L’[exemple de middleware](../deploy/kube.yaml) autorise les logins CAS `alice` et `bob`.

Appliquer le [middleware](../deploy/kube.yaml) dans le namespace de l’application, puis le référencer dans son IngressRoute HTTPS :

```yaml
spec:
  routes:
    - match: Host(`app.example.org`)
      kind: Rule
      middlewares:
        - name: mon-app-iap
      services:
        - name: mon-app
          port: 80
```

Conserver les entrypoints et la configuration TLS. Placer cln-iap avant les réécritures de chemin et inclure `/__cln_iap/callback` dans le routage. Les [règles LDAP](ldap.md) sont facultatives.
