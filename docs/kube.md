# Kubernetes

[Guide utilisateur](../README.md)

Configurer le déploiement Traefik avec :

- Le plugin monté en lecture seule dans `/plugins-local/src/github.com/eskan/cln-iap`.
- L’argument `--experimental.localplugins.cln-iap.modulename=github.com/eskan/cln-iap`.
- Les variables `CLN_IAP_*` dans l’environnement du conteneur Traefik.
- Un Secret contenant la clé de session, monté à `/run/secrets/cln_iap_jwt`.

Créer le Secret dans le namespace de Traefik, à partir des fichiers préparés par l’administrateur :

```sh
kubectl -n traefik create secret generic cln-iap-jwt --from-file=cln_iap_jwt
```

Réserver l’accès au Secret au déploiement Traefik. Définir `CLN_IAP_JWT_SECRET_FILE=/run/secrets/cln_iap_jwt`. Le [fragment administrateur](../deploy/kube-traefik.yaml) présente les variables et le montage à intégrer au déploiement existant de Traefik. Aucun ConfigMap JSON n’est nécessaire. Conserver les arguments, les fournisseurs, les volumes du plugin et les certificats existants. Redémarrer les pods après modification des variables ou du Secret.

Dans le namespace de l’application, appliquer le [middleware](../deploy/kube.yaml), puis le référencer dans l’IngressRoute HTTPS :

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

Conserver les entrypoints et la configuration TLS de l’IngressRoute. Placer ce middleware avant ceux qui modifient les chemins. Le routeur doit aussi couvrir `/__cln_iap/callback`.
