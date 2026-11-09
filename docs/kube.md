# Kubernetes

[Guide utilisateur](../README.md)

Configurer le déploiement Traefik avec :

- Le plugin monté en lecture seule dans `/plugins-local/src/github.com/eskan/cln-iap`.
- L’argument `--experimental.localplugins.cln-iap.modulename=github.com/eskan/cln-iap`.
- Un ConfigMap contenant `cln-iap.json`, monté à `/etc/traefik/cln-iap.json`.
- Un Secret contenant la clé de session, monté à `/run/secrets/cln_iap_jwt`.

Créer le ConfigMap et le Secret dans le namespace de Traefik, à partir des fichiers préparés par l’administrateur :

```sh
kubectl -n traefik create configmap cln-iap-config --from-file=cln-iap.json
kubectl -n traefik create secret generic cln-iap-jwt --from-file=cln_iap_jwt
```

Réserver l’accès au Secret au déploiement Traefik. Le fichier administrateur utilise `jwtSecretFile: /run/secrets/cln_iap_jwt` (propriété JSON dans ce fichier).

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
