# Installer avec Kubernetes

[← README](../README.md) · [Variables](configuration.md)

Prérequis : Traefik avec le fournisseur Kubernetes CRD, les ressources `Middleware` / `IngressRoute` et HTTPS configurés.

1. Récupérer [kube.yaml](../deploy/kube.yaml). Adapter les domaines, les variables et l’entrypoint `websecure`. L’exemple utilise le namespace `default`, commun à cln-iap et à votre route existante ; si vous le changez, adapter aussi l’adresse du middleware.
2. Créer le secret une seule fois et installer cln-iap :

```sh
openssl rand 32 | kubectl -n default create secret generic cln-iap-jwt --from-file=jwt_secret=/dev/stdin
kubectl -n default apply -f kube.yaml
kubectl -n default rollout status deployment/cln-iap
```

Le manifest crée le Deployment utilisant `ghcr.io/eskan/cln-iap:latest`, le Service interne, les routes de connexion et le middleware `cas`.

3. Dans la route concernée de votre `IngressRoute` (`spec.routes[]`), ajouter :

```yaml
middlewares:
  - name: cas
```

Conserver les middlewares existants après `cas`, puis appliquer votre `IngressRoute`. Ouvrir le site pour vérifier la connexion CAS. Pour plusieurs namespaces, créer le middleware dans chacun, en gardant l’adresse du Service cln-iap.
