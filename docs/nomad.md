# Installer avec Nomad

[← README](../README.md) · [Variables](configuration.md)

Prérequis : clients Nomad avec Docker, variables Nomad accessibles au job et Traefik avec le **fournisseur Nomad** et HTTPS configuré. Traefik doit joindre les ports alloués sur le réseau privé des clients.

1. Récupérer [cln-iap.nomad.hcl](../deploy/cln-iap.nomad.hcl). Adapter `dc1`, les domaines, les variables et l’entrypoint `websecure`.
2. Créer le secret une seule fois, puis soumettre le job :

```sh
nomad var put nomad/jobs/cln-iap jwt_secret="$(openssl rand -hex 32)"
nomad job validate cln-iap.nomad.hcl
nomad job run cln-iap.nomad.hcl
nomad job status cln-iap
```

Le job télécharge `ghcr.io/eskan/cln-iap:latest`, monte le secret et déclare les routes de connexion et le middleware `cas`. L’adresse de vérification utilise `${NOMAD_ADDR_http}`, renseignée par Nomad à chaque allocation. Cet exemple utilise une seule instance : plusieurs adresses déclarées sous le même middleware seraient en conflit.

3. Dans les tags du service concerné (enregistré avec `provider = "nomad"`), ajouter cette entrée en remplaçant `mon-routeur` par son nom Traefik :

```hcl
"traefik.http.routers.mon-routeur.middlewares=cas@nomad"
```

Conserver les middlewares existants après `cas@nomad`, puis soumettre le job modifié. Ouvrir le site pour vérifier la connexion CAS.

Références : [variables réseau Nomad](https://developer.hashicorp.com/nomad/docs/reference/runtime-environment-settings), [fournisseur Nomad de Traefik](https://doc.traefik.io/traefik/reference/routing-configuration/other-providers/nomad/).
