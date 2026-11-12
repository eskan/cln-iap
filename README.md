# cln-iap

<p align="center">
  <img src="docs/assets/cln-iap.png" alt="Un visiteur présente sa carte d’identité devant une barrière fermée ; un agent lui fait signe de patienter avant d’accéder à l’entrée." width="200">
</p>
Compte tenu du climat actuel autour des failles de sécurité, il paraît essentiel de restreindre la surface d’attaque de nos applications. L’une des pistes envisagées est un Identity Aware Proxy : il vise à garantir l’authentification de l’utilisateur avant tout accès. On peut le voir comme un VPN applicatif. Il ne remplace pas l’authentification propre à l’application, mais son fonctionnement reste transparent pour l’utilisateur.  
Celui-ci se connecte sur CAS, puis accède à la page demandée. Sa session est partagée entre les sites autorisés du même domaine. Chaque application peut restreindre l’accès à ses propres utilisateurs. cln-iap ne se substitue pas aux contrôles d’accès de l’application et ne lui transmet pas l’identité de l’utilisateur.

**cln-iap** s’utilise comme middleware dans **Traefik 3**.

## Prérequis

- Traefik 3 avec HTTPS terminé directement dans Traefik. Version validée : **3.7.17**.
- Un serveur CAS proposant `/login` et `/serviceValidate`, accessible en HTTPS depuis Traefik.
- Des sites partageant un domaine de cookies, par exemple `app.example.org` et `outils.example.org` sous `example.org`.
- Un administrateur pouvant monter les fichiers de configuration et le secret dans Traefik.

## Installation par l’administrateur

### Activer le plugin

Placer les fichiers du plugin dans un répertoire `cln-iap`, puis monter ce répertoire en lecture seule dans Traefik à l’emplacement :

```text
/plugins-local/src/github.com/eskan/cln-iap
```

Ajouter à la configuration statique de Traefik :

```yaml
experimental:
  localPlugins:
    cln-iap:
      moduleName: github.com/eskan/cln-iap
```

Redémarrer Traefik après l’installation ou la mise à jour du plugin. Ce mode d’installation ne nécessite pas de publication au catalogue.

### Définir les paramètres communs

Définir ces variables d’environnement sur le processus Traefik :

```text
CLN_IAP_CAS_URL=https://cas.example.org/cas
CLN_IAP_COOKIE_DOMAIN=example.org
CLN_IAP_ALLOWED_HOSTS=app.example.org,outils.example.org
CLN_IAP_JWT_SECRET_FILE=/run/secrets/cln_iap_jwt
CLN_IAP_JWT_TTL=4h
CLN_IAP_LOG_LEVEL=info
```

| Variable                  | Usage                                                                                                                                                                                                                                                  |
| ------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `CLN_IAP_CAS_URL`         | URL HTTPS de CAS, sans query ni fragment ; obligatoire.                                                                                                                                                                                                |
| `CLN_IAP_COOKIE_DOMAIN`   | Domaine commun aux sites, sans point initial ; obligatoire.                                                                                                                                                                                            |
| `CLN_IAP_ALLOWED_HOSTS`   | Liste non vide d’hôtes séparés par des virgules ; obligatoire. Les espaces autour des éléments sont ignorés, les éléments vides sont refusés. `*.dev.example.org` accepte les sous-domaines, y compris imbriqués, mais pas `dev.example.org` lui-même. |
| `CLN_IAP_JWT_SECRET_FILE` | Chemin du fichier secret accessible dans Traefik ; option recommandée.                                                                                                                                                                                 |
| `CLN_IAP_JWT_SECRET`      | Alternative au fichier ; définir exactement une des deux sources de secret. Sa valeur est accessible aux outils autorisés à inspecter l’environnement du processus.                                                                                    |
| `CLN_IAP_JWT_TTL`         | Durée de session, `4h` par défaut ; durée positive en secondes entières.                                                                                                                                                                               |
| `CLN_IAP_LOG_LEVEL`       | `debug`, `info`, `warn` ou `error` ; `info` par défaut.                                                                                                                                                                                                |

Créer le secret et le monter en lecture seule dans Traefik :

```sh
umask 077
openssl rand -hex 32 > cln_iap_jwt
```

Le secret doit contenir au moins 32 octets aléatoires. Ce secret peut être révoqué, toutes les sessions seront alors rejouées.

**Ces propriétés appartiennent exclusivement à l’administrateur.** Elles ne sont pas configurables par les labels des applications. Les déployeurs des applications n’ont besoin ni du secret ni d’une copie de la configuration commune. `allowedLogins` reste propre au middleware de chaque application.

Après modification de la configuration commune ou du secret, redémarrer les réplicas Traefik de façon coordonnée. Un changement de secret invalide les sessions existantes. Une configuration absente ou invalide empêche la création du middleware.

### Autoriser les retours dans CAS

Autoriser le callback de chaque site dans le registre des services CAS :

```text
https://app.example.org/__cln_iap/callback?state=...
https://outils.example.org/__cln_iap/callback?state=...
```

Le paramètre `state` varie à chaque connexion. Exemple de motif pour ces deux sites, si le registre CAS utilise des expressions régulières :

```text
^https://(app|outils)\.example\.org/__cln_iap/callback\?state=[A-Za-z0-9_-]{43}$
```

Le certificat HTTPS de CAS doit être reconnu par Traefik. Avec une autorité privée, installer son certificat de confiance dans l’environnement Traefik. La vérification TLS ne peut pas être désactivée dans les paramètres du service.

## Protéger un service

### Avec les labels Docker Compose

Sur le service de l’application, déclarer un middleware portant un nom propre au service et l’attacher au routeur :

```yaml
labels:
  - "traefik.http.middlewares.mon-app-iap.plugin.cln-iap.allowedLogins=alice,bob"
  - "traefik.http.routers.mon-app.middlewares=mon-app-iap"
```

Le routeur `mon-app` doit déjà pointer vers l’application et utiliser HTTPS. Garder les autres middlewares éventuels après `mon-app-iap`, notamment ceux qui réécrivent les chemins. Dans Swarm, placer ces labels sous `deploy.labels`.

### Avec un fichier dynamique Traefik

```yaml
http:
  middlewares:
    mon-app-iap:
      plugin:
        cln-iap:
          allowedLogins: "alice,bob"
```

Attacher ensuite `mon-app-iap@file` au routeur de l’application.

## Exemples par environnement

- [Docker Compose](docs/compose.md)
- [Docker Swarm](docs/swarm.md)
- [Kubernetes](docs/kube.md)
- [Nomad](docs/nomad.md)
- [Configuration par fichier Traefik](docs/traefik.md)
- [Performances](docs/benchmark.md)
