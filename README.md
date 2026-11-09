# cln-iap

**cln-iap** protège les applications Web avec une authentification CAS et une liste facultative de logins autorisés. Il s’utilise comme middleware dans Traefik 3, sans domaine d’authentification dédié.

L’utilisateur se connecte sur CAS, puis retrouve la page demandée. Sa session est partagée entre les sites autorisés du même domaine. Chaque application peut limiter l’accès à ses propres utilisateurs. cln-iap ne remplace pas les contrôles d’accès de l’application et ne lui transmet pas l’identité de l’utilisateur.

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

Monter ce fichier en lecture seule à **`/etc/traefik/cln-iap.json`** dans Traefik :

```json
{
  "casUrl": "https://cas.example.org/cas",
  "cookieDomain": "example.org",
  "allowedHosts": ["app.example.org", "outils.example.org"],
  "jwtSecretFile": "/run/secrets/cln_iap_jwt",
  "jwtTtl": "4h",
  "logLevel": "info"
}
```

| Paramètre global | Usage |
| --- | --- |
| `casUrl` | URL HTTPS de CAS, sans query ni fragment. |
| `cookieDomain` | Domaine commun aux sites, sans point initial. |
| `allowedHosts` | Tableau non vide d’hôtes autorisés. `*.dev.example.org` accepte les sous-domaines, y compris imbriqués, mais pas `dev.example.org` lui-même. |
| `jwtSecretFile` | Chemin absolu du fichier secret, accessible dans Traefik. |
| `jwtSecret` | Alternative au fichier ; ne pas renseigner les deux. |
| `jwtTtl` | Durée de session, `4h` par défaut ; durée positive en secondes entières. |
| `logLevel` | `debug`, `info`, `warn` ou `error` ; `info` par défaut. |

Les noms d’hôtes doivent être en minuscules, sans port. Tous les hôtes autorisés doivent appartenir à `cookieDomain`. N’inclure dans ce domaine partagé que des sous-domaines de confiance.

Créer le secret et le monter en lecture seule dans Traefik :

```sh
umask 077
openssl rand -hex 32 > cln_iap_jwt
```

Le secret doit contenir au moins 32 octets aléatoires. Son fichier est lu tel quel, y compris l’éventuel saut de ligne. Utiliser exactement le même fichier et les mêmes paramètres de session sur tous les réplicas Traefik partageant les cookies.

**Ces propriétés appartiennent exclusivement à l’administrateur.** Elles ne sont pas configurables par les labels des applications. Les déployeurs des applications n’ont besoin ni du secret ni d’une copie de la configuration commune. Le fichier ne contient pas de liste `allowedLogins`.

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

### Choisir les utilisateurs autorisés

`allowedLogins` est le seul paramètre propre au middleware du service.

- `"alice,bob"` autorise uniquement ces deux identifiants CAS.
- `" alice, bob "` a le même effet ; les espaces autour des éléments sont ignorés.
- Une chaîne vide ou uniquement composée d’espaces autorise tous les utilisateurs authentifiés par CAS. Le champ est facultatif dans une déclaration de middleware existante.
- Les identifiants sont sensibles à la casse : `Alice` et `alice` sont distincts. Les jokers ne sont pas interprétés.
- Une liste contenant un élément vide, comme `"alice,,bob"` ou `"alice,"`, est refusée.

Avec les labels, conserver explicitement `allowedLogins=` pour déclarer un middleware sans restriction de login.

L’autorisation est vérifiée à chaque requête. Une session obtenue sur un site ne donne pas accès à un autre site dont la liste exclut l’utilisateur. Le retrait d’un login s’applique dès que Traefik active la nouvelle configuration du middleware, sans attendre l’expiration du cookie. Un refus sur un site ne déconnecte pas l’utilisateur des autres sites.

## Routes réservées et applications sous un préfixe

Le chemin `/__cln_iap` et tout le préfixe `/__cln_iap/` sont réservés. Le callback doit passer par **le même middleware** que l’application, avant toute réécriture de chemin. Il ne faut pas l’exclure de l’authentification dans Traefik : le plugin le traite lui-même.

Un routeur `Host(...)` couvre déjà ce chemin. Si l’application utilise seulement `PathPrefix('/outils')`, ajouter un routeur pour le callback sur le même hôte :

```yaml
http:
  routers:
    outils-callback:
      rule: "Host(`outils.example.org`) && PathPrefix(`/__cln_iap`)"
      entryPoints: [websecure]
      tls: {}
      service: outils
      middlewares: [outils-iap]
```

Conserver la configuration TLS et le fournisseur correspondant à votre installation. Le service `outils` et le middleware `outils-iap` doivent exister. Le plugin répond au callback sans transmettre la requête à l’application.

Si plusieurs applications partagent un même hôte, utiliser la même politique de connexion sur cet hôte ou leur attribuer des sous-domaines distincts : le chemin de callback est commun à l’hôte.

## Comportement et dépannage

| Réponse | Signification |
| --- | --- |
| Redirection vers CAS | Absence de session valide pour une requête GET ou HEAD. |
| `401` | Session absente ou invalide pour une autre méthode, notamment POST. La requête n’est pas rejouée après connexion. |
| `403` | Utilisateur connecté, mais login non autorisé sur ce service. |
| `400` | Origine non autorisée, requête non HTTPS ou parcours de connexion invalide/expiré. |
| `404` | Chemin réservé inconnu. |
| `405` | Méthode non autorisée sur le callback. |
| `502` | Validation CAS impossible, ticket refusé ou réponse CAS invalide. |

Un parcours de connexion expire après cinq minutes. En cas d’expiration, rouvrir la page de l’application. Deux connexions simultanées sur le même hôte peuvent se remplacer : recommencer depuis la page souhaitée.

Les cookies sont sécurisés, inaccessibles au JavaScript et envoyés uniquement en HTTPS. Une session valide continue à fonctionner pendant une indisponibilité de CAS, jusqu’à son expiration. Une déconnexion de CAS ne révoque pas immédiatement le cookie cln-iap ; sa durée est contrôlée par `jwtTtl`.

Les événements du plugin apparaissent dans les logs Traefik, sans login, ticket, cookie ou secret. Configurer séparément les journaux d’accès de Traefik pour éviter d’y enregistrer la query des callbacks ou les en-têtes Cookie.

Le middleware doit être attaché à tous les routeurs donnant accès à l’application. Le plugin ne peut pas protéger un routeur auquel il n’est pas attaché, ni un accès direct au port de l’application.

## Exemples par environnement

- [Docker Compose](docs/compose.md)
- [Docker Swarm](docs/swarm.md)
- [Kubernetes](docs/kube.md)
- [Nomad](docs/nomad.md)
- [Configuration par fichier Traefik](docs/traefik.md)
- [Performances](docs/benchmark.md)
