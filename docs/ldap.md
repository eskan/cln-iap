# Autorisations LDAP

Deux configurations rendent LDAP plus simple à utiliser et plus sûr : l’administrateur conserve les paramètres de connexion et définit les attributs autorisés ; chaque application choisit seulement un attribut et les valeurs donnant accès à son service.

## Configuration administrateur

La configuration administrateur permet à Traefik de retrouver dans l’annuaire l’utilisateur authentifié par CAS. Elle décrit le serveur LDAP, le compte de lecture, la branche où chercher les utilisateurs et l’attribut correspondant au login CAS. Elle fixe aussi les attributs utilisables par les applications et la durée des autorisations.

Cette configuration est commune aux middlewares LDAP. Elle reste privée : les responsables d’applications n’ont besoin que des noms d’attributs autorisés et des valeurs utilisables.

Créer un fichier `cln-iap-ldap.json` en adaptant cet exemple à votre annuaire :

```json
{
  "url": "ldaps://annuaire.example.org:636",
  "bindDN": "cn=lecture-iap,ou=services,dc=example,dc=org",
  "passwordFile": "/run/secrets/ldap-password",
  "baseDN": "ou=personnes,dc=example,dc=org",
  "loginAttribute": "uid",
  "allowedAttributes": ["eduPersonAffiliation", "departmentNumber"],
  "caFile": "/run/secrets/ldap-ca.pem",
  "timeout": "5s",
  "authorizationTTL": "5m"
}
```

| Paramètre | Usage |
| --- | --- |
| `url` | Adresse LDAPS sans chemin ni paramètres, avec un certificat valide pour le nom indiqué. |
| `bindDN` | Compte de lecture limité aux données nécessaires. |
| `passwordFile` | Fichier contenant le mot de passe exact, sans saut de ligne ajouté. |
| `baseDN` | Branche contenant les utilisateurs. |
| `loginAttribute` | Attribut correspondant au login CAS (`uid`, `sAMAccountName`…). Chaque login doit désigner un utilisateur unique. |
| `allowedAttributes` | Attributs utilisables dans les règles des applications. |
| `caFile` | Facultatif : autorités de confiance au format PEM ; sinon, celles du système. |
| `timeout` | Délai maximal du contrôle : `5s` par défaut, entre `1s` et `1m`. |
| `authorizationTTL` | Validité de l’autorisation : `5m` par défaut, entre `1s` et `1h`, en secondes entières, sans dépasser la session CAS. |

Les noms d’attributs commencent par une lettre ASCII, suivie de lettres ASCII, chiffres ou tirets. Les filtres libres et options d’attribut ne sont pas acceptés.

Créer séparément le fichier `ldap-password` contenant le mot de passe du compte `bindDN`. Si `caFile` est renseigné, fournir aussi le certificat de l’autorité de confiance.

Rendre ces fichiers accessibles dans le conteneur Traefik en lecture seule. Les chemins du JSON désignent leurs emplacements **dans le conteneur**. Par exemple, ajouter ces entrées au service Traefik sous Docker Compose :

```yaml
volumes:
  - ./secrets/cln-iap-ldap.json:/run/secrets/cln-iap-ldap.json:ro
  - ./secrets/ldap-password:/run/secrets/ldap-password:ro
  - ./secrets/ldap-ca.pem:/run/secrets/ldap-ca.pem:ro
environment:
  CLN_IAP_LDAP_CONFIG_FILE: "/run/secrets/cln-iap-ldap.json"
```

`CLN_IAP_LDAP_CONFIG_FILE` indique à Traefik quel fichier de configuration utiliser. Réserver l’accès aux fichiers à l’administrateur et à Traefik, puis redémarrer Traefik après modification.

## Configuration par application

La configuration de l’application définit qui peut accéder à son service. Elle choisit un attribut parmi ceux autorisés par l’administrateur (`ldapAttribute`) et une liste de valeurs acceptées (`ldapAllowedValues`). Elle ne contient aucun paramètre de connexion à l’annuaire.

Dans cet exemple, seuls `alice` et `bob` peuvent accéder à l’application, à condition que leur attribut `eduPersonAffiliation` contienne `staff` ou `faculty` :

```yaml
http:
  middlewares:
    mon-app-iap:
      plugin:
        cln-iap:
          allowedLogins: "alice,bob"
          ldapAttribute: "eduPersonAffiliation"
          ldapAllowedValues:
            - "staff"
            - "faculty"
```

**LDAP est facultatif** : omettre ensemble `ldapAttribute` et `ldapAllowedValues` pour conserver seulement le contrôle CAS et l’éventuelle liste `allowedLogins`. Lorsqu’ils sont présents, les deux paramètres sont obligatoires et les valeurs doivent être non vides.

Pour ajouter la même restriction LDAP avec des labels Docker :

```yaml
labels:
  - "traefik.http.middlewares.mon-app-iap.plugin.cln-iap.ldapAttribute=eduPersonAffiliation"
  - "traefik.http.middlewares.mon-app-iap.plugin.cln-iap.ldapAllowedValues=staff,faculty"
```

Pour les valeurs contenant une virgule, utiliser la liste YAML du fournisseur de fichiers.

## Conditions d’accès

Après authentification CAS, l’accès est accordé si l’attribut choisi est autorisé par l’administrateur et contient au moins une valeur acceptée par l’application. La comparaison est exacte, espaces et casse compris ; les attributs à valeurs multiples sont acceptés. Si `allowedLogins` est renseigné, les deux restrictions doivent être satisfaites ; les logins restent vérifiés à chaque requête.

La connexion CAS est commune au domaine. L’autorisation LDAP est propre au middleware et à l’hôte, dans un cookie sécurisé. LDAP est consulté au premier accès puis au renouvellement de cette autorisation, sans nouvel appel pendant sa validité.

Une modification de règle invalide les anciennes autorisations dès son chargement par Traefik. Un changement de session CAS impose une nouvelle autorisation ; une rotation du secret invalide sessions et autorisations après redémarrage. Un retrait de droits dans LDAP prend effet au renouvellement, au plus tard après `authorizationTTL`, sans révocation individuelle immédiate.

- **403** : utilisateur absent ou ambigu, attribut manquant ou aucune valeur acceptée.
- **503** : configuration invalide ou échec du contrôle LDAP (indisponibilité, certificat, connexion ou recherche).

Pendant une indisponibilité LDAP, les autorisations encore valides restent utilisables, mais leur renouvellement est refusé. Un refus LDAP conserve la connexion CAS globale pour les autres applications.
