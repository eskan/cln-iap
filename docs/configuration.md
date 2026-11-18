# Configuration

[Guide utilisateur](../README.md)

L’administrateur configure la connexion à CAS, les sites autorisés et les secrets dans Traefik. Chaque responsable d’application définit ensuite les utilisateurs autorisés dans son middleware, sans connaître les paramètres privés. LDAP ajoute, si nécessaire, une restriction par attribut d’annuaire.

## Paramètres administrateur

Ces paramètres sont communs aux applications protégées. Ils permettent à Traefik d’authentifier les utilisateurs et de partager leur session entre les sites d’un même domaine. Les définir dans l’environnement de Traefik :

| Variable | Usage |
| --- | --- |
| `CLN_IAP_CAS_URL` | Obligatoire : URL HTTPS de CAS, sans paramètres ni fragment. |
| `CLN_IAP_COOKIE_DOMAIN` | Obligatoire : domaine commun aux sites, sans point initial. |
| `CLN_IAP_ALLOWED_HOSTS` | Obligatoire : hôtes autorisés, séparés par des virgules, sans élément vide. |
| `CLN_IAP_JWT_SECRET_FILE` | Chemin du fichier secret monté dans Traefik ; source recommandée. |
| `CLN_IAP_JWT_SECRET` | Alternative au fichier ; choisir exactement une des deux sources. Visible aux outils autorisés à inspecter l’environnement. |
| `CLN_IAP_JWT_TTL` | Durée de session : `4h` par défaut, positive et en secondes entières. |
| `CLN_IAP_LOG_LEVEL` | `debug`, `info`, `warn` ou `error` ; `info` par défaut. |
| `CLN_IAP_LDAP_CONFIG_FILE` | Facultatif : chemin de la [configuration LDAP privée](ldap.md). |

Utiliser des noms DNS en minuscules, sans port. Les hôtes de `CLN_IAP_ALLOWED_HOSTS` doivent appartenir au domaine commun. `*.dev.example.org` autorise ses sous-domaines, y compris imbriqués, mais pas `dev.example.org`. Les espaces autour des hôtes de la liste sont ignorés.

Le secret doit contenir au moins 32 octets aléatoires. Monter les fichiers en lecture seule et garder les mêmes paramètres et le même secret sur tous les réplicas. Redémarrer les instances de façon coordonnée après modification, y compris après une erreur de configuration. Une rotation du secret invalide les sessions CAS et les autorisations LDAP.

## Règles par application

Ces règles déterminent quels utilisateurs déjà authentifiés peuvent accéder à une application. Par exemple, `allowedLogins: "alice,bob"` réserve l’accès à ces deux logins CAS. Les renseigner dans le middleware de l’application, par labels ou configuration dynamique Traefik.

| Paramètre | Usage |
| --- | --- |
| `allowedLogins` | Logins CAS séparés par des virgules ; vide ou absent : tous les utilisateurs CAS. Les espaces autour des logins sont ignorés, la casse est significative et les éléments vides sont refusés. |
| `ldapAttribute` | Attribut autorisé par l’administrateur ; facultatif, à renseigner avec `ldapAllowedValues`. |
| `ldapAllowedValues` | Liste de valeurs acceptées pour cet attribut ; voir le [guide LDAP](ldap.md). |

Utiliser un nom de middleware propre à chaque application. Si les deux restrictions sont renseignées, l’utilisateur doit satisfaire `allowedLogins` et la règle LDAP. Une modification des règles s’applique dès leur chargement par Traefik.

## Connexion et erreurs

La session CAS est partagée entre les sites autorisés du domaine. Sans session valide, une requête GET ou HEAD redirige vers CAS ; les autres méthodes reçoivent `401`.

| Réponse | Vérification à effectuer |
| --- | --- |
| `400` | Vérifier HTTPS, l’hôte autorisé et l’adresse de retour CAS. |
| `403` | Vérifier le login autorisé et, si activée, la règle LDAP. |
| `502` | Vérifier l’accès à CAS, son certificat et l’enregistrement du service. |
| `503` | Vérifier les paramètres, les fichiers secrets et, si nécessaire, l’accès LDAP. |

Une configuration commune absente ou invalide bloque l’accès avec `503` et un événement `configuration_error` dans les journaux Traefik. Après correction, redémarrer Traefik. Les règles de renouvellement LDAP sont décrites dans le [guide LDAP](ldap.md).
