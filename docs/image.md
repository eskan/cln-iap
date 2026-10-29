# Publication de l’image

[← README](../README.md)

Le [workflow GitHub Actions](../.github/workflows/image.yml) teste le code puis construit une image pour **Linux amd64 et arm64**. Docker sélectionne automatiquement l’architecture au téléchargement.

- Push sur la branche par défaut : publication de `ghcr.io/eskan/cln-iap:latest` et du tag `sha-…`.
- Push d’un tag `v*` : publication du même tag, par exemple `ghcr.io/eskan/cln-iap:v1.0.0`, et de `sha-…`. `latest` reste lié à la branche par défaut.
- Pull request : tests et construction, sans publication.
- Lancement manuel depuis Actions : publication seulement depuis la branche par défaut ou un tag `v*`.

L’authentification utilise le `GITHUB_TOKEN` fourni par GitHub, sans secret supplémentaire. Le nom d’image suit le dépôt (`ghcr.io/<propriétaire>/<dépôt>`).

Après la première publication, rendre le package **public** dans ses paramètres GitHub pour permettre les téléchargements sans authentification.
