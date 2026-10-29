job "cln-iap" {
  datacenters = ["dc1"]
  type        = "service"

  group "iap" {
    count = 1
    network {
      port "http" {
        to = 8080
      }
    }
    update {
      max_parallel = 1
      canary       = 0
    }
    task "cln-iap" {
      driver = "docker"
      config {
        image = "ghcr.io/eskan/cln-iap:latest"
        ports = ["http"]
      }
      env {
        CAS_URL         = "https://cas.example.org/cas"
        AUTH_URL        = "https://auth.example.org"
        COOKIE_DOMAIN   = "example.org"
        ALLOWED_HOSTS   = "site.example.org"
        JWT_SECRET_FILE = "/secrets/jwt_secret"
      }
      template {
        data        = "{{ with nomadVar \"nomad/jobs/cln-iap\" }}{{ .jwt_secret }}{{ end }}"
        destination = "secrets/jwt_secret"
        perms       = "0444"
        change_mode = "restart"
      }
      service {
        name         = "cln-iap"
        provider     = "nomad"
        port         = "http"
        address_mode = "host"
        tags = [
          "traefik.enable=true",
          "traefik.http.routers.cln-iap.rule=Host(`auth.example.org`) && (Path(`/login`) || Path(`/callback`))",
          "traefik.http.routers.cln-iap.entrypoints=websecure",
          "traefik.http.routers.cln-iap.tls=true",
          "traefik.http.routers.cln-iap.service=cln-iap",
          "traefik.http.middlewares.cas.forwardauth.address=http://${NOMAD_ADDR_http}/verify",
          "traefik.http.middlewares.cas.forwardauth.trustForwardHeader=false",
          "traefik.http.middlewares.cas.forwardauth.authRequestHeaders=Cookie",
        ]
      }
      resources {
        cpu    = 100
        memory = 64
      }
    }
  }
}
