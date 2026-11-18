package cln_iap

import (
	"crypto/sha256"
	"encoding/json"
	"log/slog"
	"net/http"
	"time"
)

type authorizationClaims struct {
	Subject  string `json:"sub"`
	Session  string `json:"session"`
	Audience string `json:"aud"`
	Policy   string `json:"policy"`
	Issued   int64  `json:"iat"`
	Expires  int64  `json:"exp"`
}

func fingerprint(value string) string {
	sum := sha256.Sum256([]byte(value))
	return b64.EncodeToString(sum[:])
}

func (a *app) authorizationCookie() string {
	return "__Host-cln-iap-authz-" + fingerprint(a.name)
}

func (a *app) authorizationKey() []byte {
	return mac(a.secret, "cln-iap/authorization/v1")
}

func (a *app) authorizationAudience(host string) string {
	value, _ := json.Marshal([]string{a.name, host})
	return b64.EncodeToString(mac(a.authorizationKey(), string(value)))
}

func (a *app) authorizationPolicy() string {
	value, _ := json.Marshal(struct {
		Attribute         string
		Values            map[string]bool
		Logins            map[string]bool
		Directory         []string
		AllowedAttributes []string
	}{
		a.ldapAttribute, a.ldapValues, a.logins,
		[]string{a.ldap.URL, a.ldap.BindDN, a.ldap.BaseDN, a.ldap.LoginAttribute, a.ldap.PasswordFile, a.ldap.CAFile, a.ldap.Timeout, a.ldap.AuthorizationTTL},
		a.ldap.AllowedAttributes,
	})
	return b64.EncodeToString(mac(a.authorizationKey(), string(value)))
}

func (a *app) validAuthorization(token string, session claims, sessionToken, host string) bool {
	var c authorizationClaims
	now := time.Now().Unix()
	return unsign(a.authorizationKey(), jwtHeader+".", token, &c) == nil &&
		c.Subject == session.Subject && c.Session == fingerprint(sessionToken) &&
		c.Audience == a.authorizationAudience(host) && c.Policy == a.authorizationPolicy() &&
		c.Issued > 0 && c.Issued <= now && c.Issued >= session.Issued &&
		c.Expires > now && c.Expires > c.Issued && c.Expires <= session.Expires &&
		c.Expires-c.Issued <= int64(a.ldap.authorizationTTL/time.Second)
}

func (a *app) authorizeLDAP(w http.ResponseWriter, r *http.Request, session claims, sessionToken string) bool {
	if a.ldap == nil {
		return true
	}
	name := a.authorizationCookie()
	if a.validAuthorization(oneCookie(r, name), session, sessionToken, r.Host) {
		return true
	}
	allowed, err := a.ldapAllowed(r.Context(), session.Subject)
	if err != nil {
		setCookie(w, name, "", "", time.Unix(1, 0), -1)
		a.reject(w, http.StatusServiceUnavailable, slog.LevelError, "ldap_unavailable")
		return false
	}
	if !allowed {
		setCookie(w, name, "", "", time.Unix(1, 0), -1)
		a.reject(w, http.StatusForbidden, slog.LevelWarn, "ldap_not_allowed")
		return false
	}
	now := time.Now().Unix()
	expires := now + int64(a.ldap.authorizationTTL/time.Second)
	if expires > session.Expires {
		expires = session.Expires
	}
	if expires <= now {
		a.reject(w, http.StatusUnauthorized, slog.LevelDebug, "authentication_required")
		return false
	}
	token := sign(a.authorizationKey(), jwtHeader+".", authorizationClaims{
		session.Subject, fingerprint(sessionToken), a.authorizationAudience(r.Host), a.authorizationPolicy(), now, expires,
	})
	if len(token) > maxToken {
		a.reject(w, http.StatusBadGateway, slog.LevelError, "authorization_too_large")
		return false
	}
	privateResponse(w)
	setCookie(w, name, token, "", time.Unix(expires, 0), int(expires-now))
	return true
}

type authorizationResponse struct{ http.ResponseWriter }

func (w *authorizationResponse) WriteHeader(code int) {
	privateResponse(w.ResponseWriter)
	w.ResponseWriter.WriteHeader(code)
}

func (w *authorizationResponse) Write(body []byte) (int, error) {
	privateResponse(w.ResponseWriter)
	return w.ResponseWriter.Write(body)
}

func (w *authorizationResponse) Unwrap() http.ResponseWriter { return w.ResponseWriter }
