package cln_iap

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
)

type ldapSettings struct {
	URL               string   `json:"url"`
	BindDN            string   `json:"bindDN"`
	PasswordFile      string   `json:"passwordFile"`
	BaseDN            string   `json:"baseDN"`
	LoginAttribute    string   `json:"loginAttribute"`
	AllowedAttributes []string `json:"allowedAttributes"`
	CAFile            string   `json:"caFile,omitempty"`
	Timeout           string   `json:"timeout,omitempty"`
	AuthorizationTTL  string   `json:"authorizationTTL,omitempty"`
	authorizationTTL  time.Duration
	password          string
	tlsConfig         *tls.Config
	timeout           time.Duration
}

var ldapAttributeName = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9-]*$`)

func configureLDAP(c *config, path string, local *Config) error {
	if local.LDAPAttribute == "" && len(local.LDAPAllowedValues) == 0 {
		return nil
	}
	invalid := errors.New("invalid LDAP authorization configuration")
	if !ldapAttributeName.MatchString(local.LDAPAttribute) || len(local.LDAPAllowedValues) == 0 || path == "" {
		return invalid
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return invalid
	}
	var settings ldapSettings
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&settings) != nil {
		return invalid
	}
	var extra interface{}
	if decoder.Decode(&extra) != io.EOF {
		return invalid
	}
	u, err := url.Parse(settings.URL)
	if err != nil || u.Scheme != "ldaps" || u.Hostname() == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return invalid
	}
	if settings.BindDN == "" || settings.BaseDN == "" || !ldapAttributeName.MatchString(settings.LoginAttribute) {
		return invalid
	}
	if _, err := ldap.ParseDN(settings.BindDN); err != nil {
		return invalid
	}
	if _, err := ldap.ParseDN(settings.BaseDN); err != nil {
		return invalid
	}
	allowed := false
	for _, attribute := range settings.AllowedAttributes {
		if !ldapAttributeName.MatchString(attribute) {
			return invalid
		}
		if strings.EqualFold(attribute, local.LDAPAttribute) {
			allowed = true
		}
	}
	if !allowed {
		return invalid
	}
	password, err := os.ReadFile(settings.PasswordFile)
	if err != nil || len(password) == 0 {
		return invalid
	}
	settings.password = string(password)
	settings.timeout = 5 * time.Second
	if settings.Timeout != "" {
		settings.timeout, err = time.ParseDuration(settings.Timeout)
		if err != nil || settings.timeout < time.Second || settings.timeout > time.Minute {
			return invalid
		}
	}
	settings.authorizationTTL = 5 * time.Minute
	if settings.AuthorizationTTL != "" {
		settings.authorizationTTL, err = time.ParseDuration(settings.AuthorizationTTL)
		if err != nil || settings.authorizationTTL < time.Second || settings.authorizationTTL > time.Hour || settings.authorizationTTL%time.Second != 0 {
			return invalid
		}
	}
	settings.tlsConfig = &tls.Config{MinVersion: tls.VersionTLS12, ServerName: u.Hostname()}
	if settings.CAFile != "" {
		ca, err := os.ReadFile(settings.CAFile)
		if err != nil {
			return invalid
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(ca) {
			return invalid
		}
		settings.tlsConfig.RootCAs = pool
	}
	c.ldapValues = map[string]bool{}
	for _, value := range local.LDAPAllowedValues {
		if strings.TrimSpace(value) == "" {
			return invalid
		}
		c.ldapValues[value] = true
	}
	c.ldapAttribute = local.LDAPAttribute
	c.ldap = &settings
	return nil
}

func (a *app) ldapAllowed(ctx context.Context, subject string) (bool, error) {
	s := a.ldap
	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()
	u, err := url.Parse(s.URL)
	if err != nil {
		return false, err
	}
	address := u.Host
	if u.Port() == "" {
		address = net.JoinHostPort(u.Hostname(), "636")
	}
	dialer := &tls.Dialer{NetDialer: &net.Dialer{Timeout: s.timeout}, Config: s.tlsConfig}
	raw, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return false, err
	}
	defer raw.Close()
	conn := ldap.NewConn(raw, true)
	conn.Start()
	defer conn.Close()
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			raw.Close()
		case <-done:
		}
	}()
	conn.SetTimeout(s.timeout)
	if err := conn.Bind(s.BindDN, s.password); err != nil {
		return false, err
	}
	result, err := conn.Search(ldap.NewSearchRequest(s.BaseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 2, int(s.timeout/time.Second), false,
		"("+s.LoginAttribute+"="+ldap.EscapeFilter(subject)+")", []string{a.ldapAttribute}, nil))
	if err != nil {
		return false, err
	}
	if len(result.Entries) != 1 || len(result.Referrals) != 0 {
		return false, nil
	}
	for _, attribute := range result.Entries[0].Attributes {
		if strings.EqualFold(attribute.Name, a.ldapAttribute) {
			for _, value := range attribute.Values {
				if a.ldapValues[value] {
					return true, nil
				}
			}
		}
	}
	return false, nil
}
