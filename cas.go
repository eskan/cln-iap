package main

import (
	"context"
	"crypto/tls"
	"encoding/xml"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
)

const casNamespace = "http://www.yale.edu/tp/cas"

// Unknown elements at the response or success level are rejected; CAS user
// attributes are accepted but ignored. Namespace prefixes themselves are arbitrary.
type casResponse struct {
	XMLName xml.Name `xml:"http://www.yale.edu/tp/cas serviceResponse"`
	Success []struct {
		Users []struct {
			Text     string     `xml:",chardata"`
			Children []struct{} `xml:",any"`
		} `xml:"http://www.yale.edu/tp/cas user"`
		Attributes []struct{} `xml:"http://www.yale.edu/tp/cas attributes"`
		Unknown    []struct{} `xml:",any"`
		Text       string     `xml:",chardata"`
	} `xml:"http://www.yale.edu/tp/cas authenticationSuccess"`
	Failure []struct {
		Children []struct{} `xml:",any"`
	} `xml:"http://www.yale.edu/tp/cas authenticationFailure"`
	Unknown []struct{} `xml:",any"`
	Text    string     `xml:",chardata"`
}

// Only bounded, application-owned categories may reach logs, never upstream errors.
type casError struct {
	reason string
	status int
}

func (e *casError) Error() string { return e.reason }

func casTransportError(err error) error {
	var certificate *tls.CertificateVerificationError
	var network net.Error
	switch {
	case errors.As(err, &certificate):
		return &casError{reason: "tls_error"}
	case errors.As(err, &network) && network.Timeout():
		return &casError{reason: "timeout"}
	case errors.Is(err, context.Canceled):
		return &casError{reason: "request_canceled"}
	default:
		return &casError{reason: "network_error"}
	}
}

func (a *app) validateTicket(ctx context.Context, ticket, service string) (string, error) {
	endpoint := a.cas + "/serviceValidate?" + url.Values{"ticket": {ticket}, "service": {service}}.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return "", &casError{reason: "invalid_response"}
	}
	req.Header.Set("Accept", "application/xml")
	res, err := a.client.Do(req)
	if err != nil {
		return "", casTransportError(err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return "", &casError{reason: "http_status", status: res.StatusCode}
	}
	const limit = 64 << 10
	body, err := io.ReadAll(io.LimitReader(res.Body, limit+1))
	if err != nil {
		return "", casTransportError(err)
	}
	if len(body) > limit {
		return "", &casError{reason: "response_too_large"}
	}
	decoder := xml.NewDecoder(strings.NewReader(string(body)))
	var response casResponse
	if decoder.Decode(&response) != nil {
		return "", &casError{reason: "invalid_response"}
	}
	// Decode alone would accept a second XML document after the first one.
	for {
		token, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", &casError{reason: "invalid_response"}
		}
		if text, ok := token.(xml.CharData); !ok || strings.TrimSpace(string(text)) != "" {
			return "", &casError{reason: "invalid_response"}
		}
	}
	if len(response.Failure) == 1 && len(response.Success) == 0 && len(response.Unknown) == 0 &&
		strings.TrimSpace(response.Text) == "" && len(response.Failure[0].Children) == 0 {
		return "", &casError{reason: "ticket_rejected"}
	}
	if len(response.Failure) != 0 {
		return "", &casError{reason: "invalid_response"}
	}
	if len(response.Success) != 1 || len(response.Unknown) != 0 || strings.TrimSpace(response.Text) != "" {
		return "", &casError{reason: "invalid_response"}
	}
	success := response.Success[0]
	if len(success.Users) != 1 || len(success.Unknown) != 0 || len(success.Attributes) > 1 ||
		strings.TrimSpace(success.Text) != "" || len(success.Users[0].Children) != 0 {
		return "", &casError{reason: "invalid_response"}
	}
	user := success.Users[0].Text
	if strings.TrimSpace(user) == "" {
		return "", &casError{reason: "invalid_response"}
	}
	return user, nil
}
