package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/kilo666mj/switchboard/internal/egress"
)

const maxResponseBytes = 4 << 20
const integrationPath = "/proxy/network/integration"

type client struct {
	base, apiKey string
	http         *http.Client
}

func newClient(base, apiKey, caFile, tlsServerName string, policy *egress.Policy) (*client, error) {
	u, err := url.Parse(base)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil ||
		u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return nil, errors.New("UNIFI_URL must be an HTTPS controller origin without credentials, query, or path")
	}
	if strings.TrimSpace(apiKey) == "" || strings.ContainsAny(apiKey, "\r\n") {
		return nil, errors.New("UNIFI_API_KEY is required and must not contain newlines")
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	if policy != nil {
		if err := policy.ValidateURL(base); err != nil {
			return nil, fmt.Errorf("UniFi egress policy: %w", err)
		}
		transport = policy.Transport()
	}
	if tlsServerName != "" && (caFile == "" || strings.ContainsAny(tlsServerName, "/:@* \t\r\n")) {
		return nil, errors.New("UNIFI_TLS_SERVER_NAME requires an explicit UNIFI_CA_FILE and a certificate DNS name")
	}
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12, ServerName: tlsServerName}
	if caFile != "" {
		pem, err := os.ReadFile(caFile)
		if err != nil {
			return nil, errors.New("cannot read UNIFI_CA_FILE")
		}
		pool, err := x509.SystemCertPool()
		if err != nil {
			return nil, errors.New("cannot load system certificate roots")
		}
		if !pool.AppendCertsFromPEM(pem) {
			return nil, errors.New("UNIFI_CA_FILE contains no certificates")
		}
		transport.TLSClientConfig.RootCAs = pool
	}
	return &client{
		base: strings.TrimSuffix(base, "/"), apiKey: apiKey,
		http: &http.Client{Transport: transport, Timeout: 15 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }},
	}, nil
}

// get has no caller-controlled destination or method. Errors deliberately omit
// response bodies and transport details, which can contain credentials.
func (c *client) get(ctx context.Context, path string, query url.Values) (map[string]any, error) {
	endpoint := c.base + integrationPath + path
	if len(query) > 0 {
		endpoint += "?" + query.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, errors.New("cannot construct UniFi request")
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("X-API-Key", c.apiKey)
	response, err := c.http.Do(req)
	if err != nil {
		return nil, errors.New("UniFi connection failed; check controller reachability, TLS trust, and egress policy")
	}
	defer func() { _ = response.Body.Close() }()
	switch response.StatusCode {
	case http.StatusUnauthorized, http.StatusForbidden:
		return nil, errors.New("UniFi denied access; check the local integration API key and its permissions")
	case http.StatusNotFound:
		return nil, errors.New("UniFi endpoint or resource not found; check the installed Network version and identifiers")
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, fmt.Errorf("UniFi returned HTTP %d", response.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, maxResponseBytes+1))
	if err != nil {
		return nil, errors.New("cannot read UniFi response")
	}
	if len(raw) > maxResponseBytes {
		return nil, errors.New("UniFi response exceeds 4 MiB limit")
	}
	var result map[string]any
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := decoder.Decode(&result); err != nil || result == nil {
		return nil, errors.New("UniFi returned an invalid JSON object")
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return nil, errors.New("UniFi returned trailing response data")
	}
	return result, nil
}
