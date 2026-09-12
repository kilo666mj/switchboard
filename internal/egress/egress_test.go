package egress

import (
	"context"
	"net"
	"strings"
	"testing"

	"github.com/kilo666mj/switchboard/internal/config"
)

func TestPolicyValidatesDestinationsAndHTTPS(t *testing.T) {
	policy, err := New(config.EgressPolicy{
		AllowedDestinations: []string{"api.example.internal:443", "[2001:db8::1]:8443"},
		AllowedCIDRs:        []string{"192.0.2.0/24", "2001:db8::/32"},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, raw := range []string{"https://api.example.internal/mcp", "https://[2001:db8::1]:8443/mcp"} {
		if err := policy.ValidateURL(raw); err != nil {
			t.Fatalf("ValidateURL(%q): %v", raw, err)
		}
	}
	for _, raw := range []string{"http://api.example.internal/mcp", "https://other.example.internal/mcp", "https://user@api.example.internal/mcp"} {
		if err := policy.ValidateURL(raw); err == nil {
			t.Fatalf("ValidateURL(%q) succeeded", raw)
		}
	}
}

func TestPolicyRejectsAnyDisallowedDNSAnswer(t *testing.T) {
	policy, err := New(config.EgressPolicy{AllowedDestinations: []string{"api.example.internal:443"}, AllowedCIDRs: []string{"192.0.2.0/24"}})
	if err != nil {
		t.Fatal(err)
	}
	policy.lookup = func(context.Context, string, string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("192.0.2.5"), net.ParseIP("198.51.100.7")}, nil
	}
	if _, err := policy.dialContext(t.Context(), "tcp", "api.example.internal:443"); err == nil || !strings.Contains(err.Error(), "outside allowed_cidrs") {
		t.Fatalf("dialContext error = %v", err)
	}
}

func TestPolicyDialsValidatedIPAddressDirectly(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	policy, err := New(config.EgressPolicy{AllowedDestinations: []string{listener.Addr().String()}, AllowedCIDRs: []string{"127.0.0.0/8"}})
	if err != nil {
		t.Fatal(err)
	}
	accepted := make(chan struct{})
	go func() {
		connection, err := listener.Accept()
		if err == nil {
			connection.Close()
			close(accepted)
		}
	}()
	connection, err := policy.dialContext(t.Context(), "tcp4", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	connection.Close()
	<-accepted
}

func TestPolicyConfigurationFailsClosed(t *testing.T) {
	for _, cfg := range []config.EgressPolicy{
		{},
		{AllowedDestinations: []string{"missing-port.example.internal"}, AllowedCIDRs: []string{"192.0.2.0/24"}},
		{AllowedDestinations: []string{"api.example.internal:443"}, AllowedCIDRs: []string{"invalid"}},
		{AllowedDestinations: []string{"api.example.internal:443", "API.EXAMPLE.INTERNAL:443"}, AllowedCIDRs: []string{"192.0.2.0/24"}},
	} {
		if _, err := New(cfg); err == nil {
			t.Fatalf("invalid policy accepted: %+v", cfg)
		}
	}
}
