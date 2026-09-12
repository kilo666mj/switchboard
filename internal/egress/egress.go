// Package egress enforces an optional, explicit outbound network boundary.
package egress

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"

	"github.com/kilo666mj/switchboard/internal/config"
)

type lookupFunc func(context.Context, string, string) ([]net.IP, error)

type Policy struct {
	destinations map[string]bool
	prefixes     []netip.Prefix
	lookup       lookupFunc
}

func New(cfg config.EgressPolicy) (*Policy, error) {
	if len(cfg.AllowedDestinations) == 0 || len(cfg.AllowedCIDRs) == 0 {
		return nil, fmt.Errorf("egress policy requires allowed_destinations and allowed_cidrs")
	}
	policy := &Policy{destinations: map[string]bool{}, lookup: net.DefaultResolver.LookupIP}
	for _, raw := range cfg.AllowedDestinations {
		destination, err := normalizeDestination(raw)
		if err != nil {
			return nil, fmt.Errorf("invalid allowed destination %q: %w", raw, err)
		}
		if policy.destinations[destination] {
			return nil, fmt.Errorf("duplicate allowed destination %q", raw)
		}
		policy.destinations[destination] = true
	}
	for _, raw := range cfg.AllowedCIDRs {
		prefix, err := netip.ParsePrefix(raw)
		if err != nil {
			return nil, fmt.Errorf("invalid allowed CIDR %q: %w", raw, err)
		}
		policy.prefixes = append(policy.prefixes, prefix.Masked())
	}
	return policy, nil
}

func (p *Policy) ValidateURL(raw string) error {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil {
		return fmt.Errorf("egress policy requires an HTTPS URL without user information")
	}
	port := parsed.Port()
	if port == "" {
		port = "443"
	}
	destination, err := normalizeDestination(net.JoinHostPort(parsed.Hostname(), port))
	if err != nil {
		return err
	}
	if !p.destinations[destination] {
		return fmt.Errorf("destination %q is not in allowed_destinations", destination)
	}
	return nil
}

func (p *Policy) Transport() *http.Transport {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	// Environment proxies are a separate egress path and must not bypass this policy.
	transport.Proxy = nil
	transport.DialContext = p.dialContext
	return transport
}

func (p *Policy) dialContext(ctx context.Context, network, address string) (net.Conn, error) {
	destination, err := normalizeDestination(address)
	if err != nil {
		return nil, err
	}
	if !p.destinations[destination] {
		return nil, fmt.Errorf("egress destination %q is not allowed", destination)
	}
	host, port, _ := net.SplitHostPort(destination)
	addresses, err := p.resolve(ctx, host)
	if err != nil {
		return nil, err
	}
	for _, address := range addresses {
		if !p.addressAllowed(address) {
			return nil, fmt.Errorf("egress destination %q resolves outside allowed_cidrs", destination)
		}
	}
	dialer := new(net.Dialer)
	var lastErr error
	for _, address := range addresses {
		if network == "tcp4" && !address.Is4() || network == "tcp6" && !address.Is6() {
			continue
		}
		connection, err := dialer.DialContext(ctx, network, net.JoinHostPort(address.String(), port))
		if err == nil {
			return connection, nil
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("destination %q resolved to no usable addresses", destination)
	}
	return nil, lastErr
}

func (p *Policy) resolve(ctx context.Context, host string) ([]netip.Addr, error) {
	if address, err := netip.ParseAddr(host); err == nil {
		return []netip.Addr{address.Unmap()}, nil
	}
	resolved, err := p.lookup(ctx, "ip", host)
	if err != nil {
		return nil, fmt.Errorf("resolve egress destination %q: %w", host, err)
	}
	addresses := make([]netip.Addr, 0, len(resolved))
	for _, raw := range resolved {
		address, ok := netip.AddrFromSlice(raw)
		if ok {
			addresses = append(addresses, address.Unmap())
		}
	}
	if len(addresses) == 0 {
		return nil, fmt.Errorf("egress destination %q resolved to no addresses", host)
	}
	return addresses, nil
}

func (p *Policy) addressAllowed(address netip.Addr) bool {
	for _, prefix := range p.prefixes {
		if prefix.Contains(address) {
			return true
		}
	}
	return false
}

func normalizeDestination(raw string) (string, error) {
	host, port, err := net.SplitHostPort(strings.TrimSpace(raw))
	if err != nil || host == "" || port == "" {
		return "", fmt.Errorf("use exact host:port syntax")
	}
	portNumber, err := strconv.ParseUint(port, 10, 16)
	if err != nil || portNumber == 0 {
		return "", fmt.Errorf("port must be between 1 and 65535")
	}
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	if address, err := netip.ParseAddr(host); err == nil {
		host = address.Unmap().String()
	} else if strings.ContainsAny(host, " /%") {
		return "", fmt.Errorf("invalid host")
	}
	return net.JoinHostPort(host, strconv.FormatUint(portNumber, 10)), nil
}
