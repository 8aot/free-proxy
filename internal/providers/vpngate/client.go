package vpngate

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/masteralanlab/free-proxy/internal/config"
	"github.com/masteralanlab/free-proxy/internal/domain"
)

const (
	maxResponseBytes = 8 << 20 // 8 MiB; the VPNGate feed is normally far smaller.
	userAgent        = "free-proxy/0.1"
)

// Provider fetches and parses nodes from VPNGate with a direct TLS/HTTP fallback chain.
type Provider struct {
	apiURL  string
	limit   int
	timeout time.Duration

	httpClient *http.Client // optional injected client for tests
	clients    []*http.Client
	now        func() time.Time

	LastStats ParseStats
}

// NewProvider builds a Provider over the VPN Gate endpoint.
func NewProvider() *Provider {
	p := &Provider{
		apiURL:  config.VPNGateAPIURL,
		limit:   config.DiscoveryLimit,
		timeout: config.RequestTimeout,
		now:     time.Now,
	}
	p.clients = buildFallbackClients(p.apiURL, p.timeout)
	return p
}

// WithHTTPClient injects a client (tests); it bypasses the fallback chain.
func (p *Provider) WithHTTPClient(c *http.Client) *Provider {
	p.httpClient = c
	return p
}

// Name identifies the provider.
func (p *Provider) Name() string { return "vpngate" }

// ParseStats exposes the last parse counters (total, valid, dup, malformed, missing).
func (p *Provider) ParseStats() (int, int, int, int, int) {
	s := p.LastStats
	return s.TotalRows, s.ValidRows, s.DuplicateRows, s.MalformedRows, s.MissingFieldRows
}

type target struct {
	url    string
	verify bool
}

// Discover fetches the node list directly, trying HTTPS, HTTPS-no-verify, and HTTP.
func (p *Provider) Discover(ctx context.Context) ([]domain.DiscoveredNode, error) {
	if p.httpClient != nil {
		return p.fetch(ctx, p.httpClient, p.apiURL)
	}

	targets := p.clients
	if len(targets) == 0 {
		targets = buildFallbackClients(p.apiURL, p.timeout)
		p.clients = targets
	}
	var lastErr error
	for _, client := range targets {
		nodes, err := p.fetch(ctx, client, p.apiURL)
		if err != nil {
			lastErr = err
			continue
		}
		return nodes, nil
	}
	if lastErr == nil {
		lastErr = errors.New("no reachable endpoint")
	}
	return nil, fmt.Errorf("unable to fetch VPNGate nodes: %w", lastErr)
}

func (p *Provider) fetch(ctx context.Context, client *http.Client, endpoint string) ([]domain.DiscoveredNode, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", userAgent)
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("VPNGate returned status %d", resp.StatusCode)
	}

	// Bound memory usage even if the upstream endpoint is compromised or starts
	// returning an unexpectedly large payload. The parser only needs a complete
	// snapshot, so fail closed rather than silently parsing a truncated feed.
	limited := io.LimitReader(resp.Body, maxResponseBytes+1)
	body, err := io.ReadAll(limited)
	if err != nil {
		return nil, err
	}
	if len(body) > maxResponseBytes {
		return nil, fmt.Errorf("VPNGate response exceeds %d bytes", maxResponseBytes)
	}

	res, err := ParseResponse(string(body), p.limit, p.now())
	if err != nil {
		return nil, err
	}
	p.LastStats = res.Stats
	if res.Nodes == nil {
		res.Nodes = []domain.DiscoveredNode{}
	}
	return res.Nodes, nil
}

func buildFallbackClients(apiURL string, timeout time.Duration) []*http.Client {
	targets := []target{{apiURL, true}}
	if strings.HasPrefix(apiURL, "https://") {
		targets = append(targets,
			target{apiURL, false},
			target{strings.Replace(apiURL, "https://", "http://", 1), true},
		)
	}
	clients := make([]*http.Client, 0, len(targets))
	for _, t := range targets {
		clients = append(clients, buildClient(t.verify, timeout))
	}
	return clients
}

func buildClient(verify bool, timeout time.Duration) *http.Client {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: !verify}, //nolint:gosec // intentional TLS fallback
	}
	return &http.Client{Timeout: timeout, Transport: tr}
}
