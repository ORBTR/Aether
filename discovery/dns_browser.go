//go:build js && wasm

/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 */
package discovery

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// BrowserDNSDiscoverer uses DNS-over-HTTPS (DoH) via fetch() for peer
// discovery in WASM environments where net.Resolver is unavailable.
// Queries Cloudflare (1.1.1.1) or Google (dns.google) DoH endpoints.
type BrowserDNSDiscoverer struct {
	domain   string
	gateways []string // DoH endpoints
}

// NewBrowserDNSDiscoverer creates a DNS discoverer for browser WASM.
func NewBrowserDNSDiscoverer(domain string) *BrowserDNSDiscoverer {
	return &BrowserDNSDiscoverer{
		domain: domain,
		gateways: []string{
			"https://cloudflare-dns.com/dns-query",
			"https://dns.google/resolve",
		},
	}
}

// Discover queries DoH for SRV records and returns peer addresses.
func (d *BrowserDNSDiscoverer) Discover(ctx context.Context) ([]string, error) {
	for _, gw := range d.gateways {
		addrs, err := d.queryDoH(ctx, gw)
		if err == nil && len(addrs) > 0 {
			return addrs, nil
		}
	}
	return nil, fmt.Errorf("all DoH gateways failed for %s", d.domain)
}

func (d *BrowserDNSDiscoverer) queryDoH(ctx context.Context, gateway string) ([]string, error) {
	// Use JSON DNS API (simpler than wire format for browser)
	url := fmt.Sprintf("%s?name=%s&type=SRV", gateway, d.domain)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/dns-json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	// Parse Google/Cloudflare DNS JSON response
	var result struct {
		Answer []struct {
			Data string `json:"data"`
		} `json:"Answer"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, err
	}

	var addrs []string
	for _, ans := range result.Answer {
		// SRV data format: "priority weight port target"
		parts := strings.Fields(ans.Data)
		if len(parts) >= 4 {
			target := strings.TrimSuffix(parts[3], ".")
			port := parts[2]
			addrs = append(addrs, fmt.Sprintf("%s:%s", target, port))
		}
	}
	return addrs, nil
}
