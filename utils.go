package ygg

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	ycore "github.com/yggdrasil-network/yggdrasil-go/src/core"
)

func SaveJSON(path string, v any) error {
	tmp := path + ".tmp"
	b, _ := json.MarshalIndent(v, "", "  ")
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// uniqUnion returns a union of a and b preserving the order of a, then appending unseen items from b.
func uniqUnion(a, b []string) []string {
	seen := make(map[string]struct{}, len(a)+len(b))
	out := make([]string, 0, len(a)+len(b))
	for _, s := range a {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	for _, s := range b {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}

type publicPeerEntry struct {
	Up *bool `json:"up"`
}

var supportedPeerSchemes = map[string]struct{}{
	"http":  {},
	"https": {},
	"tcp":   {},
	"tls":   {},
	"quic":  {},
	"ws":    {},
	"wss":   {},
}

func fetchPeersFromURL(timeout time.Duration) ([]string, error) {
	ctx := context.Background()
	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}

	cl := &http.Client{Timeout: timeout}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, publicPeersURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "say/0.1")
	resp, err := cl.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("%s", resp.Status)
	}

	var raw map[string]json.RawMessage
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return nil, fmt.Errorf("decode peers: %w", err)
	}

	seen := map[string]struct{}{}
	out := make([]string, 0, len(raw))

	for _, blob := range raw {
		var nodes map[string]publicPeerEntry
		if err := json.Unmarshal(blob, &nodes); err != nil {
			continue // skip metadata blocks
		}
		for endpoint, meta := range nodes {
			endpoint = strings.TrimSpace(endpoint)
			if endpoint == "" {
				continue
			}
			if meta.Up != nil && !*meta.Up {
				continue
			}
			if _, ok := seen[endpoint]; ok {
				continue
			}
			if !isSupportedPeerScheme(endpoint) {
				continue
			}
			seen[endpoint] = struct{}{}
			out = append(out, endpoint)
		}
	}

	if len(out) == 0 {
		return nil, fmt.Errorf("no peers found in %s", publicPeersURL)
	}
	return out, nil
}

func isSupportedPeerScheme(raw string) bool {
	if raw == "" {
		return false
	}
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	if _, ok := supportedPeerSchemes[strings.ToLower(u.Scheme)]; !ok {
		return false
	}
	return true
}

// FilterAlivePeers checks peer availability and returns only those considered "alive".
// For http/https - perform HTTP GET with InsecureTLS; for other schemes - TCP dial to host:port.
func FilterAlivePeers(peers []string, timeout time.Duration, maxParallel int) []string {
	if maxParallel <= 0 {
		maxParallel = 16
	}
	type result struct {
		idx int
		ok  bool
	}

	alive := make([]string, 0, len(peers))
	ch := make(chan result, len(peers))
	sem := make(chan struct{}, maxParallel)
	var wg sync.WaitGroup

	for i, raw := range peers {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}

		wg.Add(1)
		sem <- struct{}{}
		go func(idx int, p string) {
			defer wg.Done()
			defer func() { <-sem }()
			ok := probePeer(p, timeout)
			ch <- result{idx: idx, ok: ok}
		}(i, raw)
	}

	wg.Wait()
	close(ch)

	for res := range ch {
		if res.ok {
			alive = append(alive, strings.TrimSpace(peers[res.idx]))
		}
	}
	return alive
}

func probePeer(raw string, timeout time.Duration) bool {
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}

	switch strings.ToLower(u.Scheme) {
	case "http", "https":
		// Any successful HTTP response (any status) counts as alive.
		tr := &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true, // insecure, like curl -k
			},
			DialContext: (&net.Dialer{Timeout: timeout}).DialContext,
		}
		cl := &http.Client{Transport: tr, Timeout: timeout}
		req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, raw, nil)
		resp, err := cl.Do(req)
		if err != nil {
			return false
		}
		resp.Body.Close()
		return true

	default:
		// For other schemes, try TCP to host:port if present.
		hostport := u.Host
		if hostport == "" && u.Opaque != "" {
			// support for forms like "scheme:host:port" without //
			hostport = u.Opaque
		}
		if hostport == "" {
			return false
		}
		d := net.Dialer{Timeout: timeout}
		c, err := d.Dial("tcp", hostport)
		if err != nil {
			return false
		}
		_ = c.Close()
		return true
	}
}

func CollectPeers(static []string, timeout time.Duration, maxParallel int) ([]string, error) {
	var all []string
	all = append(all, static...)
	fromURL, err := fetchPeersFromURL(timeout)
	if err != nil && !errors.Is(err, context.DeadlineExceeded) {
		return nil, err
	}
	all = append(all, fromURL...)
	// dedupe and basic sanitize
	seen := map[string]struct{}{}
	uniq := make([]string, 0, len(all))
	for _, p := range all {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if _, ok := seen[p]; ok {
			continue
		}
		// only accept schemes we know how to probe
		if !isSupportedPeerScheme(p) {
			continue
		}
		seen[p] = struct{}{}
		uniq = append(uniq, p)
	}
	if len(uniq) == 0 {
		return nil, fmt.Errorf("no peers provided")
	}
	alive := FilterAlivePeers(uniq, timeout, maxParallel)
	if len(alive) == 0 {
		return nil, fmt.Errorf("no alive peers")
	}
	return alive, nil
}

// certFromPrivateKey creates a self-signed TLS cert using the provided ed25519 private key.
func certFromPrivateKey(priv ed25519.PrivateKey) (*tls.Certificate, error) {
	tpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(3650 * 24 * time.Hour), // ~10 years
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}
	pub := priv.Public().(ed25519.PublicKey)
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, pub, priv)
	if err != nil {
		return nil, err
	}
	cert := &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: priv}
	return cert, nil
}

// hasUp is an internal helper used by Connected/WaitConnected and the monitor.
// hasUp reports whether the core has at least one Up peer.
func hasUp(core *ycore.Core) bool {
	for _, p := range core.GetPeers() {
		if p.Up {
			return true
		}
	}
	return false
}

// notifyConnectivity invokes the connectivity handler if set.
func notifyConnectivity(connected bool) {
	if h := connectivityHandler; h != nil {
		h(connected)
	}
}
