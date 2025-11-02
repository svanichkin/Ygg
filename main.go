package ygg

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"

	ycfg "github.com/yggdrasil-network/yggdrasil-go/src/config"
	ycore "github.com/yggdrasil-network/yggdrasil-go/src/core"
)

const publicPeersURL = "https://publicpeers.neilalexander.dev/"

type quietLogger struct{}

func (l quietLogger) Printf(string, ...interface{})     {}
func (l quietLogger) Println(...interface{})            {}
func (l quietLogger) Infof(string, ...interface{})      {}
func (l quietLogger) Infoln(...interface{})             {}
func (l quietLogger) Warnf(string, ...interface{})      {}
func (l quietLogger) Warnln(...interface{})             {}
func (l quietLogger) Errorf(f string, a ...interface{}) { log.Printf(f, a...) }
func (l quietLogger) Errorln(a ...interface{})          { log.Println(a...) }
func (l quietLogger) Debugf(string, ...interface{})     {}
func (l quietLogger) Debugln(...interface{})            {}
func (l quietLogger) Traceln(...interface{})            {}

var (
	verbose  bool
	maxPeers int
)

// ConnectivityHandler is called whenever the node transitions between
// connected and disconnected states.
type ConnectivityHandler func(connected bool)

var connectivityHandler ConnectivityHandler

// SetConnectivityHandler installs a callback for connectivity state changes.
// The callback is invoked on a background goroutine.
func SetConnectivityHandler(h ConnectivityHandler) { connectivityHandler = h }

// SetVerbose enables or disables verbose logging from this package.
func SetVerbose(v bool) { verbose = v }

// SetMaxPeers sets an upper bound on the number of peers to add at startup.
// If n <= 0, there is no limit.
func SetMaxPeers(n int) { maxPeers = n }

func logV(format string, a ...interface{}) {
	if verbose {
		log.Printf(format, a...)
	}
}

// New initializes (or loads) configuration from cfgPath, discovers peers, starts
// an embedded Yggdrasil core, connects to alive peers, and returns the Node.
// If cfgPath is empty, a default location is chosen (next to the binary or
// ~/.config/say/config.json). The caller owns the returned Node and may stop it
// by calling Close().
func New(cfgPath string) (*Node, error) {
	// Default values if not set via setters
	if maxPeers == 0 {
		maxPeers = 100
	}

	// Resolve config path if empty (same logic as the old main())
	if strings.TrimSpace(cfgPath) == "" {
		if exe, err := os.Executable(); err == nil {
			exeDir := filepath.Dir(exe)
			cand := filepath.Join(exeDir, "config.json")
			if _, err := os.Stat(cand); err == nil {
				cfgPath = cand
			}
		}
		if cfgPath == "" {
			if home, err := os.UserHomeDir(); err == nil {
				cand := filepath.Join(home, ".config", "say", "config.json")
				if _, err := os.Stat(cand); err == nil {
					cfgPath = cand
				} else {
					_ = os.MkdirAll(filepath.Dir(cand), 0o755)
					cfgPath = cand
				}
			}
		}
	}

	log.Println("config path:", cfgPath)

	ac, err := LoadOrInitAppConfig(cfgPath)
	if err != nil {
		return nil, err
	}
	yc, err := PrepareYggConfig(ac)
	if err != nil {
		return nil, err
	}
	if e := SaveJSON(cfgPath, ac); e != nil {
		log.Printf("warn: can't write config: %v", e)
	} else {
		log.Println("config saved (keys inline)")
	}

	startPeers := time.Now()
	logV("peers: static=%d", len(ac.Peers))
	var alive []string
	if len(ac.Peers) > 0 {
		logV("bg: fetching peers from %s", publicPeersURL)
		// We have peers in config: start ASAP with those that are alive
		alive = FilterAlivePeers(ac.Peers, 2*time.Second, 16)
		logV("peers: alive_from_config=%d", len(alive))
		if len(alive) == 0 {
			// Fallback: try to fetch once synchronously
			if fromURL, err := fetchPeersFromURL(2 * time.Second); err == nil {
				ac.Peers = uniqUnion(ac.Peers, fromURL)
				if e := SaveJSON(cfgPath, ac); e != nil {
					log.Printf("warn: can't save peers to config: %v", e)
				}
				alive = FilterAlivePeers(ac.Peers, 2*time.Second, 16)
				logV("peers: alive_after_merge=%d", len(alive))
			}
			if len(alive) == 0 {
				return nil, fmt.Errorf("peers: no alive peers")
			}
		}
		// Background one-shot refresh from URL (non-blocking)
		go func() {
			fromURL, err := fetchPeersFromURL(5 * time.Second)
			if err != nil {
				log.Printf("peers refresh: fetch failed: %v", err)
				return
			}
			before := len(ac.Peers)
			ac.Peers = uniqUnion(ac.Peers, fromURL)
			added := len(ac.Peers) - before
			if added > 0 {
				if e := SaveJSON(cfgPath, ac); e != nil {
					log.Printf("warn: can't save peers to config: %v", e)
				}
			}
			freshAlive := FilterAlivePeers(fromURL, 2*time.Second, 16)
			log.Printf("peers updated: %d total (added=%d, alive_new=%d)", len(ac.Peers), added, len(freshAlive))
		}()
	} else {
		log.Println("fetching peers from", publicPeersURL)
		// No peers in config: block until we fetch fresh peers (retry with backoff)
		backoff := 2 * time.Second
		for {
			fromURL, err := fetchPeersFromURL(2 * time.Second)
			if err != nil {
				log.Printf("peers: fetch failed: %v; retrying in %s", err, backoff)
				time.Sleep(backoff)
				if backoff < 30*time.Second {
					backoff *= 2
				}
				continue
			}
			alive = FilterAlivePeers(fromURL, 2*time.Second, 16)
			logV("peers: fetched=%d alive=%d (cold start)", len(fromURL), len(alive))
			if len(alive) == 0 {
				log.Printf("peers: fetched but none alive; retrying in %s", backoff)
				time.Sleep(backoff)
				if backoff < 30*time.Second {
					backoff *= 2
				}
				continue
			}
			ac.Peers = uniqUnion(ac.Peers, fromURL)
			if e := SaveJSON(cfgPath, ac); e != nil {
				log.Printf("warn: can't save peers to config: %v", e)
			}
			break
		}
	}

	logV("peers: ready=%d (took %s)", len(alive), time.Since(startPeers).Truncate(time.Millisecond))

	node, err := StartAndConnect(yc, alive, quietLogger{})
	if err != nil {
		return nil, err
	}

	addr := node.Core.Address()
	keyHex := strings.TrimSpace(ac.Seed)
	if len(keyHex) >= 8 {
		log.Printf("connected: %s (key fp=%s…)", addr.String(), keyHex[:8])
	} else {
		log.Printf("connected: %s", addr.String())
	}
	log.Printf("subnet (/64): %s", node.Core.Subnet())

	// Start connectivity monitor if user installed a handler.
	if connectivityHandler != nil {
		node.startConnectivityMonitor(3 * time.Second)
	}

	return node, nil
}

func init() {
	// create default data directory for examples
	_ = os.MkdirAll(filepath.Join(".", "data"), 0o755)
}

type AppConfig struct {
	// inline private key seed (empty => generate)
	Seed string `json:"seed,omitempty"`
	// static peers (tcp://host:port, tls://..., quic://...)
	Peers []string `json:"peers"`
	// timeouts
	DialTimeoutSec int `json:"dial_timeout_sec,omitempty"`
}

func LoadOrInitAppConfig(path string) (*AppConfig, error) {
	b, err := os.ReadFile(path)
	if err == nil {
		var c AppConfig
		if e := json.Unmarshal(b, &c); e != nil {
			return nil, e
		}
		changed := false
		if c.Peers == nil {
			c.Peers = []string{}
			changed = true
		}
		if c.DialTimeoutSec == 0 {
			c.DialTimeoutSec = 3
			changed = true
		}
		// If we had to add defaults, persist them back to the existing config file.
		if changed {
			_ = os.MkdirAll(filepath.Dir(path), 0o755)
			_ = SaveJSON(path, &c)
		}
		return &c, nil
	}
	// Create a new config with sane defaults if the file does not exist yet.
	c := &AppConfig{
		Peers:          []string{},
		DialTimeoutSec: 3,
	}
	_ = os.MkdirAll(filepath.Dir(path), 0o755)
	_ = SaveJSON(path, c)
	return c, nil
}

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

// -------- Ygg cfg/keys --------

type Node struct {
	Core      *ycore.Core
	Config    *ycfg.NodeConfig
	monCancel context.CancelFunc
}

// Close attempts to gracefully stop the underlying core, if supported.
func (n *Node) Close() error {
	// stop background monitor if running
	if n != nil && n.monCancel != nil {
		n.monCancel()
		n.monCancel = nil
	}
	// try to stop the core gracefully if supported
	type stopper interface{ Stop() }
	if n != nil && n.Core != nil {
		if s, ok := any(n.Core).(stopper); ok {
			s.Stop()
		}
	}
	return nil
}

// startConnectivityMonitor launches a lightweight connectivity watcher.
// It sends an initial state and then only on changes. Callers stop it via Close().
func (n *Node) startConnectivityMonitor(interval time.Duration) {
	if n == nil || n.Core == nil {
		return
	}
	if interval <= 0 {
		interval = 3 * time.Second
	}
	ctx, cancel := context.WithCancel(context.Background())
	n.monCancel = cancel

	go func() {
		t := time.NewTicker(interval)
		defer t.Stop()

		prev := hasUp(n.Core)
		notifyConnectivity(prev)

		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				cur := hasUp(n.Core)
				if cur != prev {
					prev = cur
					notifyConnectivity(cur)
				}
			}
		}
	}()
}

// generate or load keys into ycfg.NodeConfig

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

func PrepareYggConfig(app *AppConfig) (*ycfg.NodeConfig, error) {
	cfg := ycfg.GenerateConfig() // sane defaults; will be overridden below

	loadedExisting := false

	// 1) Read key in multiple formats: hex or base64/base64url (32/64 bytes)
	if s := strings.TrimSpace(app.Seed); s != "" {
		var raw []byte
		if b, err := base64.RawURLEncoding.DecodeString(s); err == nil {
			raw = b
		} else if b, err := base64.RawStdEncoding.DecodeString(s); err == nil {
			raw = b
		} else if b, err := hex.DecodeString(s); err == nil {
			raw = b
		} else {
			return nil, fmt.Errorf("bad inline_key value: not base64/base64url or hex: %w", err)
		}
		switch len(raw) {
		case 32: // seed -> derive full key
			k := ed25519.NewKeyFromSeed(raw)
			cfg.PrivateKey = ycfg.KeyBytes(k)
		case ed25519.PrivateKeySize: // 64 bytes full key -> treat as seed+pub, rebuild from seed
			k := ed25519.NewKeyFromSeed(raw[:32])
			cfg.PrivateKey = ycfg.KeyBytes(k)
		default:
			return nil, fmt.Errorf("inline_key_hex has unexpected length %d (want 32 or 64 bytes)", len(raw))
		}
		// standardize: always store 32-byte seed as base64url (short form)
		seed := []byte(cfg.PrivateKey)[:32]
		app.Seed = base64.RawURLEncoding.EncodeToString(seed)
		loadedExisting = true
	}

	// 3) If no key was loaded — generate a new one
	if !loadedExisting {
		_, genPriv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("generate ed25519 key: %w", err)
		}
		cfg.PrivateKey = ycfg.KeyBytes(genPriv)
		// store only the 32-byte seed to keep config compact
		app.Seed = base64.RawURLEncoding.EncodeToString([]byte(cfg.PrivateKey)[:32])
		log.Println("generated new private key (saved to config.json)")
	} else {
		log.Println("using private key from config.json")
	}

	// 4) Ensure TLS certificate exists for the core
	if cfg.Certificate == nil {
		if err := cfg.GenerateSelfSignedCertificate(); err != nil {
			return nil, err
		}
	}

	return cfg, nil
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

// start Core and connect to peers until first connection is up
func StartAndConnect(cfg *ycfg.NodeConfig, peers []string, logger ycore.Logger) (*Node, error) {
	t0 := time.Now()
	// Force core to use the same ed25519 key as in cfg.PrivateKey (ignore cfg.Certificate)
	if len(cfg.PrivateKey) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("cfg.PrivateKey length=%d, want %d", len(cfg.PrivateKey), ed25519.PrivateKeySize)
	}
	cert, err := certFromPrivateKey(ed25519.PrivateKey(cfg.PrivateKey))
	if err != nil {
		return nil, fmt.Errorf("make cert: %w", err)
	}

	// Build SetupOptions from cfg
	var opts []ycore.SetupOption
	if cfg.NodeInfo != nil {
		opts = append(opts, ycore.NodeInfo(cfg.NodeInfo))
	}
	if cfg.NodeInfoPrivacy {
		opts = append(opts, ycore.NodeInfoPrivacy(true))
	}
	for _, la := range cfg.Listen {
		la = strings.TrimSpace(la)
		if la != "" {
			opts = append(opts, ycore.ListenAddress(la))
		}
	}
	for _, hexKey := range cfg.AllowedPublicKeys {
		hexKey = strings.TrimSpace(hexKey)
		if hexKey == "" {
			continue
		}
		b, err := hex.DecodeString(hexKey)
		if err == nil && len(b) == ed25519.PublicKeySize {
			opts = append(opts, ycore.AllowedPublicKey(ed25519.PublicKey(b)))
		}
	}

	core, err := ycore.New(cert, logger, opts...)
	if err != nil {
		return nil, err
	}
	logV("core: adding peers=%d", len(peers))
	// add peers to autodial table
	added := 0
	for _, p := range peers {
		if maxPeers > 0 && added >= maxPeers {
			break
		}
		if u, e := url.Parse(p); e == nil {
			_ = core.AddPeer(u, "")
			added++
		}
	}
	logV("core: added peers=%d (max=%d)", added, maxPeers)
	core.RetryPeersNow()

	// wait for the first Up peer
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	tick := time.NewTicker(500 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("connect timeout")
		case <-tick.C:
			ok := false
			for _, pi := range core.GetPeers() {
				if pi.Up {
					ok = true
					break
				}
			}
			if ok {
				logV("connect: first_up in %s", time.Since(t0).Truncate(time.Millisecond))
				return &Node{Core: core, Config: cfg}, nil
			}
			core.RetryPeersNow()
		}
	}
}

// FilterAlivePeers checks peer availability and returns only those considered "alive".
// For http/https — perform HTTP GET with InsecureTLS; for other schemes — TCP dial to host:port.
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

func fetchPeersFromURL(timeout time.Duration) ([]string, error) {
	cl := &http.Client{Timeout: timeout}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, publicPeersURL, nil)
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
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	re := regexp.MustCompile(`(tcp|tls|quic|ws|wss)://[^<\s]+`)
	matches := re.FindAllString(string(b), -1)
	if len(matches) == 0 {
		return nil, fmt.Errorf("no peers found on page")
	}
	seen := map[string]struct{}{}
	out := make([]string, 0, len(matches))
	for _, m := range matches {
		m = strings.TrimSpace(m)
		if m == "" {
			continue
		}
		if _, ok := seen[m]; ok {
			continue
		}
		seen[m] = struct{}{}
		out = append(out, m)
	}
	return out, nil
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
		u, err := url.Parse(p)
		if err != nil {
			continue
		}
		sc := strings.ToLower(u.Scheme)
		if sc != "http" && sc != "https" && sc != "tcp" && sc != "tls" && sc != "quic" && sc != "ws" && sc != "wss" {
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
