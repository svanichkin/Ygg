package ygg

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"

	ycfg "github.com/yggdrasil-network/yggdrasil-go/src/config"
	ycore "github.com/yggdrasil-network/yggdrasil-go/src/core"
	ipv6rwc "github.com/yggdrasil-network/yggdrasil-go/src/ipv6rwc"

	// gVisor netstack
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
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

// defaultNode is set by New() so top-level helpers (ListenTCP/DialTCP) can be used.
var defaultNode *Node

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
	// Start in-process netstack immediately (single-mode runtime, no OS utun)
	if _, err := node.StartNetstack(); err != nil {
		return nil, fmt.Errorf("start netstack: %w", err)
	}

	addr := node.Core.Address()
	keyHex := strings.TrimSpace(ac.Seed)
	if len(keyHex) >= 8 {
		log.Printf("connected: %s (key fp=%s…)", addr.String(), keyHex[:8])
	} else {
		log.Printf("connected: %s", addr.String())
	}

	// Start connectivity monitor if user installed a handler.
	if connectivityHandler != nil {
		node.startConnectivityMonitor(3 * time.Second)
	}
	// Expose as default for package-level helpers
	defaultNode = node

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

// -------- Ygg cfg/keys --------

type Node struct {
	Core      *ycore.Core
	Config    *ycfg.NodeConfig
	monCancel context.CancelFunc
	Net       *Netstack
}

// Netstack wraps an in-process gVisor TCP/IP stack bridged to Yggdrasil core via ipv6rwc.
type Netstack struct {
	Stack   *stack.Stack
	NICID   tcpip.NICID
	addr    tcpip.Address
	mtu     uint32
	rwc     io.ReadWriteCloser
	chEP    *channel.Endpoint
	stopCh  chan struct{}
	stopped bool
}

// AddrString returns our Ygg IPv6 as string
func (ns *Netstack) AddrString() string {
	if ns == nil {
		return ""
	}
	return ns.addr.String()
}

// Addr returns our Ygg IPv6 as net.IP
func (ns *Netstack) Addr() net.IP {
	if ns == nil {
		return nil
	}
	ip := net.ParseIP(ns.addr.String())
	return ip
}

// Close stops pumps and releases resources.
func (ns *Netstack) Close() error {
	if ns == nil || ns.stopped {
		return nil
	}
	ns.stopped = true
	close(ns.stopCh)
	if ns.chEP != nil {
		ns.chEP.Close()
		ns.chEP = nil
	}
	if ns.rwc != nil {
		_ = ns.rwc.Close()
		ns.rwc = nil
	}
	ns.Stack = nil
	ns.NICID = 0
	log.Printf("[netstack] closed")
	return nil
}

// ListenTCP exposes a net.Listener-like API backed by netstack.
func (ns *Netstack) ListenTCP(port int) (net.Listener, error) {
	if ns == nil || ns.Stack == nil {
		return nil, fmt.Errorf("netstack not started")
	}
	if port <= 0 || port > 65535 {
		return nil, fmt.Errorf("invalid port %d", port)
	}
	log.Printf("[p2p] [ns] listen tcp [%s]:%d", ns.addr.String(), port)
	fa := tcpip.FullAddress{NIC: ns.NICID, Addr: ns.addr, Port: uint16(port)}
	ln, err := gonet.ListenTCP(ns.Stack, fa, ipv6.ProtocolNumber)
	if err != nil {
		return nil, err
	}
	return ln, nil
}

// DialTCP dials a remote Ygg IPv6 + port through the in-process stack.
func (ns *Netstack) DialTCP(peerIPv6 string, port int, timeout time.Duration) (net.Conn, error) {
	if ns == nil || ns.Stack == nil {
		return nil, fmt.Errorf("netstack not started")
	}
	if port <= 0 || port > 65535 {
		return nil, fmt.Errorf("invalid port %d", port)
	}
	s := strings.TrimSpace(peerIPv6)
	if len(s) > 0 && s[0] == '[' && s[len(s)-1] == ']' {
		s = s[1 : len(s)-1]
	}
	ip := net.ParseIP(s)
	if ip == nil || ip.To4() != nil {
		return nil, fmt.Errorf("invalid IPv6 address: %q", peerIPv6)
	}
	ip = ip.To16()
	if ip == nil {
		return nil, fmt.Errorf("invalid IPv6 address: %q", peerIPv6)
	}
	// Check 0200::/7 (first 7 bits are 0b0010 000)
	if !in0200(ip) {
		return nil, fmt.Errorf("address %q not in 0200::/7", peerIPv6)
	}
	log.Printf("[p2p] [ns] dial tcp [%s]:%d", ip.String(), port)
	var p16 [16]byte
	copy(p16[:], ip)
	rfa := tcpip.FullAddress{NIC: ns.NICID, Addr: tcpip.AddrFrom16(p16), Port: uint16(port)}

	// Apply optional timeout via context.
	ctx := context.Background()
	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}

	c, err := gonet.DialContextTCP(ctx, ns.Stack, rfa, ipv6.ProtocolNumber)
	if err != nil {
		return nil, err
	}
	if timeout > 0 {
		_ = c.SetDeadline(time.Now().Add(timeout))
	}
	// Optional low-latency settings (if supported by gonet)
	var ic interface{} = c
	type noDelaySetter interface{ SetNoDelay(bool) error }
	type kaSetter interface {
		SetKeepAlive(bool) error
		SetKeepAlivePeriod(time.Duration) error
	}
	if nd, ok := ic.(noDelaySetter); ok {
		_ = nd.SetNoDelay(true)
	}
	if ka, ok := ic.(kaSetter); ok {
		_ = ka.SetKeepAlive(true)
		_ = ka.SetKeepAlivePeriod(30 * time.Second)
	}
	return c, nil
}

// ListenUDP exposes a net.PacketConn-like API backed by netstack for UDP.
func (ns *Netstack) ListenUDP(port int) (net.PacketConn, error) {
	if ns == nil || ns.Stack == nil {
		return nil, fmt.Errorf("netstack not started")
	}
	if port <= 0 || port > 65535 {
		return nil, fmt.Errorf("invalid port %d", port)
	}
	lfa := tcpip.FullAddress{NIC: ns.NICID, Addr: ns.addr, Port: uint16(port)}
	pc, err := gonet.DialUDP(ns.Stack, &lfa, nil, ipv6.ProtocolNumber)
	if err != nil {
		return nil, err
	}
	log.Printf("[p2p] [ns] listen udp [%s]:%d", ns.addr.String(), port)
	return pc, nil
}

// DialUDP dials a remote Ygg IPv6 + port using UDP.
func (ns *Netstack) DialUDP(peerIPv6 string, port int, timeout time.Duration) (net.PacketConn, tcpip.FullAddress, error) {
	if ns == nil || ns.Stack == nil {
		return nil, tcpip.FullAddress{}, fmt.Errorf("netstack not started")
	}
	if port <= 0 || port > 65535 {
		return nil, tcpip.FullAddress{}, fmt.Errorf("invalid port %d", port)
	}
	s := strings.TrimSpace(peerIPv6)
	if len(s) > 0 && s[0] == '[' && s[len(s)-1] == ']' {
		s = s[1 : len(s)-1]
	}
	ip := net.ParseIP(s)
	if ip == nil || ip.To4() != nil {
		return nil, tcpip.FullAddress{}, fmt.Errorf("invalid IPv6 address: %q", peerIPv6)
	}
	ip = ip.To16()
	if ip == nil {
		return nil, tcpip.FullAddress{}, fmt.Errorf("invalid IPv6 address: %q", peerIPv6)
	}
	if !in0200(ip) {
		return nil, tcpip.FullAddress{}, fmt.Errorf("address %q not in 0200::/7", peerIPv6)
	}
	var p16 [16]byte
	copy(p16[:], ip)
	rfa := tcpip.FullAddress{NIC: ns.NICID, Addr: tcpip.AddrFrom16(p16), Port: uint16(port)}

	// Bind ephemeral local UDP on our NIC/address.
	lfa := tcpip.FullAddress{NIC: ns.NICID, Addr: ns.addr}
	pc, err := gonet.DialUDP(ns.Stack, &lfa, &rfa, ipv6.ProtocolNumber)
	if err != nil {
		return nil, tcpip.FullAddress{}, err
	}
	log.Printf("[p2p] [ns] dial udp [%s]:%d", ip.String(), port)
	return pc, rfa, nil
}

// ListenTCP exposes netstack-backed listener from the node.
func (n *Node) ListenTCP(port int) (net.Listener, error) {
	if n == nil || n.Net == nil {
		return nil, fmt.Errorf("netstack not started")
	}
	return n.Net.ListenTCP(port)
}

// DialTCP dials peer via this node's netstack with a default timeout.
func (n *Node) DialTCP(peerIPv6 string, port int) (net.Conn, error) {
	if n == nil || n.Net == nil {
		return nil, fmt.Errorf("netstack not started")
	}
	return n.Net.DialTCP(peerIPv6, port, 10*time.Second)
}

// newNetstack wires Ygg core to gVisor netstack via ipv6rwc/channel endpoint.
func (n *Node) StartNetstack() (*Netstack, error) {
	if n == nil || n.Core == nil {
		return nil, fmt.Errorf("ygg core not initialized")
	}
	// Guard: if already running and not stopped, return immediately
	if n.Net != nil && !n.Net.stopped {
		return n.Net, nil
	}
	// L3 R/W link to Ygg core
	rwc := ipv6rwc.NewReadWriteCloser(n.Core)
	// Channel endpoint with larger queue and MTU 1280
	const mtu = 1280
	ep := channel.New(4096, uint32(mtu), "ygg-chan")
	st := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol},
	})
	// Enlarge TCP buffers for more stable signaling streams.
	_ = st.SetTransportProtocolOption(tcp.ProtocolNumber, &tcpip.TCPReceiveBufferSizeRangeOption{Min: 4 << 10, Default: 256 << 10, Max: 4 << 20})
	_ = st.SetTransportProtocolOption(tcp.ProtocolNumber, &tcpip.TCPSendBufferSizeRangeOption{Min: 4 << 10, Default: 256 << 10, Max: 4 << 20})
	nicID := tcpip.NICID(1)
	if err := st.CreateNIC(nicID, ep); err != nil {
		return nil, fmt.Errorf("create NIC: %w", err)
	}
	// Note: in this gVisor version, NIC is usable right after CreateNIC; no explicit SetNICUp.
	// Our Ygg /128 address
	ya := n.Core.Address() // net.IP
	if ya == nil || ya.To16() == nil || ya.To4() != nil {
		return nil, fmt.Errorf("bad ygg address")
	}
	y16 := ya.To16()
	if y16 == nil {
		return nil, fmt.Errorf("bad ygg v6 address")
	}
	var a16 [16]byte
	copy(a16[:], y16)
	yaddr := tcpip.AddrFrom16(a16)
	if err := st.AddProtocolAddress(nicID, tcpip.ProtocolAddress{
		Protocol: ipv6.ProtocolNumber,
		AddressWithPrefix: tcpip.AddressWithPrefix{
			Address:   yaddr,
			PrefixLen: 128,
		},
	}, stack.AddressProperties{}); err != nil {
		return nil, fmt.Errorf("add addr: %w", err)
	}
	log.Printf("[netstack] nic=%d ready, route 200::/7 via nic", nicID)
	log.Printf("[netstack] addr bound /128: %s", ya.String())
	// Default ::/0 via this NIC so all IPv6 traffic (incl. Ygg) has a path.
	st.AddRoute(tcpip.Route{Destination: header.IPv6Any.WithPrefix().Subnet(), NIC: nicID})

	// Our /64 on-link to prefer local-prefix peers.
	ap := tcpip.AddressWithPrefix{Address: yaddr, PrefixLen: 64}
	st.AddRoute(tcpip.Route{Destination: ap.Subnet(), NIC: nicID})

	// Explicit Ygg 200::/7 (optional but documents intent).
	var pfx200 [16]byte
	pfx200[0] = 0x02
	addr200 := tcpip.AddrFrom16(pfx200)
	sub200 := (tcpip.AddressWithPrefix{Address: addr200, PrefixLen: 7}).Subnet()
	st.AddRoute(tcpip.Route{Destination: sub200, NIC: nicID})
	ns := &Netstack{Stack: st, NICID: nicID, addr: yaddr, mtu: mtu, rwc: rwc, chEP: ep, stopCh: make(chan struct{})}
	n.Net = ns
	// TX pump: packets from netstack -> ygg core
	go func() {
		var txBytes uint64
		defer log.Printf("[netstack] tx stopped, bytes=%d", txBytes)
		for {
			select {
			case <-ns.stopCh:
				log.Printf("[netstack] tx stopping")
				return
			default:
			}
			pkt := ep.Read()
			if pkt == nil {
				// No outgoing packet currently; brief idle sleep.
				time.Sleep(2 * time.Millisecond)
				continue
			}
			view := pkt.ToView()
			b := view.AsSlice()
			pkt.DecRef()
			if len(b) == 0 {
				continue
			}
			off := 0
			for off < len(b) {
				n, err := rwc.Write(b[off:])
				if err != nil {
					if strings.Contains(err.Error(), "closed") || err == io.EOF {
						log.Printf("[netstack] tx: write closed: %v", err)
						return
					}
					log.Printf("[netstack] tx write error (will retry): %v", err)
					time.Sleep(5 * time.Millisecond)
					continue
				}
				if n <= 0 {
					time.Sleep(1 * time.Millisecond)
					continue
				}
				off += n
				txBytes += uint64(n)
			}
		}
	}()
	// RX pump: frames from ygg core -> netstack
	go func() {
		var rxBytes uint64
		defer log.Printf("[netstack] rx stopped, bytes=%d", rxBytes)
		buf := make([]byte, mtu)
		for {
			select {
			case <-ns.stopCh:
				return
			default:
			}
			nread, err := rwc.Read(buf)
			if err != nil {
				if err == io.EOF || err == io.ErrClosedPipe || strings.Contains(err.Error(), "closed") {
					return
				}
				log.Printf("[netstack] rx read error: %v", err)
				time.Sleep(10 * time.Millisecond)
				continue
			}
			if nread <= 0 {
				continue
			}
			rxBytes += uint64(nread)
			payload := make([]byte, nread)
			copy(payload, buf[:nread])
			pb := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(payload)})
			ep.InjectInbound(header.IPv6ProtocolNumber, pb)
			pb.DecRef()
		}
	}()
	log.Printf("[netstack] up: addr=%s mtu=%d", ya.String(), mtu)
	return ns, nil
}

// ErrNotConnected is returned when an operation requires an active Ygg link
// (at least one Up peer), but the node currently has none.
var ErrNotConnected = errors.New("ygg: not connected")

// Connected reports whether the node currently has at least one Up peer.
func (n *Node) Connected() bool {
	if n == nil || n.Core == nil {
		return false
	}
	return hasUp(n.Core)
}

// WaitConnected blocks until the node has at least one Up peer or the context
// is cancelled. The check runs at the given interval; if interval <= 0, 500ms
// is used. Returns nil when connected, ctx.Err() on cancellation/timeout.
func (n *Node) WaitConnected(ctx context.Context, interval time.Duration) error {
	if n == nil || n.Core == nil {
		return ErrNotConnected
	}
	if interval <= 0 {
		interval = 500 * time.Millisecond
	}
	// Fast path: already connected
	if hasUp(n.Core) {
		return nil
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
			if hasUp(n.Core) {
				return nil
			}
			// Nudge the core to retry peers faster while we wait
			n.Core.RetryPeersNow()
		}
	}
}

// Close attempts to gracefully stop the underlying core, if supported.
func (n *Node) Close() error {
	// stop background monitor if running
	if n != nil && n.monCancel != nil {
		n.monCancel()
		n.monCancel = nil
	}
	// stop in-process netstack if running
	if n != nil && n.Net != nil {
		_ = n.Net.Close()
		n.Net = nil
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

	// Note: we do not request OS TUN here. The process will run in user-space mode
	// and expose L3 via ipv6rwc to an in-process netstack (configured elsewhere).
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

// ListenTCP listens on the current default node's user-space netstack.
func ListenTCP(port int) (net.Listener, error) {
	if defaultNode == nil || defaultNode.Net == nil {
		return nil, fmt.Errorf("ygg: default node not initialized")
	}
	return defaultNode.ListenTCP(port)
}

// DialTCP dials a peer over the current default node's user-space netstack.
func DialTCP(peerIPv6 string, port int) (net.Conn, error) {
	if defaultNode == nil || defaultNode.Net == nil {
		return nil, fmt.Errorf("ygg: default node not initialized")
	}
	return defaultNode.DialTCP(peerIPv6, port)
}

// ListenUDP listens on the current default node's user-space netstack and returns
// a PacketConn bound to our Ygg IPv6 on the given port. Packets can be ReadFrom/WriteTo.
func ListenUDP(port int) (net.PacketConn, error) {
	if defaultNode == nil || defaultNode.Net == nil {
		return nil, fmt.Errorf("ygg: default node not initialized")
	}
	return defaultNode.Net.ListenUDP(port)
}

// DialUDP dials a peer over the current default node's user-space netstack and returns
// a connected PacketConn (Write/Read without specifying addr each time).
func DialUDP(peerIPv6 string, port int) (net.PacketConn, error) {
	if defaultNode == nil || defaultNode.Net == nil {
		return nil, fmt.Errorf("ygg: default node not initialized")
	}
	pc, _, err := defaultNode.Net.DialUDP(peerIPv6, port, 10*time.Second)
	return pc, err
}

// in0200 reports whether ip is in 0200::/7 (Yggdrasil space).
func in0200(ip net.IP) bool {
	b := ip.To16()
	if b == nil {
		return false
	}
	// 0200::/7 means the top 7 bits equal 0b0010 000.
	// Accept 0x20xx (0010 0000) and 0x30xx (0011 0000) as commonly used by Yggdrasil.
	return b[0]&0xFE == 0x02
}
