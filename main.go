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

	// gVisor netstack dependencies
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

const publicPeersURL = "https://publicpeers.neilalexander.dev/publicnodes.json"

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

// defaultNode lets package-level helpers (ListenTCP/DialTCP) reuse the last created node.
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
	// Default values if not set via setters.
	if maxPeers == 0 {
		maxPeers = 100
	}

	// Resolve config path if caller left it empty.
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

	logV("config path: %s", cfgPath)

	ac, err := LoadOrInitAppConfig(cfgPath)
	if err != nil {
		return nil, err
	}
	yc, err := PrepareYggConfig(ac)
	if err != nil {
		return nil, err
	}
	if e := SaveJSON(cfgPath, ac); e != nil {
		logV("warn: can't write config: %v", e)
	} else {
		logV("config saved (keys inline)")
	}

	startPeers := time.Now()
	logV("peers: static=%d", len(ac.Peers))
	var alive []string
	if len(ac.Peers) > 0 {
		logV("bg: fetching peers from %s", publicPeersURL)
		// We have peers in config: start ASAP with those that are alive.
		alive = FilterAlivePeers(ac.Peers, 2*time.Second, 16)
		logV("peers: alive_from_config=%d", len(alive))
		if len(alive) == 0 {
			// Fallback: try to fetch once synchronously
			if fromURL, err := fetchPeersFromURL(2 * time.Second); err == nil {
				ac.Peers = uniqUnion(ac.Peers, fromURL)
				if e := SaveJSON(cfgPath, ac); e != nil {
					logV("warn: can't save peers to config: %v", e)
				}
				alive = FilterAlivePeers(ac.Peers, 2*time.Second, 16)
				logV("peers: alive_after_merge=%d", len(alive))
			}
			if len(alive) == 0 {
				return nil, fmt.Errorf("peers: no alive peers")
			}
		}
		// Background one-shot refresh from URL (non-blocking).
		go func() {
			fromURL, err := fetchPeersFromURL(5 * time.Second)
			if err != nil {
				logV("peers refresh: fetch failed: %v", err)
				return
			}
			before := len(ac.Peers)
			ac.Peers = uniqUnion(ac.Peers, fromURL)
			added := len(ac.Peers) - before
			if added > 0 {
				if e := SaveJSON(cfgPath, ac); e != nil {
					logV("warn: can't save peers to config: %v", e)
				}
			}
			freshAlive := FilterAlivePeers(fromURL, 2*time.Second, 16)
			logV("peers updated: %d total (added=%d, alive_new=%d)", len(ac.Peers), added, len(freshAlive))
		}()
	} else {
		logV("fetching peers from %s", publicPeersURL)
		// No peers in config: block until we fetch fresh peers (retry with backoff).
		backoff := 2 * time.Second
		for {
			fromURL, err := fetchPeersFromURL(2 * time.Second)
			if err != nil {
				logV("peers: fetch failed: %v; retrying in %s", err, backoff)
				time.Sleep(backoff)
				if backoff < 30*time.Second {
					backoff *= 2
				}
				continue
			}
			alive = FilterAlivePeers(fromURL, 2*time.Second, 16)
			logV("peers: fetched=%d alive=%d (cold start)", len(fromURL), len(alive))
			if len(alive) == 0 {
				logV("peers: fetched but none alive; retrying in %s", backoff)
				time.Sleep(backoff)
				if backoff < 30*time.Second {
					backoff *= 2
				}
				continue
			}
			ac.Peers = uniqUnion(ac.Peers, fromURL)
			if e := SaveJSON(cfgPath, ac); e != nil {
				logV("warn: can't save peers to config: %v", e)
			}
			break
		}
	}

	logV("peers: ready=%d (took %s)", len(alive), time.Since(startPeers).Truncate(time.Millisecond))

	node, err := StartAndConnect(yc, alive, quietLogger{})
	if err != nil {
		return nil, err
	}
	// Start in-process netstack immediately (single-mode runtime, no OS utun).
	if _, err := node.StartNetstack(); err != nil {
		return nil, fmt.Errorf("start netstack: %w", err)
	}

	addr := node.Core.Address()
	keyHex := strings.TrimSpace(ac.Seed)
	if len(keyHex) >= 8 {
		logV("connected: %s (key fp=%s...)", addr.String(), keyHex[:8])
	} else {
		logV("connected: %s", addr.String())
	}

	// Start connectivity monitor if user installed a handler.
	if connectivityHandler != nil {
		node.startConnectivityMonitor(3 * time.Second)
	}
	// Expose as default for package-level helpers.
	defaultNode = node

	return node, nil
}

func init() {
	// Create the default data directory for examples.
	_ = os.MkdirAll(filepath.Join(".", "data"), 0o755)
}

type AppConfig struct {
	// Seed is the inline private key seed (empty => generate).
	Seed string `json:"seed,omitempty"`
	// Peers lists static peers (tcp://host:port, tls://..., quic://...).
	Peers []string `json:"peers"`
	// DialTimeoutSec controls connect timeouts.
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
	c.Peers = append(c.Peers, "tcp://37.186.113.100:1514",
		"quic://37.186.113.100:1515",
		"tls://37.186.113.100:1515",
		"ws://37.186.113.100:1516",
		"wss://ygg-evn-1.wgos.org:443",
		"tls://syd.joel.net.au:8443",
		"tls://sirsegv.moe:7676",
		"tls://yg-syd.magicum.net:23700",
		"quic://yg-syd.magicum.net:23701",
		"tls://yg-mel.magicum.net:23800",
		"quic://yg-mel.magicum.net:23801",
		"tls://109.176.250.101:65534",
		"tls://[2a02:1b8:10:147::1:1ea]:65534",
		"quic://ip6.casa2.mywire.org:44443?key=000000003cb1cc50e05147fc548f6d1f78e7ffcdc67b456f9bb0db6f0a5e4723",
		"tcp://Yggdrasil.UnderEu.Net:37001",
		"quic://Yggdrasil.UnderEu.Net:37003",
		"quic://ip6.casa2.mywire.org:44443?key=af4885c078c705dc0e21a696171f3d7878c48bd47164571590f29f38ed5a4573",
		"quic://scarlet.mboa.dev:3443",
		"tcp://ygg.nadeko.net:44441",
		"tls://ygg.nadeko.net:44442",
		"tls://[2a03:3b40:fe:ab::1]:993",
		"tls://37.205.14.171:993",
		"tcp://ygg-hel-1.wgos.org:45170",
		"tls://ygg-hel-1.wgos.org:45171",
		"quic://ygg-hel-1.wgos.org:45171",
		"ws://ygg-hel-1.wgos.org:45172",
		"tls://[2a01:4f9:2b:2d8f::2]:1337",
		"tls://95.217.35.92:1337",
		"tcp://[2001:470:1f13:e56::64]:39565",
		"tls://[2001:470:1f13:e56::64]:39575",
		"tcp://62.210.85.80:39565",
		"tls://62.210.85.80:39575",
		"tcp://s2.i2pd.xyz:39565",
		"tls://s2.i2pd.xyz:39575",
		"tcp://51.15.204.214:12345",
		"tls://51.15.204.214:54321",
		"tcp://yggpeer.tilde.green:53299",
		"tls://yggpeer.tilde.green:59454",
		"quic://yggpeer.tilde.green:62265",
		"tls://ygg.jholden.org:1555",
		"tls://n.ygg.yt:443",
		"quic://ip4.fvm.mywire.org:443?key=000000000143db657d1d6f80b5066dd109a4cb31f7dc6cb5d56050fffb014217",
		"tcp://ip4.fvm.mywire.org:8080?key=000000000143db657d1d6f80b5066dd109a4cb31f7dc6cb5d56050fffb014217",
		"quic://ip6.fvm.mywire.org:443?key=000000000143db657d1d6f80b5066dd109a4cb31f7dc6cb5d56050fffb014217",
		"tcp://ip6.fvm.mywire.org:8080?key=000000000143db657d1d6f80b5066dd109a4cb31f7dc6cb5d56050fffb014217",
		"tls://b.ygg.yt:443",
		"tls://g.ygg.yt:443",
		"tcp://ygg1.mk16.de:1337?key=0000000087ee9949eeab56bd430ee8f324cad55abf3993ed9b9be63ce693e18a",
		"tls://ygg1.mk16.de:1338?key=0000000087ee9949eeab56bd430ee8f324cad55abf3993ed9b9be63ce693e18a",
		"tcp://[2a0b:4142:e9e::2]:65535",
		"tcp://94.159.111.184:65535",
		"tls://vpn.ltha.de:443?key=0000006149970f245e6cec43664bce203f2514b60a153e194f31e2b229a1339d",
		"tcp://[2a0b:4142:ce0::2]:65535",
		"tcp://94.159.110.4:65535",
		"tcp://yggdrasil.su:62486",
		"tls://yggdrasil.su:62586",
		"tcp://87.251.77.39:65535",
		"quic://87.251.77.39:65535",
		"quic://[2a0c:b641:ce0::25d8:c5d6]:65535",
		"tcp://[2a0c:b641:ce0::25d8:c5d6]:65535",
		"quic://31.57.241.104:65535",
		"tcp://31.57.241.104:65535",
		"tcp://ygg2.mk16.de:1337?key=000000d80a2d7b3126ea65c8c08fc751088c491a5cdd47eff11c86fa1e4644ae",
		"tls://ygg2.mk16.de:1338?key=000000d80a2d7b3126ea65c8c08fc751088c491a5cdd47eff11c86fa1e4644ae",
		"tls://helium.avevad.com:1337",
		"tcp://ygg.mkg20001.io:80",
		"tls://ygg.mkg20001.io:443",
		"tls://91.98.126.143:32000",
		"tls://yggdrasil.neilalexander.dev:64648?key=ecbbcb3298e7d3b4196103333c3e839cfe47a6ca47602b94a6d596683f6bb358",
		"tcp://bode.theender.net:42069",
		"tls://bode.theender.net:42169?key=f91b909f43829f8b20732b3bcf80cbc4bb078dd47b41638379a078e35984c9a4",
		"quic://[2a0b:4142:e9e::2]:65535",
		"quic://94.159.111.184:65535",
		"quic://[2a0b:4142:ce0::2]:65535",
		"quic://94.159.110.4:65535",
		"tls://de-fsn-1.peer.v4.yggdrasil.chaz6.com:4444",
		"tls://mlupo.duckdns.org:9001",
		"tls://yg-hkg.magicum.net:32333",
		"quic://yg-hkg.magicum.net:32334",
		"ws://ygg1.grin.hu:42443",
		"tls://ygg1.grin.hu:42444",
		"tls://astrra.space:55535",
		"tls://133.18.201.69:54232",
		"tls://153.120.42.137:54232",
		"tls://yg-tyo.magicum.net:32333",
		"quic://yg-tyo.magicum.net:32334",
		"tls://srl.newsdeef.eu:59999",
		"tcp://srl.newsdeef.eu:9999",
		"tcp://vpn.itrus.su:7991",
		"tls://vpn.itrus.su:7992",
		"quic://vpn.itrus.su:7993",
		"ws://vpn.itrus.su:7994",
		"tcp://146.103.111.53:65535",
		"tcp://[2a14:1e00:3:15c::]:65535",
		"tcp://109.107.177.127:65535",
		"tcp://[2a0d:8480:3:234c::]:65535",
		"quic://[2a14:1e00:1:ecd::]:65535",
		"tcp://[2a14:1e00:1:ecd::]:65535",
		"quic://5.35.70.181:65535",
		"tcp://5.35.70.181:65535",
		"tcp://[2a14:1e00:1:f3c::]:65535",
		"quic://[2a14:1e00:1:f3c::]:65535",
		"quic://89.110.116.167:65535",
		"tcp://89.110.116.167:65535",
		"tcp://212.34.131.160:65535",
		"quic://212.34.131.160:65535",
		"tcp://[2a14:1e00:1:bae::]:65535",
		"quic://[2a14:1e00:1:bae::]:65535",
		"tcp://146.103.107.222:65535",
		"quic://146.103.107.222:65535",
		"tcp://[2a14:1e00:3:2b2::]:65535",
		"quic://[2a14:1e00:3:2b2::]:65535",
		"tls://23.137.249.65:444",
		"quic://[2a0d:8480:1:209e::]:65535",
		"tcp://[2a0d:8480:1:209e::]:65535",
		"tcp://88.210.10.78:65535",
		"quic://88.210.10.78:65535",
		"tcp://thatmaidguy.fvds.ru:7991",
		"quic://146.103.111.53:65535",
		"quic://[2a14:1e00:3:15c::]:65535",
		"quic://109.107.177.127:65535",
		"quic://[2a0d:8480:3:234c::]:65535",
		"tcp://ygg-nl.incognet.io:8883",
		"tls://ygg-nl.incognet.io:8884",
		"quic://ygg-nl.incognet.io:8885",
		"ws://ygg-nl.incognet.io:8886",
		"quic://185.181.60.111:1513?key=00defa4b4b243547f2d5641ac5235ff1e35d393c576e4bb9cd45baefc81e48d9",
		"tls://185.181.60.111:1513?key=00defa4b4b243547f2d5641ac5235ff1e35d393c576e4bb9cd45baefc81e48d9",
		"quic://[2a03:94e0:ffff:185:181:60:0:111]:1513?key=00defa4b4b243547f2d5641ac5235ff1e35d393c576e4bb9cd45baefc81e48d9",
		"tls://[2a03:94e0:ffff:185:181:60:0:111]:1513?key=00defa4b4b243547f2d5641ac5235ff1e35d393c576e4bb9cd45baefc81e48d9",
		"tls://185.165.169.234:8443",
		"tcp://185.165.169.234:8880",
		"tcp://45.137.99.182:1337",
		"tcp://srv.itrus.su:7991",
		"tls://srv.itrus.su:7992",
		"quic://srv.itrus.su:7993",
		"ws://srv.itrus.su:7994",
		"quic://ip4.01.msk.ru.dioni.su:9002",
		"tcp://ip4.01.msk.ru.dioni.su:9002",
		"tls://ip4.01.msk.ru.dioni.su:9003",
		"ws://ip4.01.msk.ru.dioni.su:9004",
		"quic://ip6.01.msk.ru.dioni.su:9002",
		"tcp://ip6.01.msk.ru.dioni.su:9002",
		"tls://ip6.01.msk.ru.dioni.su:9003",
		"ws://ip6.01.msk.ru.dioni.su:9004",
		"tcp://ip4.01.ekb.ru.dioni.su:9002",
		"quic://ip4.01.ekb.ru.dioni.su:9002",
		"tls://ip4.01.ekb.ru.dioni.su:9003",
		"ws://ip4.01.ekb.ru.dioni.su:9004",
		"tcp://ip6.01.ekb.ru.dioni.su:9002",
		"quic://ip6.01.ekb.ru.dioni.su:9002",
		"tls://ip6.01.ekb.ru.dioni.su:9003",
		"ws://ip6.01.ekb.ru.dioni.su:9004",
		"tcp://ip4.01.tom.ru.dioni.su:9002",
		"quic://ip4.01.tom.ru.dioni.su:9002",
		"tls://ip4.01.tom.ru.dioni.su:9003",
		"ws://ip4.01.tom.ru.dioni.su:9004",
		"tcp://[2a09:5302:ffff::132a]:65535",
		"quic://[2a09:5302:ffff::132a]:65535",
		"quic://89.44.86.85:65535",
		"tcp://89.44.86.85:65535",
		"tls://[2a09:5302:ffff::992]:443",
		"tcp://[2a09:5302:ffff::992]:12403",
		"tls://45.95.202.21:443",
		"tcp://45.95.202.21:12403",
		"tls://[2a00:b700::a:279]:443",
		"tcp://[2a00:b700::a:279]:12402",
		"tls://45.147.200.202:443",
		"tcp://45.147.200.202:12402",
		"ws://kursk.cleverfox.org:15016",
		"tcp://ygg-msk-1.averyan.ru:8363",
		"tcp://box.paulll.cc:13337",
		"tls://box.paulll.cc:13338",
		"tcp://188.225.9.167:18226",
		"tls://188.225.9.167:18227",
		"tcp://yggno.de:18226",
		"tls://yggno.de:18227",
		"tls://37.192.232.33:442",
		"tcp://37.192.232.33:8080",
		"tcp://yg-vvo.magicum.net:29330",
		"tls://yg-vvo.magicum.net:29331",
		"tcp://itcom.multed.com:7991",
		"tcp://195.58.51.167:7991",
		"tls://195.58.51.167:7992",
		"ws://195.58.51.167:7993",
		"tcp://kzn1.neonxp.ru:7991",
		"tls://kzn1.neonxp.ru:7992",
		"ws://kzn1.neonxp.ru:7993",
		"tcp://ekb.itrus.su:7991",
		"tls://ekb.itrus.su:7992",
		"quic://ekb.itrus.su:7993",
		"ws://ekb.itrus.su:7994",
		"tcp://yggdrasil.1337.moe:7676",
		"tcp://91.220.109.93:8080",
		"tls://kursk.cleverfox.org:15015",
		"quic://kursk.cleverfox.org:15015",
		"tls://ygg-msk-1.averyan.ru:8362",
		"quic://ygg-msk-1.averyan.ru:8364",
		"quic://vix.duckdns.org:36014",
		"tls://vix.duckdns.org:36014",
		"quic://195.58.51.167:7994",
		"quic://kzn1.neonxp.ru:7994",
		"tcp://195.2.74.155:7991",
		"tls://195.2.74.155:7992",
		"ws://195.2.74.155:7993",
		"quic://195.2.74.155:7994",
		"tcp://msk1.neonxp.ru:7991",
		"tls://msk1.neonxp.ru:7992",
		"ws://msk1.neonxp.ru:7993",
		"quic://msk1.neonxp.ru:7994",
		"tcp://pp1.ygg.sy.sa:8441",
		"tls://pp1.ygg.sy.sa:8442",
		"quic://pp1.ygg.sy.sa:8443",
		"quic://asia.deinfra.org:15015",
		"tls://asia.deinfra.org:15015",
		"tcp://y.zbin.eu:7743",
		"tcp://yggdrasil.deavmi.assigned.network:2000",
		"tls://yggdrasil.deavmi.assigned.network:2001",
		"tcp://[2a04:5b81:2011:1:dea6:32ff:fe0b:b610]:2000",
		"tls://[2a04:5b81:2011:1:dea6:32ff:fe0b:b610]:2001",
		"quic://spain.magicum.net:36900",
		"tls://spain.magicum.net:36901",
		"tcp://rendezvous.anton.molyboha.me:50421",
		"quic://[2a12:5940:b1a0::2]:65535",
		"tcp://[2a12:5940:b1a0::2]:65535",
		"quic://77.91.84.76:65535",
		"tcp://77.91.84.76:65535",
		"tcp://ygg.ace.ctrl-c.liu.se:9998?key=5636b3af4738c3998284c4805d91209cab38921159c66a6f359f3f692af1c908",
		"tls://ygg.ace.ctrl-c.liu.se:9999?key=5636b3af4738c3998284c4805d91209cab38921159c66a6f359f3f692af1c908",
		"tcp://sysop.link:555",
		"quic://sysop.link:555",
		"tcp://sto01.yggdrasil.hosted-by.skhron.eu:8883",
		"tls://sto01.yggdrasil.hosted-by.skhron.eu:8884",
		"quic://sto01.yggdrasil.hosted-by.skhron.eu:8885",
		"ws://sto01.yggdrasil.hosted-by.skhron.eu:8886",
		"tls://193.93.119.42:443",
		"ws://193.93.119.42:850",
		"quic://193.93.119.42:1443",
		"tcp://193.93.119.42:14244",
		"quic://yggdrasil.sunsung.fun:4441",
		"tcp://yggdrasil.sunsung.fun:4442",
		"tls://yggdrasil.sunsung.fun:4443",
		"tls://78.27.153.163:179",
		"tls://78.27.153.163:3784",
		"tls://78.27.153.163:3785",
		"tcp://78.27.153.163:33165",
		"tls://78.27.153.163:33166",
		"tls://london.sabretruth.org:18472",
		"tcp://london.sabretruth.org:18473",
		"tls://ygg.jjolly.dev:3443",
		"quic://ip4.nerdvm.mywire.org:443?key=00000000c61d731961a290d127cd3fc03a4c5f3f35b9083559d4c81d48d65854",
		"tcp://ip4.nerdvm.mywire.org:8080?key=00000000c61d731961a290d127cd3fc03a4c5f3f35b9083559d4c81d48d65854",
		"quic://ip6.nerdvm.mywire.org:443?key=00000000c61d731961a290d127cd3fc03a4c5f3f35b9083559d4c81d48d65854",
		"tcp://ip6.nerdvm.mywire.org:8080?key=00000000c61d731961a290d127cd3fc03a4c5f3f35b9083559d4c81d48d65854",
		"tcp://ygg3.mk16.de:1337?key=000003acdaf2a60e8de2f63c3e63b7e911d02380934f09ee5c83acb758f470c1",
		"tls://ygg3.mk16.de:1338?key=000003acdaf2a60e8de2f63c3e63b7e911d02380934f09ee5c83acb758f470c1",
		"tls://23.184.48.86:993",
		"quic://23.184.48.86:993",
		"quic://[2602:fc24:18:7a42::1]:993",
		"tls://[2602:fc24:18:7a42::1]:993",
		"tls://209.205.228.160:5621",
		"quic://mo.us.ygg.triplebit.org:443",
		"tls://mo.us.ygg.triplebit.org:993",
		"tcp://mo.us.ygg.triplebit.org:9000",
		"ws://mo.us.ygg.triplebit.org:9010",
		"tcp://leo.node.3dt.net:9002",
		"tls://leo.node.3dt.net:9003",
		"quic://leo.node.3dt.net:9004",
		"tcp://ygg-kcmo.incognet.io:8883",
		"tls://ygg-kcmo.incognet.io:8884",
		"quic://ygg-kcmo.incognet.io:8885",
		"ws://ygg-kcmo.incognet.io:8886",
		"quic://mn.us.ygg.triplebit.org:443",
		"tls://mn.us.ygg.triplebit.org:993",
		"tcp://mn.us.ygg.triplebit.org:9000",
		"ws://mn.us.ygg.triplebit.org:9010",
		"tcp://neo.node.3dt.net:9002",
		"tls://neo.node.3dt.net:9003",
		"quic://neo.node.3dt.net:9004",
		"tcp://longseason.1200bps.xyz:13121",
		"tls://longseason.1200bps.xyz:13122",
		"tcp://srv.newsdeef.eu:9999",
		"tls://srv.newsdeef.eu:59999",
		"tcp://ygg-pa.incognet.io:8883",
		"tls://ygg-pa.incognet.io:8884",
		"quic://ygg-pa.incognet.io:8885",
		"ws://ygg-pa.incognet.io:8886",
		"tcp://129.80.167.244:23163",
		"tls://129.80.167.244:23164",
		"quic://129.80.167.244:23165",
		"ws://129.80.167.244:23166",
		"tcp://[2603:c020:4015:b937:a1c7:aff8:b558:d1fe]:23163",
		"tls://[2603:c020:4015:b937:a1c7:aff8:b558:d1fe]:23164",
		"quic://[2603:c020:4015:b937:a1c7:aff8:b558:d1fe]:23165",
		"ws://[2603:c020:4015:b937:a1c7:aff8:b558:d1fe]:23166",
		"tcp://ygg-wa.incognet.io:8883",
		"tls://ygg-wa.incognet.io:8884",
		"quic://ygg-wa.incognet.io:8885",
		"ws://ygg-wa.incognet.io:8886",
		"quic://redcatho.de:9494",
		"tls://redcatho.de:9494",
		"tls://ygg.mnpnk.com:443",
		"tls://44.234.134.124:443",
		"quic://ip4.nerdvm.mywire.org:443?key=6342592a45a234afce0966610217f798e4898f6b1607d354fb126c239d05abf7",
		"tcp://ip4.nerdvm.mywire.org:8080?key=6342592a45a234afce0966610217f798e4898f6b1607d354fb126c239d05abf7",
		"quic://ip6.nerdvm.mywire.org:443?key=6342592a45a234afce0966610217f798e4898f6b1607d354fb126c239d05abf7",
		"tcp://ip6.nerdvm.mywire.org:8080?key=6342592a45a234afce0966610217f798e4898f6b1607d354fb126c239d05abf7",
		"tcp://micr0.dev:7991",
		"tls://micr0.dev:7992")
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

// Netstack wraps an in-process gVisor TCP/IP stack bridged to the Yggdrasil core via ipv6rwc.
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

// AddrString returns our Ygg IPv6 as string.
func (ns *Netstack) AddrString() string {
	if ns == nil {
		return ""
	}
	return ns.addr.String()
}

// Addr returns our Ygg IPv6 as net.IP.
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
	logV("[netstack] closed")
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
	logV("[p2p] [ns] listen tcp [%s]:%d", ns.addr.String(), port)
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
	logV("[p2p] [ns] dial tcp [%s]:%d", ip.String(), port)
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
	// Optional low-latency settings (if supported by gonet).
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

// ListenUDP returns an unconnected UDP PacketConn bound to our Ygg IPv6. In gonet, DialUDP with raddr=nil yields an unconnected socket that supports ReadFrom/WriteTo.
func (ns *Netstack) ListenUDP(port int) (net.PacketConn, error) {
	if ns == nil || ns.Stack == nil {
		return nil, fmt.Errorf("netstack not started")
	}
	if port <= 0 || port > 65535 {
		return nil, fmt.Errorf("invalid port %d", port)
	}
	// Bind a UDP endpoint without a remote; gonet.DialUDP(lfa, nil) returns an
	// unconnected PacketConn that supports ReadFrom/WriteTo.
	lfa := tcpip.FullAddress{NIC: ns.NICID, Addr: ns.addr, Port: uint16(port)}
	pc, err := gonet.DialUDP(ns.Stack, &lfa, nil, ipv6.ProtocolNumber)
	if err != nil {
		return nil, err
	}
	logV("[p2p] [ns] listen udp [%s]:%d", ns.addr.String(), port)
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
	logV("[p2p] [ns] dial udp [%s]:%d", ip.String(), port)
	return pc, rfa, nil
}

// ListenTCP exposes a netstack-backed listener from the node.
func (n *Node) ListenTCP(port int) (net.Listener, error) {
	if n == nil || n.Net == nil {
		return nil, fmt.Errorf("netstack not started")
	}
	return n.Net.ListenTCP(port)
}

// DialTCP dials a peer via this node's netstack with a default timeout.
func (n *Node) DialTCP(peerIPv6 string, port int) (net.Conn, error) {
	if n == nil || n.Net == nil {
		return nil, fmt.Errorf("netstack not started")
	}
	return n.Net.DialTCP(peerIPv6, port, 10*time.Second)
}

// StartNetstack wires the Yggdrasil core to the gVisor netstack via an ipv6rwc/channel endpoint.
func (n *Node) StartNetstack() (*Netstack, error) {
	if n == nil || n.Core == nil {
		return nil, fmt.Errorf("ygg core not initialized")
	}
	// Guard: if already running and not stopped, return immediately.
	if n.Net != nil && !n.Net.stopped {
		return n.Net, nil
	}
	// L3 R/W link to Ygg core.
	rwc := ipv6rwc.NewReadWriteCloser(n.Core)
	// Channel endpoint with larger queue and MTU 1280.
	const mtu = 1280
	ep := channel.New(4096, uint32(mtu), "ygg-chan")
	st := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol},
	})
	// Enlarge transport buffers to better absorb bursts.
	_ = st.SetOption(tcpip.ReceiveBufferSizeOption{Min: 4 << 10, Default: 512 << 10, Max: 4 << 20})
	_ = st.SetOption(tcpip.SendBufferSizeOption{Min: 4 << 10, Default: 512 << 10, Max: 4 << 20})
	_ = st.SetTransportProtocolOption(tcp.ProtocolNumber, &tcpip.TCPReceiveBufferSizeRangeOption{Min: 4 << 10, Default: 256 << 10, Max: 4 << 20})
	_ = st.SetTransportProtocolOption(tcp.ProtocolNumber, &tcpip.TCPSendBufferSizeRangeOption{Min: 4 << 10, Default: 256 << 10, Max: 4 << 20})
	nicID := tcpip.NICID(1)
	if err := st.CreateNIC(nicID, ep); err != nil {
		return nil, fmt.Errorf("create NIC: %w", err)
	}
	// Note: in this gVisor version, NIC is usable right after CreateNIC; no explicit SetNICUp.
	// Our Ygg /128 address.
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
	logV("[netstack] nic=%d ready, route 200::/7 via nic", nicID)
	logV("[netstack] addr bound /128: %s", ya.String())
	// Default ::/0 via this NIC so all IPv6 traffic (including Ygg) has a path.
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
	// TX pump: packets from netstack -> ygg core.
	go func() {
		var txBytes uint64
		defer logV("[netstack] tx stopped, bytes=%d", txBytes)
		for {
			select {
			case <-ns.stopCh:
				logV("[netstack] tx stopping")
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
					logV("[netstack] tx write error (will retry): %v", err)
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
	// RX pump: frames from ygg core -> netstack.
	go func() {
		var rxBytes uint64
		defer logV("[netstack] rx stopped, bytes=%d", rxBytes)
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
				logV("[netstack] rx read error: %v", err)
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
	logV("[netstack] up: addr=%s mtu=%d", ya.String(), mtu)
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

// PrepareYggConfig generates or loads keys into ycfg.NodeConfig.
func PrepareYggConfig(app *AppConfig) (*ycfg.NodeConfig, error) {
	cfg := ycfg.GenerateConfig() // sane defaults; will be overridden below.

	loadedExisting := false

	// Step 1: read key in multiple formats (hex or base64/base64url, 32/64 bytes).
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
		// Step 2: standardize config to a 32-byte base64url seed.
		seed := []byte(cfg.PrivateKey)[:32]
		app.Seed = base64.RawURLEncoding.EncodeToString(seed)
		loadedExisting = true
	}

	// Step 3: if no key was loaded, generate a new one.
	if !loadedExisting {
		_, genPriv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("generate ed25519 key: %w", err)
		}
		cfg.PrivateKey = ycfg.KeyBytes(genPriv)
		// Store only the 32-byte seed to keep config compact.
		app.Seed = base64.RawURLEncoding.EncodeToString([]byte(cfg.PrivateKey)[:32])
		logV("generated new private key (saved to config.json)")
	} else {
		logV("using private key from config.json")
	}

	// Step 4: ensure the core has a TLS certificate.
	if cfg.Certificate == nil {
		if err := cfg.GenerateSelfSignedCertificate(); err != nil {
			return nil, err
		}
	}

	return cfg, nil
}

// StartAndConnect starts the core and connects to peers until the first one is up.
func StartAndConnect(cfg *ycfg.NodeConfig, peers []string, logger ycore.Logger) (*Node, error) {
	t0 := time.Now()
	// Force core to use the same ed25519 key as in cfg.PrivateKey (ignore cfg.Certificate).
	if len(cfg.PrivateKey) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("cfg.PrivateKey length=%d, want %d", len(cfg.PrivateKey), ed25519.PrivateKeySize)
	}
	cert, err := certFromPrivateKey(ed25519.PrivateKey(cfg.PrivateKey))
	if err != nil {
		return nil, fmt.Errorf("make cert: %w", err)
	}

	// Build setup options from cfg.
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

	// Note: we do not request OS TUN here. The process runs in user-space mode
	// and exposes L3 via ipv6rwc to an in-process netstack (configured elsewhere).
	core, err := ycore.New(cert, logger, opts...)
	if err != nil {
		return nil, err
	}
	logV("core: adding peers=%d", len(peers))
	// Add peers to the autodial table.
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

	// Wait for the first Up peer.
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
