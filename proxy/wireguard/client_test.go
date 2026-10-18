package wireguard

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	stdnet "net"
	"testing"
	"time"

	dnsapp "github.com/xtls/xray-core/app/dns"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/geodata"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/dns"
	"github.com/xtls/xray-core/features/outbound"
	"github.com/xtls/xray-core/transport/internet"
	"golang.org/x/crypto/curve25519"
	"golang.zx2c4.com/wireguard/conn"
)

type testDNS struct{ ips []net.IP }

func (*testDNS) Type() interface{} { return dns.ClientType() }
func (*testDNS) Start() error      { return nil }
func (*testDNS) Close() error      { return nil }
func (d *testDNS) LookupIP(string, dns.IPOption) ([]net.IP, uint32, error) {
	return d.ips, 600, nil
}

// untagged is the outbound handler NewClient reads its tag from.
type untagged struct{ outbound.Handler }

func (untagged) Tag() string { return "" }

func testKey(t *testing.T) (priv, pub string) {
	var k [32]byte
	if _, err := rand.Read(k[:]); err != nil {
		t.Fatal(err)
	}
	p, err := curve25519.X25519(k[:], curve25519.Basepoint)
	if err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(k[:]), hex.EncodeToString(p)
}

// The bind socket must come up for an endpoint that only Xray's DNS knows.
func TestClientEndpointResolvedByXrayDNS(t *testing.T) {
	v, err := core.New(&core.Config{App: []*serial.TypedMessage{serial.ToTypedMessage(&dnsapp.Config{
		StaticHosts: []*dnsapp.Config_HostMapping{{
			Domain: &geodata.DomainRule{Value: &geodata.DomainRule_Custom{Custom: &geodata.Domain{Type: geodata.Domain_Full, Value: "wg.test"}}},
			Ip:     [][]byte{{127, 0, 0, 1}},
		}},
	})}})
	common.Must(err)
	ctx := context.WithValue(context.Background(), core.XrayKey(1), v)
	ctx = session.ContextWithStreamSettings(ctx, &internet.MemoryStreamConfig{})
	ctx = session.ContextWithFullHandler(ctx, untagged{})

	priv, _ := testKey(t)
	_, peerPub := testKey(t)
	h, err := NewClient(ctx, &DeviceConfig{
		IsClient:    true,
		NoKernelTun: true,
		SecretKey:   priv,
		Endpoint:    []string{"10.0.0.2"},
		Mtu:         1420,
		Peers:       []*PeerConfig{{PublicKey: peerPub, Endpoint: "wg.test:51820", AllowedIps: []string{"0.0.0.0/0"}}},
	})
	common.Must(err)
	t.Cleanup(func() { h.Close() })
	if err := h.up(context.Background()); err != nil {
		t.Fatal(err)
	}
}

// Without a domain strategy, a relay name with A and AAAA records must not
// resolve to the IPv6 address at random: hosts without IPv6 would then never
// reach the relay.
func TestResolveLocalPrefersIPv4(t *testing.T) {
	resolve := MakeResolveLocal(&testDNS{ips: []net.IP{net.ParseIP("2001:db8::1"), net.ParseIP("192.0.2.1")}}, &internet.MemoryStreamConfig{})
	for i := 0; i < 50; i++ {
		ip, err := resolve("relay.test")
		if err != nil {
			t.Fatal(err)
		}
		if ip.To4() == nil {
			t.Fatalf("got %v, want the IPv4 address", ip)
		}
	}
}

func newUDPClientTestSocket(tb testing.TB, network, address string) *stdnet.UDPConn {
	tb.Helper()
	addr, err := stdnet.ResolveUDPAddr(network, address)
	if err != nil {
		tb.Fatal(err)
	}
	c, err := stdnet.ListenUDP(network, addr)
	if err != nil {
		if network == "udp6" {
			tb.Skipf("IPv6 loopback unavailable: %v", err)
		}
		tb.Fatal(err)
	}
	tb.Cleanup(func() { c.Close() })
	if err := c.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		tb.Fatal(err)
	}
	return c
}

func TestUDPConnClientTargetsAndReplies(t *testing.T) {
	for _, family := range []struct{ network, address string }{{"udp4", "127.0.0.1:0"}, {"udp6", "[::1]:0"}} {
		for _, fallback := range []bool{false, true} {
			name := family.network + "/native"
			if fallback {
				name = family.network + "/wrapped"
			}
			t.Run(name, func(t *testing.T) {
				local := newUDPClientTestSocket(t, family.network, family.address)
				primary := newUDPClientTestSocket(t, family.network, family.address)
				other := newUDPClientTestSocket(t, family.network, family.address)
				var pc stdnet.PacketConn = local
				if fallback {
					pc = struct{ stdnet.PacketConn }{local}
				}
				client := &UDPConnClient{PacketConn: pc, Dest: primary.LocalAddr().(*stdnet.UDPAddr)}
				primaryDest := net.DestinationFromAddr(primary.LocalAddr())
				otherDest := net.DestinationFromAddr(other.LocalAddr())
				domainDest := net.UDPDestination(net.DomainAddress("target.example"), otherDest.Port)
				targets := []*net.Destination{nil, &primaryDest, &otherDest, &domainDest}
				mb := make(buf.MultiBuffer, 0, len(targets))
				for i, target := range targets {
					b := buf.New()
					b.Write([]byte{byte(i)})
					b.UDP = target
					mb = append(mb, b)
				}
				if err := client.WriteMultiBuffer(mb); err != nil {
					t.Fatal(err)
				}
				for i, target := range []*stdnet.UDPConn{primary, primary, other, other} {
					var payload [8]byte
					n, source, err := target.ReadFromUDPAddrPort(payload[:])
					if err != nil || n != 1 || payload[0] != byte(i) {
						t.Fatalf("target packet %d: n=%d err=%v payload=%v", i, n, err, payload[:n])
					}
					if _, err := target.WriteToUDPAddrPort(payload[:n], source); err != nil {
						t.Fatal(err)
					}
					mb, err := client.ReadMultiBuffer()
					if err != nil {
						t.Fatal(err)
					}
					want := net.DestinationFromAddr(target.LocalAddr())
					valid := len(mb) == 1 && bytes.Equal(mb[0].Bytes(), []byte{byte(i)}) && *mb[0].UDP == want
					buf.ReleaseMulti(mb)
					if !valid {
						t.Fatalf("reply %d lost payload or source address", i)
					}
				}
			})
		}
	}
}

func newBindTestClient(t *testing.T, settings *internet.MemoryStreamConfig) *Handler {
	t.Helper()
	v, err := core.New(&core.Config{App: []*serial.TypedMessage{serial.ToTypedMessage(&dnsapp.Config{})}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { v.Close() })
	ctx := context.WithValue(context.Background(), core.XrayKey(1), v)
	ctx = session.ContextWithStreamSettings(ctx, settings)
	ctx = session.ContextWithFullHandler(ctx, untagged{})
	priv, _ := testKey(t)
	_, pub := testKey(t)
	h, err := NewClient(ctx, &DeviceConfig{
		IsClient: true, NoKernelTun: true, SecretKey: priv,
		Endpoint: []string{"10.0.0.2"}, Mtu: 1420, Reserved: []byte{1, 2, 3},
		Peers: []*PeerConfig{{PublicKey: pub, Endpoint: "127.0.0.1:51820", AllowedIps: []string{"0.0.0.0/0"}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { h.Close() })
	return h
}

func TestClientReusesDeviceAndUpdatesBindContext(t *testing.T) {
	h := newBindTestClient(t, &internet.MemoryStreamConfig{})
	dev, b := h.dev, h.bind
	if b.BatchSize() != batchSize {
		t.Fatalf("native pre-open batch = %d, want %d", b.BatchSize(), batchSize)
	}
	type contextKey struct{}
	opened := make(chan int, 2)
	b.listenFunc = func(ctx context.Context) (net.PacketConn, error) {
		opened <- ctx.Value(contextKey{}).(int)
		return stdnet.ListenPacket("udp4", "127.0.0.1:0")
	}
	for i := 1; i <= 2; i++ {
		ctx := context.WithValue(context.Background(), contextKey{}, i)
		if err := h.up(ctx); err != nil {
			t.Fatal(err)
		}
		if h.dev != dev || h.bind != b || h.ipc != "" {
			t.Fatal("up replaced the device/bind or retained applied peer configuration")
		}
		if got := <-opened; got != i {
			t.Fatalf("listener context = %d, want %d", got, i)
		}
		if err := dev.Down(); err != nil {
			t.Fatal(err)
		}
	}
}

func TestClientDialerProxyFallbackBatchBound(t *testing.T) {
	h := newBindTestClient(t, &internet.MemoryStreamConfig{
		SocketSettings: &internet.SocketConfig{DialerProxy: "relay"},
	})
	b := h.bind
	if b.BatchSize() != 1 {
		t.Fatalf("dialerProxy advertised a pre-open batch of %d packets", b.BatchSize())
	}
	// Stop device workers before exercising its constructed bind directly.
	h.Close()
	local := newUDPClientTestSocket(t, "udp4", "127.0.0.1:0")
	peer := newUDPClientTestSocket(t, "udp4", "127.0.0.1:0")
	wrapped := &wrappedTestPacketConn{PacketConn: local}
	rc, wc := &testCounter{}, &testCounter{}
	b.listenFunc = func(context.Context) (net.PacketConn, error) {
		return &PacketCounterConnection{PacketConn: wrapped, ReadCounter: rc, WriteCounter: wc}, nil
	}
	fns, _, err := b.Open(0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { b.Close() })
	ep := &conn.StdNetEndpoint{AddrPort: peer.LocalAddr().(*stdnet.UDPAddr).AddrPort()}
	if err := b.Send([][]byte{{4, 0, 0, 0, 9}}, ep); err != nil {
		t.Fatal(err)
	}
	var packet [32]byte
	n, _, err := peer.ReadFromUDP(packet[:])
	if err != nil || !bytes.Equal(packet[:n], []byte{4, 1, 2, 3, 9}) {
		t.Fatalf("custom send lost payload/reserved bytes: n=%d err=%v", n, err)
	}
	if _, err := peer.WriteToUDP(packet[:n], local.LocalAddr().(*stdnet.UDPAddr)); err != nil {
		t.Fatal(err)
	}
	reads, sizes := [][]byte{make([]byte, 32)}, make([]int, 1)
	eps := make([]conn.Endpoint, 1)
	if n, err := fns[0](reads, sizes, eps); err != nil || n != 1 || !bytes.Equal(reads[0][:sizes[0]], []byte{4, 0, 0, 0, 9}) {
		t.Fatalf("custom receive lost payload: n=%d err=%v", n, err)
	}
	if b.BatchSize() != 1 || b.batch != nil || wrapped.reads.Load() != 1 || wrapped.writes.Load() != 1 ||
		rc.Value() != 5 || wc.Value() != 5 {
		t.Fatalf("custom transport bypassed wrappers/counters or grew its batch: batch=%d read=%d write=%d", b.BatchSize(), rc.Value(), wc.Value())
	}
}
