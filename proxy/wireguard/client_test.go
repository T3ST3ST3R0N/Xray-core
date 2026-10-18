package wireguard

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	stdnet "net"
	"net/netip"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/features/dns"
	"github.com/xtls/xray-core/transport/internet"
	"golang.org/x/crypto/curve25519"
	"golang.zx2c4.com/wireguard/conn"
)

type testDNS struct {
	fail atomic.Bool
	ips  []net.IP
}

func (*testDNS) Type() interface{} { return dns.ClientType() }
func (*testDNS) Start() error      { return nil }
func (*testDNS) Close() error      { return nil }
func (d *testDNS) LookupIP(string, dns.IPOption) ([]net.IP, uint32, error) {
	if d.fail.Load() {
		return nil, 0, errors.New("lookup failed")
	}
	return d.ips, 600, nil
}

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

func newTestClient(t *testing.T, endpoint string, d *testDNS) *Handler {
	t.Helper()
	priv, _ := testKey(t)
	_, peerPub := testKey(t)
	tun, tnet, _, err := CreateNetTUN([]netip.Addr{netip.MustParseAddr("10.0.0.2")}, nil, 1420, true)
	if err != nil {
		t.Fatal(err)
	}
	h := &Handler{
		conf: &DeviceConfig{
			SecretKey: priv,
			Peers:     []*PeerConfig{{PublicKey: peerPub, Endpoint: endpoint, AllowedIps: []string{"0.0.0.0/0"}}},
		},
		dns:            d,
		streamSettings: &internet.MemoryStreamConfig{},
		tun:            tun,
		tnet:           tnet,
	}
	t.Cleanup(func() { h.Close() })
	return h
}

// A failed init must not leave a device behind: each one reads the shared
// TUN, so after a later successful init the leftovers would take packets
// meant for the working device.
func TestClientInitRetryKeepsOneDevice(t *testing.T) {
	d := &testDNS{ips: []net.IP{net.ParseIP("127.0.0.1")}}
	d.fail.Store(true)
	h := newTestClient(t, "localhost:51820", d)

	if err := h.init(context.Background()); err == nil {
		t.Fatal("init succeeded although the endpoint does not resolve")
	}
	time.Sleep(100 * time.Millisecond)
	before := runtime.NumGoroutine()
	for i := 0; i < 5; i++ {
		if err := h.init(context.Background()); err == nil {
			t.Fatal("init succeeded although the endpoint does not resolve")
		}
	}
	time.Sleep(100 * time.Millisecond)
	if n := runtime.NumGoroutine(); n > before+runtime.NumCPU() {
		t.Fatalf("goroutines grew from %d to %d over 5 failed inits", before, n)
	}
	d.fail.Store(false)
	if err := h.init(context.Background()); err != nil {
		t.Fatal(err)
	}
}

// The bind socket must come up for an endpoint that only Xray's DNS knows.
func TestClientEndpointResolvedByXrayDNS(t *testing.T) {
	h := newTestClient(t, "wg.test:51820", &testDNS{ips: []net.IP{net.ParseIP("127.0.0.1")}})
	if err := h.init(context.Background()); err != nil {
		t.Fatal(err)
	}
}

// Without a domain strategy, a relay name with A and AAAA records must not
// resolve to the IPv6 address at random: hosts without IPv6 would then never
// reach the relay.
func TestResolveLocalPrefersIPv4(t *testing.T) {
	h := &Handler{
		dns:            &testDNS{ips: []net.IP{net.ParseIP("2001:db8::1"), net.ParseIP("192.0.2.1")}},
		streamSettings: &internet.MemoryStreamConfig{},
	}
	for i := 0; i < 50; i++ {
		ip, err := h.resolveLocal("relay.test")
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

func TestClientDialerProxyFallbackBatchBound(t *testing.T) {
	d := &testDNS{}
	d.fail.Store(true)
	h := newTestClient(t, "wg.test:51820", d)
	h.streamSettings.SocketSettings = &internet.SocketConfig{DialerProxy: "relay"}
	h.conf.Reserved = []byte{1, 2, 3}
	// Leave the configured device available before its listener can open.
	// A dialerProxy returns a custom PacketConn, not a native UDP socket.
	if err := h.init(context.Background()); err == nil {
		t.Fatal("init succeeded despite failed endpoint resolution")
	}
	if h.dev == nil {
		t.Fatal("init did not create the device")
	}
	b := h.dev.Bind().(*bind)
	if b.BatchSize() != 1 {
		t.Fatalf("dialerProxy advertised a pre-open batch of %d packets", b.BatchSize())
	}
	// Stop device workers before exercising its constructed bind directly.
	h.dev.Close()
	local := newUDPClientTestSocket(t, "udp4", "127.0.0.1:0")
	peer := newUDPClientTestSocket(t, "udp4", "127.0.0.1:0")
	wrapped := &wrappedTestPacketConn{PacketConn: local}
	rc, wc := &testCounter{}, &testCounter{}
	b.listenFunc = func() (net.PacketConn, error) {
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
