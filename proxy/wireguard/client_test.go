package wireguard

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"testing"

	dnsapp "github.com/xtls/xray-core/app/dns"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/geodata"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/dns"
	"github.com/xtls/xray-core/features/outbound"
	"github.com/xtls/xray-core/transport/internet"
	"golang.org/x/crypto/curve25519"
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
