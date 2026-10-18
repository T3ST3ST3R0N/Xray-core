package wireguard

import (
	"bytes"
	"context"
	"net"
	"net/netip"
	"os"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"golang.org/x/net/ipv6"
	"golang.zx2c4.com/wireguard/conn"
)

type testCounter struct{ v atomic.Int64 }

func (c *testCounter) Value() int64      { return c.v.Load() }
func (c *testCounter) Set(n int64) int64 { return c.v.Swap(n) }
func (c *testCounter) Add(n int64) int64 { return c.v.Add(n) - n }

// openTestBind opens a bind on a loopback UDP socket wrapped like client.go
// does when stats are enabled.
func openTestBind(t *testing.T, network, addr string, reserved []byte) (*bind, conn.ReceiveFunc, *testCounter, *testCounter) {
	t.Helper()
	rc, wc := &testCounter{}, &testCounter{}
	b := &bind{
		reserved:     reserved,
		batchEnabled: true,
		listenFunc: func(context.Context) (net.PacketConn, error) {
			c, err := net.ListenPacket(network, addr)
			if err != nil {
				return nil, err
			}
			return &PacketCounterConnection{PacketConn: c, ReadCounter: rc, WriteCounter: wc}, nil
		},
	}
	fns, _, err := b.Open(0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = b.Close() })
	return b, fns[0], rc, wc
}

func testPacket(i int) []byte {
	p := make([]byte, 100+i)
	p[0] = 4
	for j := 4; j < len(p); j++ {
		p[j] = byte(i)
	}
	return p
}

func testBindRoundTrip(t *testing.T, network, bindAddr, peerAddr string, wantBatch bool) {
	b, recv, rc, wc := openTestBind(t, network, bindAddr, []byte{1, 2, 3})
	if (b.batch != nil) != wantBatch {
		t.Fatalf("batch = %v, want %v", b.batch != nil, wantBatch)
	}
	peer, err := net.ListenPacket("udp", peerAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	peerAP := peer.LocalAddr().(*net.UDPAddr).AddrPort()

	// Send: every datagram arrives intact, with the reserved bytes set.
	const count = 200 // more than conn.IdealBatchSize
	bufs := make([][]byte, count)
	var total int64
	for i := range bufs {
		bufs[i] = testPacket(i % 50)
		total += int64(len(bufs[i]))
	}
	if err := b.Send(bufs, &conn.StdNetEndpoint{AddrPort: peerAP}); err != nil {
		t.Fatal(err)
	}
	_ = peer.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 2048)
	for i := 0; i < count; i++ {
		n, _, err := peer.ReadFrom(buf)
		if err != nil {
			t.Fatalf("datagram %d: %v", i, err)
		}
		want := testPacket(i % 50)
		copy(want[1:4], []byte{1, 2, 3})
		if !bytes.Equal(buf[:n], want) {
			t.Fatalf("datagram %d differs", i)
		}
	}
	if wc.Value() != total {
		t.Fatalf("write counter = %d, want %d", wc.Value(), total)
	}

	// Receive: datagrams come back with the reserved bytes cleared and the
	// peer as endpoint.
	bindAP := netip.AddrPortFrom(peerAP.Addr(), uint16(b.LocalAddr().(*net.UDPAddr).Port))
	total = 0
	for i := 0; i < count; i++ {
		p := testPacket(i % 50)
		copy(p[1:4], []byte{9, 9, 9})
		total += int64(len(p))
		if _, err := peer.WriteTo(p, net.UDPAddrFromAddrPort(bindAP)); err != nil {
			t.Fatal(err)
		}
	}
	rbufs := make([][]byte, b.BatchSize())
	for i := range rbufs {
		rbufs[i] = make([]byte, 2048)
	}
	sizes := make([]int, len(rbufs))
	eps := make([]conn.Endpoint, len(rbufs))
	got := 0
	for got < count {
		n, err := recv(rbufs, sizes, eps)
		if err != nil {
			t.Fatal(err)
		}
		for i := 0; i < n; i++ {
			want := testPacket((got + i) % 50)
			if !bytes.Equal(rbufs[i][:sizes[i]], want) {
				t.Fatalf("received datagram %d differs", got+i)
			}
			ep := eps[i].(*conn.StdNetEndpoint).AddrPort
			if ep.Addr().Unmap() != peerAP.Addr().Unmap() || ep.Port() != peerAP.Port() {
				t.Fatalf("endpoint = %v, want %v", ep, peerAP)
			}
		}
		got += n
	}
	if rc.Value() != total {
		t.Fatalf("read counter = %d, want %d", rc.Value(), total)
	}

	// Close ends a pending receive with net.ErrClosed.
	done := make(chan error, 1)
	go func() {
		_, err := recv(rbufs, sizes, eps)
		done <- err
	}()
	time.Sleep(50 * time.Millisecond)
	_ = b.Close()
	select {
	case err := <-done:
		if err != net.ErrClosed {
			t.Fatalf("receive after close: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("receive did not return after close")
	}
}

func TestBindIPv4(t *testing.T) {
	testBindRoundTrip(t, "udp4", "127.0.0.1:0", "127.0.0.1:0", batchSize > 1)
}

// Xray's dialer listens on a dual-stack socket and sends to IPv4 peers.
func TestBindDualStackToIPv4(t *testing.T) {
	testBindRoundTrip(t, "udp", "[::]:0", "127.0.0.1:0", batchSize > 1)
}

func TestBindIPv6(t *testing.T) {
	if c, err := net.ListenPacket("udp6", "[::1]:0"); err != nil {
		t.Skip("no IPv6 loopback")
	} else {
		c.Close()
	}
	testBindRoundTrip(t, "udp6", "[::1]:0", "[::1]:0", batchSize > 1)
}

func TestPackMsgsGSO(t *testing.T) {
	if gsoControlSize == 0 {
		t.Skip("no UDP GSO on this system")
	}
	sizes := func(n, size int) []int {
		s := make([]int, n)
		for i := range s {
			s[i] = size
		}
		return s
	}
	cases := []struct {
		name  string
		sizes []int
		want  [][]int // datagram sizes per message
	}{
		{
			"short tail ends a run",
			[]int{1000, 1000, 1000, 500, 1000, 1200, 1200, 100},
			[][]int{{1000, 1000, 1000, 500}, {1000}, {1200, 1200, 100}},
		},
		{"segment limit", sizes(100, 100), [][]int{sizes(64, 100), sizes(36, 100)}},
		{"payload limit", sizes(50, 1452), [][]int{sizes(45, 1452), sizes(5, 1452)}},
	}
	addr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1}
	for _, c := range cases {
		bufs := make([][]byte, len(c.sizes))
		for i, n := range c.sizes {
			bufs[i] = make([]byte, n)
		}
		msgs := make([]ipv6.Message, conn.IdealBatchSize)
		n, count := packMsgs(msgs, bufs, addr, true)
		if count != len(bufs) || n != len(c.want) {
			t.Fatalf("%s: got %d messages with %d datagrams, want %d with %d", c.name, n, count, len(c.want), len(bufs))
		}
		for i, want := range c.want {
			m := msgs[i]
			if len(m.Buffers) != len(want) {
				t.Fatalf("%s: message %d has %d datagrams, want %d", c.name, i, len(m.Buffers), len(want))
			}
			for j := range want {
				if len(m.Buffers[j]) != want[j] {
					t.Fatalf("%s: message %d datagram %d has %d bytes, want %d", c.name, i, j, len(m.Buffers[j]), want[j])
				}
			}
			if (len(m.OOB) > 0) != (len(want) > 1) {
				t.Fatalf("%s: message %d: control %v for %d datagrams", c.name, i, m.OOB, len(want))
			}
		}
	}
}

// gsoConn counts UDP_SEGMENT sends, or rejects them with failErr like a
// route without checksum offload (EIO) or with a smaller MTU (EMSGSIZE).
type gsoConn struct {
	batchConn
	failErr   error
	gsoMsgs   int
	failedGSO int
}

func (c *gsoConn) WriteBatch(ms []ipv6.Message, flags int) (int, error) {
	if c.failErr != nil {
		for i := range ms {
			if len(ms[i].OOB) > 0 {
				if i == 0 {
					c.failedGSO++
					return 0, os.NewSyscallError("sendmmsg", c.failErr)
				}
				ms = ms[:i]
				break
			}
		}
	}
	n, err := c.batchConn.WriteBatch(ms, flags)
	for i := 0; i < n; i++ {
		if len(ms[i].OOB) > 0 {
			c.gsoMsgs++
		}
	}
	return n, err
}

// testBindGSO sends runs of equal-sized datagrams and checks that the peer
// gets each one intact and in order.
func testBindGSO(t *testing.T, network, bindAddr, peerAddr string, failErr error) {
	b, _, _, wc := openTestBind(t, network, bindAddr, nil)
	if !b.gso {
		t.Skip("no UDP GSO")
	}
	gc := &gsoConn{batchConn: b.batch, failErr: failErr}
	b.batch = gc
	b.raw = nil // Exercise the injected batch connection, not native sendmsg.
	pa, err := net.ResolveUDPAddr("udp", peerAddr)
	if err != nil {
		t.Fatal(err)
	}
	peer, err := net.ListenUDP("udp", pa)
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	_ = peer.SetReadBuffer(1 << 20)
	ep := &conn.StdNetEndpoint{AddrPort: peer.LocalAddr().(*net.UDPAddr).AddrPort()}

	var bufs [][]byte
	var total int64
	for i := 0; i < conn.IdealBatchSize; i++ {
		size := 1200
		if i%40 == 39 {
			size = 300 + i
		}
		p := testPacket(i % 50)
		p = append(p, make([]byte, size-len(p))...)
		bufs = append(bufs, p)
		total += int64(size)
	}
	want := make([][]byte, len(bufs))
	for i := range bufs {
		want[i] = bytes.Clone(bufs[i])
	}
	if err := b.Send(bufs, ep); err != nil {
		t.Fatal(err)
	}
	_ = peer.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 2048)
	for i := range want {
		n, _, err := peer.ReadFrom(buf)
		if err != nil {
			t.Fatalf("datagram %d: %v", i, err)
		}
		if !bytes.Equal(buf[:n], want[i]) {
			t.Fatalf("datagram %d differs: got %d bytes, want %d", i, n, len(want[i]))
		}
	}
	if wc.Value() != total {
		t.Fatalf("write counter = %d, want %d", wc.Value(), total)
	}
	if failErr != nil && (gc.failedGSO != 1 || gc.gsoMsgs != 0 || b.gso) {
		t.Fatalf("failed GSO sends = %d, GSO sends = %d, gso = %v; want 1, 0, false", gc.failedGSO, gc.gsoMsgs, b.gso)
	}
	if failErr == nil && gc.gsoMsgs == 0 {
		t.Fatal("no GSO sends")
	}
}

func TestBindGSO(t *testing.T) {
	testBindGSO(t, "udp4", "127.0.0.1:0", "127.0.0.1:0", nil)
}

func TestBindGSODualStackToIPv4(t *testing.T) {
	testBindGSO(t, "udp", "[::]:0", "127.0.0.1:0", nil)
}

func TestBindGSOIPv6(t *testing.T) {
	if c, err := net.ListenPacket("udp6", "[::1]:0"); err != nil {
		t.Skip("no IPv6 loopback")
	} else {
		c.Close()
	}
	testBindGSO(t, "udp6", "[::1]:0", "[::1]:0", nil)
}

func TestBindGSOFallback(t *testing.T) {
	for _, err := range []error{syscall.EIO, syscall.EMSGSIZE, syscall.EINVAL} {
		t.Run(err.Error(), func(t *testing.T) {
			testBindGSO(t, "udp4", "127.0.0.1:0", "127.0.0.1:0", err)
		})
	}
}

type wrappedTestPacketConn struct {
	net.PacketConn
	reads  atomic.Int64
	writes atomic.Int64
}

func (c *wrappedTestPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	c.reads.Add(1)
	return c.PacketConn.ReadFrom(p)
}

func (c *wrappedTestPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	c.writes.Add(1)
	return c.PacketConn.WriteTo(p, addr)
}

func TestBindFallbackDeliveryAndBatchBound(t *testing.T) {
	for _, optIn := range []bool{false, true} {
		name := "custom default"
		if optIn {
			name = "native opt-in downgraded"
		}
		t.Run(name, func(t *testing.T) {
			rc, wc := &testCounter{}, &testCounter{}
			var wrapped *wrappedTestPacketConn
			opens := 0
			b := &bind{
				batchEnabled: optIn,
				reserved:     []byte{1, 2, 3},
				listenFunc: func(context.Context) (net.PacketConn, error) {
					c, err := net.ListenPacket("udp4", "127.0.0.1:0")
					if err != nil {
						return nil, err
					}
					opens++
					if opens == 1 {
						wrapped = &wrappedTestPacketConn{PacketConn: c}
						c = wrapped
					}
					return &PacketCounterConnection{PacketConn: c, ReadCounter: rc, WriteCounter: wc}, nil
				},
			}
			t.Cleanup(func() { b.Close() })
			beforeOpen := b.BatchSize()
			wantBefore := 1
			if optIn {
				wantBefore = batchSize
			}
			if beforeOpen != wantBefore {
				t.Fatalf("pre-open BatchSize = %d, want %d", beforeOpen, wantBefore)
			}
			peer := newUDPClientTestSocket(t, "udp4", "127.0.0.1:0")
			ep := &conn.StdNetEndpoint{AddrPort: peer.LocalAddr().(*net.UDPAddr).AddrPort()}
			for round := range 2 {
				fns, _, err := b.Open(0)
				if err != nil {
					t.Fatal(err)
				}
				if b.BatchSize() != 1 || b.BatchSize() > beforeOpen || b.batch != nil {
					t.Fatalf("fallback grew its advertised batch bound: %d", b.BatchSize())
				}
				sent := []byte{4, 0, 0, 0, byte(round)}
				if err := b.Send([][]byte{sent}, ep); err != nil {
					t.Fatal(err)
				}
				var packet [32]byte
				n, _, err := peer.ReadFromUDP(packet[:])
				if err != nil || !bytes.Equal(packet[:n], []byte{4, 1, 2, 3, byte(round)}) {
					t.Fatalf("fallback send: n=%d err=%v data=%v", n, err, packet[:n])
				}
				if _, err := peer.WriteToUDP(packet[:n], b.LocalAddr().(*net.UDPAddr)); err != nil {
					t.Fatal(err)
				}
				reads := [][]byte{make([]byte, 32)}
				sizes, eps := make([]int, 1), make([]conn.Endpoint, 1)
				n, err = fns[0](reads, sizes, eps)
				if err != nil || n != 1 || !bytes.Equal(reads[0][:sizes[0]], []byte{4, 0, 0, 0, byte(round)}) {
					t.Fatalf("fallback receive: n=%d err=%v", n, err)
				}
				if eps[0].(*conn.StdNetEndpoint).AddrPort != ep.AddrPort {
					t.Fatal("fallback lost the source endpoint")
				}
				if rc.Value() != int64((round+1)*5) || wc.Value() != int64((round+1)*5) {
					t.Fatalf("fallback counters: read=%d write=%d", rc.Value(), wc.Value())
				}
				b.Close()
			}
			// The first socket must use the wrapper, and reopening on a plain
			// socket must not grow the lifetime bound allocated before Open.
			if wrapped.reads.Load() != 1 || wrapped.writes.Load() != 1 || b.BatchSize() != 1 {
				t.Fatal("fallback bypassed the wrapper or enlarged its batch on reopen")
			}
		})
	}
}
