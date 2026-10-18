package wireguard

import (
	"bytes"
	"net/netip"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/net"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

func newTestNetTun(t *testing.T) (*netTun, net.Conn) {
	t.Helper()
	dev, tnet, _, err := CreateNetTUN([]netip.Addr{netip.MustParseAddr("10.0.0.2")}, nil, 1420, true)
	if err != nil {
		t.Fatal(err)
	}
	c, err := tnet.DialUDPAddrPort(netip.AddrPort{}, netip.MustParseAddrPort("10.0.0.1:53"))
	if err != nil {
		t.Fatal(err)
	}
	return dev.(*netTun), c
}

func testBufs(n int) ([][]byte, []int) {
	bufs := make([][]byte, n)
	for i := range bufs {
		bufs[i] = make([]byte, 2048)
	}
	return bufs, make([]int, n)
}

// Packets the stack sends wait in the endpoint queue and come out of one
// Read together, so wireguard-go can handle them as a batch.
func TestNetTunReadBatch(t *testing.T) {
	tun, c := newTestNetTun(t)
	defer tun.Close()
	const count = 5
	for i := 0; i < count; i++ {
		if _, err := c.Write([]byte{byte(i)}); err != nil {
			t.Fatal(err)
		}
	}

	const offset = 16
	bufs, sizes := testBufs(8)
	n, err := tun.Read(bufs, sizes, offset)
	if err != nil {
		t.Fatal(err)
	}
	if n != count {
		t.Fatalf("read %d packets, want %d", n, count)
	}
	for i := 0; i < n; i++ {
		ip := header.IPv4(bufs[i][offset : offset+sizes[i]])
		if !ip.IsValid(sizes[i]) || ip.TransportProtocol() != header.UDPProtocolNumber {
			t.Fatalf("packet %d is not an IPv4 UDP packet", i)
		}
		if p := header.UDP(ip.Payload()).Payload(); len(p) != 1 || p[0] != byte(i) {
			t.Fatalf("packet %d carries %v, want [%d]", i, p, i)
		}
	}
}

// A sender waits once maxQueued packets are queued instead of overflowing
// the endpoint queue, and goes on when Read takes them or the tun closes.
func TestNetTunBackpressure(t *testing.T) {
	for _, closeTun := range []bool{false, true} {
		tun, c := newTestNetTun(t)
		closeDevice := sync.OnceFunc(func() { _ = tun.Close() })
		t.Cleanup(func() { _ = c.Close() })
		t.Cleanup(closeDevice)
		const count = maxQueued + 10
		done := make(chan error, 1)
		go func() {
			for i := range count {
				if _, err := c.Write([]byte{byte(i)}); err != nil {
					done <- err
					return
				}
			}
			done <- nil
		}()
		deadline := time.NewTimer(5 * time.Second)
		defer deadline.Stop()
		producerDone := false
		waitQueued := func(minimum int) {
			for tun.ep.NumQueued() < minimum {
				if producerDone {
					t.Fatalf("sender finished with %d packets queued, waiting for %d", tun.ep.NumQueued(), minimum)
				}
				select {
				case err := <-done:
					producerDone = true
					if err != nil {
						t.Fatalf("sender failed before close: %v", err)
					}
				case <-deadline.C:
					t.Fatalf("queue did not reach %d packets (close: %v)", minimum, closeTun)
				default:
					runtime.Gosched()
				}
			}
		}
		// Observe the actual bound, not whether a fixed sleep happened to
		// give the producer enough CPU time to reach it.
		waitQueued(maxQueued)
		select {
		case err := <-done:
			t.Fatalf("sender did not wait for the reader: %v", err)
		default:
		}
		if n := tun.ep.NumQueued(); n != maxQueued {
			t.Fatalf("%d packets queued, want the backpressure bound %d", n, maxQueued)
		}
		if closeTun {
			closeDevice()
		} else {
			bufs, sizes := testBufs(128)
			for got := 0; got < count; {
				// This is the only queue reader, so Read cannot block after
				// observing a packet. Empty-queue waits also check write errors.
				waitQueued(1)
				n, err := tun.Read(bufs, sizes, 0)
				if err != nil {
					t.Fatal(err)
				}
				if n == 0 {
					t.Fatal("reader made no progress")
				}
				got += n
			}
		}
		if !producerDone {
			select {
			case err := <-done:
				// Closing can interrupt a subsequent write. Every error before
				// closing, and every error in the draining case, is a failure.
				if err != nil && !closeTun {
					t.Fatalf("sender failed while draining: %v", err)
				}
			case <-deadline.C:
				t.Fatalf("sender still waiting (close: %v)", closeTun)
			}
		}
	}
}

func TestNetTunReadViewsAndHeaderOffset(t *testing.T) {
	tun, c := newTestNetTun(t)
	defer tun.Close()
	defer c.Close()
	payload := buffer.MakeWithData([]byte("first"))
	tail := buffer.MakeWithData([]byte("second"))
	payload.Merge(&tail)
	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		ReserveHeaderBytes: 128,
		Payload:            payload,
	})
	defer pkt.DecRef()
	copy(pkt.NetworkHeader().Push(3), []byte("hdr"))
	var packets stack.PacketBufferList
	packets.PushBack(pkt)
	// Exercise full and shortened destinations: the iterator must visit all
	// views, skip unused reserved headers, and stay within the caller's buffer.
	const offset = 7
	const want = "hdrfirstsecond"
	for _, limit := range []int{8, len(want)} {
		if n, err := tun.ep.WritePackets(packets); err != nil || n != 1 {
			t.Fatalf("queue packet: n=%d err=%v", n, err)
		}
		out := bytes.Repeat([]byte{0xcc}, offset+limit)
		sizes := make([]int, 1)
		if n, err := tun.Read([][]byte{out}, sizes, offset); err != nil || n != 1 {
			t.Fatalf("read packet: n=%d err=%v", n, err)
		}
		if sizes[0] != limit || string(out[offset:]) != want[:limit] || !bytes.Equal(out[:offset], bytes.Repeat([]byte{0xcc}, offset)) {
			t.Fatalf("view copy lost its offset, prefix, or packet bounds: size=%d data=%x", sizes[0], out)
		}
	}
}
