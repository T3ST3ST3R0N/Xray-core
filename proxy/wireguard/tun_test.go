package wireguard

import (
	"bytes"
	"io"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/checksum"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

// BenchmarkUDPManagerNewSession measures what one new UDP flow costs the
// inbound while it stays open: QUIC and DNS open many short flows, and each
// one lives until the connection idle timeout.
func BenchmarkUDPManagerNewSession(b *testing.B) {
	m := &udpManager{
		handler: func(conn net.Conn, dest net.Destination) {},
		m:       make(map[udpFlowKey]*udpConn),
	}
	dst := net.UDPDestination(net.ParseAddress("1.1.1.1"), 443)
	payload := make([]byte, 1200)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		src := net.UDPDestination(net.IPAddress([]byte{10, byte(i >> 16), byte(i >> 8), byte(i)}), net.Port(1024+i%60000))
		m.feed(src, dst, payload)
	}
}

func TestPacketQueueOrderAndClose(t *testing.T) {
	q := newPacketQueue(udpQueueLimit)
	for i := 0; i < 3; i++ {
		if !q.push(&packet{p: []byte{byte(i)}}) {
			t.Fatalf("push %d rejected", i)
		}
	}
	for i := 0; i < 3; i++ {
		p, ok := q.pop()
		if !ok || p.p[0] != byte(i) {
			t.Fatalf("pop %d: got %v, %v", i, p, ok)
		}
	}
	q.close()
	if _, ok := q.pop(); ok {
		t.Fatal("pop after close returned a packet")
	}
	if q.push(&packet{}) {
		t.Fatal("push after close accepted")
	}
}

func TestPacketQueueLimit(t *testing.T) {
	q := newPacketQueue(udpQueueLimit)
	for i := 0; i < udpQueueLimit; i++ {
		if !q.push(&packet{}) {
			t.Fatalf("push %d rejected below the limit", i)
		}
	}
	if q.push(&packet{}) {
		t.Fatal("push above the limit accepted")
	}
}

func TestPacketQueueCloseUnblocksReader(t *testing.T) {
	q := newPacketQueue(udpQueueLimit)
	done := make(chan bool)
	go func() {
		_, ok := q.pop()
		done <- ok
	}()
	q.close()
	select {
	case ok := <-done:
		if ok {
			t.Fatal("blocked pop returned a packet after close")
		}
	case <-time.After(time.Second):
		t.Fatal("close did not wake the reader")
	}
}

func TestPacketQueueDropsDrainedStorage(t *testing.T) {
	q := newPacketQueue(udpQueueLimit)
	for i := 0; i < 100; i++ {
		q.push(&packet{})
	}
	for i := 0; i < 100; i++ {
		q.pop()
	}
	if q.items != nil {
		t.Fatalf("drained queue still holds %d slots", cap(q.items))
	}
}

func TestPacketQueuePopBatch(t *testing.T) {
	q := newPacketQueue(udpQueueLimit)
	var dst [64]*packet
	if n := q.popBatch(nil); n != 0 {
		t.Fatalf("empty destination returned %d packets", n)
	}
	for i := range 70 {
		q.push(&packet{p: []byte{byte(i)}})
	}
	storage := q.items
	q.close()
	for offset := 0; offset < 70; {
		n := q.popBatch(dst[:])
		want := min(len(dst), 70-offset)
		if n != want {
			t.Fatalf("batch at %d: got %d, want %d", offset, n, want)
		}
		for i, p := range dst[:n] {
			if p.p[0] != byte(offset+i) {
				t.Fatalf("batch reordered packet %d", offset+i)
			}
		}
		offset += n
	}
	if n := q.popBatch(dst[:]); n != 0 {
		t.Fatalf("closed and drained queue returned %d packets", n)
	}
	for i, p := range storage {
		if p != nil {
			t.Fatalf("drained slot %d retains a packet", i)
		}
	}
	if q.items != nil {
		t.Fatal("drained queue retains storage")
	}
}

func TestPacketQueuePopBatchWaitsForPacket(t *testing.T) {
	q := newPacketQueue(udpQueueLimit)
	done := make(chan int, 1)
	go func() {
		var dst [64]*packet
		done <- q.popBatch(dst[:])
	}()
	q.push(&packet{})
	select {
	case n := <-done:
		if n != 1 {
			t.Fatalf("batch returned %d packets", n)
		}
	case <-time.After(time.Second):
		t.Fatal("push did not wake the batch reader")
	}
	q.close()
}

func TestUDPConnReadMultiBufferBatches(t *testing.T) {
	q := newPacketQueue(udpQueueLimit)
	c := &udpConn{queue: q}
	dest := net.UDPDestination(net.LocalHostIP, 53)
	for i := range 130 {
		q.push(&packet{p: []byte{byte(i)}, dest: &dest})
	}
	q.close()
	for offset := 0; offset < 130; {
		mb, err := c.ReadMultiBuffer()
		if err != nil {
			t.Fatal(err)
		}
		want := min(64, 130-offset)
		if len(mb) != want {
			buf.ReleaseMulti(mb)
			t.Fatalf("batch at %d: got %d, want %d", offset, len(mb), want)
		}
		for i, b := range mb {
			if b.Len() != 1 || b.Bytes()[0] != byte(offset+i) || b.UDP != &dest {
				buf.ReleaseMulti(mb)
				t.Fatalf("batch lost packet data or destination at %d", offset+i)
			}
		}
		offset += len(mb)
		buf.ReleaseMulti(mb)
	}
	if _, err := c.ReadMultiBuffer(); err != io.EOF {
		t.Fatalf("closed/drained read: %v", err)
	}
}

func TestUDPConnReadMultiBufferSkipsOversizedPackets(t *testing.T) {
	q := newPacketQueue(udpQueueLimit)
	c := &udpConn{queue: q}
	dest := net.UDPDestination(net.LocalHostIP, 53)
	q.push(&packet{p: make([]byte, buf.Size+1), dest: &dest})
	q.push(&packet{p: []byte("valid"), dest: &dest})
	q.close()
	mb, err := c.ReadMultiBuffer()
	if err != nil {
		t.Fatal(err)
	}
	defer buf.ReleaseMulti(mb)
	if len(mb) != 1 || string(mb[0].Bytes()) != "valid" {
		t.Fatal("oversized packet prevented the remaining batch from being returned")
	}
}

func TestUDPManagerFlowIdentity(t *testing.T) {
	manager := &udpManager{
		m:       make(map[udpFlowKey]*udpConn),
		handler: func(net.Conn, net.Destination) {},
	}
	first := net.UDPDestination(net.ParseAddress("192.0.2.1"), 1234)
	other := first
	other.Port++
	v6 := net.UDPDestination(net.ParseAddress("2001:db8::1"), first.Port)
	dst := net.UDPDestination(net.ParseAddress("198.51.100.1"), 53)
	for _, src := range []net.Destination{first, other, v6} {
		manager.feed(src, dst, []byte("one"))
	}
	// Reconstruct the same address value rather than reusing the interface.
	same := net.UDPDestination(net.IPAddress([]byte{192, 0, 2, 1}), first.Port)
	manager.feed(same, dst, []byte("two"))
	if len(manager.m) != 3 {
		t.Fatalf("got %d flows, want distinct address/port pairs", len(manager.m))
	}
	c := manager.m[flowKey(first)]
	c.queue.close()
	mb, err := c.ReadMultiBuffer()
	if err != nil {
		t.Fatal(err)
	}
	defer buf.ReleaseMulti(mb)
	if len(mb) != 2 || string(mb[0].Bytes()) != "one" || string(mb[1].Bytes()) != "two" {
		t.Fatal("equal source addresses did not reuse the same ordered flow")
	}
	manager.close(c)
	if _, ok := manager.m[flowKey(first)]; ok || len(manager.m) != 2 {
		t.Fatal("closing one source removed the wrong flow")
	}
}

func TestRawUDPPacketHeadersAndPayload(t *testing.T) {
	for _, family := range []struct{ src, dst string }{
		{"192.0.2.1", "198.51.100.1"},
		{"2001:db8::1", "2001:db8::2"},
	} {
		t.Run(family.src, func(t *testing.T) {
			dev := newICMPTestStack(t)
			manager := &udpManager{stack: dev.stack}
			src := net.UDPDestination(net.ParseAddress(family.src), 1234)
			dst := net.UDPDestination(net.ParseAddress(family.dst), 4321)
			payload := []byte("raw UDP reply")
			if err := manager.writeRawUDPPacket(payload, src, dst); err != nil {
				t.Fatal(err)
			}
			packet := make([]byte, 256)
			sizes := make([]int, 1)
			if n, err := dev.Read([][]byte{packet}, sizes, 0); err != nil || n != 1 {
				t.Fatalf("read reply: n=%d err=%v", n, err)
			}
			packet = packet[:sizes[0]]
			srcIP := tcpip.AddrFromSlice(src.Address.IP())
			dstIP := tcpip.AddrFromSlice(dst.Address.IP())
			ipHdrSize := header.IPv6MinimumSize
			if src.Address.Family().IsIPv4() {
				ipHdrSize = header.IPv4MinimumSize
				ip := header.IPv4(packet)
				if !ip.IsValid(len(packet)) || ip.SourceAddress() != srcIP || ip.DestinationAddress() != dstIP ||
					ip.TransportProtocol() != header.UDPProtocolNumber || checksum.Checksum(packet[:ipHdrSize], 0) != 0xffff {
					t.Fatal("invalid IPv4 reply header")
				}
			} else {
				ip := header.IPv6(packet)
				if !ip.IsValid(len(packet)) || ip.SourceAddress() != srcIP || ip.DestinationAddress() != dstIP ||
					ip.TransportProtocol() != header.UDPProtocolNumber {
					t.Fatal("invalid IPv6 reply header")
				}
			}
			udp := header.UDP(packet[ipHdrSize:])
			if udp.SourcePort() != uint16(src.Port) || udp.DestinationPort() != uint16(dst.Port) ||
				int(udp.Length()) != header.UDPMinimumSize+len(payload) || !bytes.Equal(udp.Payload(), payload) {
				t.Fatal("UDP reply lost ports, length, or payload")
			}
			xsum := header.PseudoHeaderChecksum(header.UDPProtocolNumber, srcIP, dstIP, uint16(len(udp)))
			if checksum.Checksum(udp, xsum) != 0xffff {
				t.Fatal("invalid UDP reply checksum")
			}
		})
	}
}
