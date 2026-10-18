package tun

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
)

// BenchmarkUDPNewSession measures what one new UDP flow costs the
// inbound while it stays open: QUIC and DNS open many short flows, and each
// one lives until the connection idle timeout.
func BenchmarkUDPNewSession(b *testing.B) {
	u := newUdpConnectionHandler(func(conn net.Conn, dest net.Destination) {}, nil)
	dst := net.UDPDestination(net.ParseAddress("1.1.1.1"), 443)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		src := net.UDPDestination(net.IPAddress([]byte{10, byte(i >> 16), byte(i >> 8), byte(i)}), net.Port(1024+i%60000))
		u.HandlePacket(src, dst, &buf.Buffer{})
	}
}

// Steady-state lookup, packet ownership and queue handoff are separate from
// new-session allocation and the raw queue microbenchmarks. Run explicitly:
// go test ./proxy/tun -run '^$' -bench 'BenchmarkUDP(FlowSteadyState|WritePacket)$' -benchmem
func BenchmarkUDPFlowSteadyState(b *testing.B) {
	accepted := make(chan *udpConn, 1)
	u := newUdpConnectionHandler(func(c net.Conn, _ net.Destination) {
		accepted <- c.(*udpConn)
	}, nil)
	src := net.UDPDestination(net.ParseAddress("10.66.0.2"), 1234)
	dst := net.UDPDestination(net.ParseAddress("1.1.1.1"), 53)
	payload := bytes.Repeat([]byte{0x5a}, 1200)
	packet := buf.NewWithSize(int32(len(payload)))
	packet.Write(payload)
	u.HandlePacket(src, dst, packet)
	c := <-accepted
	b.Cleanup(func() { c.Close() })
	first, ok := c.queue.pop()
	if !ok || first.UDP == nil || *first.UDP != dst || !bytes.Equal(first.Bytes(), payload) {
		b.Fatal("UDP flow lost payload or destination")
	}
	first.Release()
	b.SetBytes(int64(len(payload)))
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		// Match the copy/ownership boundary in stack.handleUDP.
		packet := buf.NewWithSize(int32(len(payload)))
		packet.Write(payload)
		u.HandlePacket(src, dst, packet)
		got, ok := c.queue.pop()
		if !ok {
			b.Fatal("UDP flow queue closed")
		}
		got.Release()
	}
	b.StopTimer()
}

// Capture into reusable storage instead of adding the allocating link fixture's
// packet copy to every sample. This measures packet construction plus the sink
// copy, not privileged OS TUN writes or WireGuard encryption.
type udpBenchmarkLink struct {
	*link
	packet []byte
}

func (l *udpBenchmarkLink) WritePacket(header, payload []byte) error {
	l.packet = append(l.packet[:0], header...)
	l.packet = append(l.packet, payload...)
	return nil
}

func BenchmarkUDPWritePacket(b *testing.B) {
	for _, tc := range []struct {
		name, src, dst string
	}{
		{"IPv4", "1.1.1.1", "10.66.0.2"},
		{"IPv6", "2606:4700:4700::1111", "fd00::2"},
	} {
		b.Run(tc.name, func(b *testing.B) {
			dev := &udpBenchmarkLink{link: newLink(), packet: make([]byte, 0, 2048)}
			network, err := NewStack(context.Background(), StackOptions{Tun: dev, MTU: 1420}, nil)
			if err != nil {
				b.Fatal(err)
			}
			b.Cleanup(func() { network.Close(); dev.Close() })
			s := network.(*stack)
			src := net.UDPDestination(net.ParseAddress(tc.src), 53)
			dst := net.UDPDestination(net.ParseAddress(tc.dst), 1234)
			payload := bytes.Repeat([]byte{0x5a}, 1200)
			if err := s.writeUDP(payload, src, dst); err != nil {
				b.Fatal(err)
			}
			packet, ok := parsePacket(dev.packet)
			if !ok || packet.proto != protoUDP || !packet.verified() ||
				packet.src.String() != tc.src || packet.dst.String() != tc.dst ||
				!bytes.Equal(packet.payload[udpHeaderSize:], payload) {
				b.Fatal("UDP packet payload, addresses or checksum mismatch")
			}
			b.SetBytes(int64(len(payload)))
			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				if err := s.writeUDP(payload, src, dst); err != nil {
					b.Fatal(err)
				}
			}
			b.StopTimer()
		})
	}
}

func TestPacketQueueOrderAndClose(t *testing.T) {
	q := newPacketQueue(udpQueueLimit)
	for i := 0; i < 3; i++ {
		b := buf.New()
		b.WriteByte(byte(i))
		if !q.push(b) {
			t.Fatalf("push %d rejected", i)
		}
	}
	for i := 0; i < 3; i++ {
		b, ok := q.pop()
		if !ok || b.Byte(0) != byte(i) {
			t.Fatalf("pop %d: got %v, %v", i, b, ok)
		}
		b.Release()
	}
	q.close()
	if _, ok := q.pop(); ok {
		t.Fatal("pop after close returned a packet")
	}
	if q.push(&buf.Buffer{}) {
		t.Fatal("push after close accepted")
	}
}

func TestPacketQueueLimit(t *testing.T) {
	q := newPacketQueue(udpQueueLimit)
	for i := 0; i < udpQueueLimit; i++ {
		if !q.push(&buf.Buffer{}) {
			t.Fatalf("push %d rejected below the limit", i)
		}
	}
	if q.push(&buf.Buffer{}) {
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
		q.push(&buf.Buffer{})
	}
	for i := 0; i < 100; i++ {
		q.pop()
	}
	if q.items != nil {
		t.Fatalf("drained queue still holds %d slots", cap(q.items))
	}
}
