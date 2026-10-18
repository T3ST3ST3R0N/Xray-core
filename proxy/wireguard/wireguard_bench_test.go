package wireguard

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"testing"
	"time"

	xnet "github.com/xtls/xray-core/common/net"
	"golang.org/x/crypto/curve25519"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
)

// Throughput is opt-in; ordinary regression tests do not run these benchmarks:
// go test ./proxy/wireguard -run '^$' -bench 'Benchmark(WireGuardTCP|NetTUNWriteRead|BindUDP)$' -benchmem
//
// WireGuardTCP uses two real WireGuard devices, native loopback UDP binds, and
// proxy/tun TCP stacks via CreateNetTUN. NetTUNWriteRead isolates the device
// adapter and ICMP stack path, without encryption or a privileged OS interface.
// The current UDP queue microbenchmarks live in proxy/tun, not WireGuard:
// go test ./proxy/tun -run '^$' -bench 'BenchmarkQueue(Burst|Stream)(Chan|PacketQueue)$' -benchmem
const throughputPacketSize = 1200

func benchmarkBuffers(count, size int) ([][]byte, []int, []conn.Endpoint) {
	bufs := make([][]byte, count)
	for i := range bufs {
		bufs[i] = make([]byte, size)
	}
	return bufs, make([]int, count), make([]conn.Endpoint, count)
}

func newThroughputTUN(tb testing.TB) tun.Device {
	tb.Helper()
	dev, _, err := CreateNetTUN([]netip.Addr{netip.MustParseAddr("10.66.0.1")}, nil, 1420, nil)
	if err != nil {
		tb.Fatal(err)
	}
	tb.Cleanup(func() { dev.Close() })
	// Stack connections do not implement deadlines; closing the device unblocks Read.
	timer := time.AfterFunc(30*time.Second, func() { dev.Close() })
	tb.Cleanup(func() { timer.Stop() })
	return dev
}

func throughputEchoPacket() []byte {
	packet := make([]byte, throughputPacketSize)
	packet[0], packet[8], packet[9] = 0x45, 64, 1
	binary.BigEndian.PutUint16(packet[2:], uint16(len(packet)))
	copy(packet[12:16], []byte{10, 66, 0, 2})
	copy(packet[16:20], []byte{10, 66, 0, 1})
	binary.BigEndian.PutUint16(packet[10:], ^onesSum(packet[:20], 0))
	echo := packet[20:]
	echo[0] = 8
	binary.BigEndian.PutUint16(echo[4:], 123)
	binary.BigEndian.PutUint16(echo[2:], ^onesSum(echo, 0))
	return packet
}

func BenchmarkNetTUNWriteRead(b *testing.B) {
	for _, batch := range []int{1, conn.IdealBatchSize} {
		b.Run(fmt.Sprintf("batch=%d", batch), func(b *testing.B) {
			dev := newThroughputTUN(b)
			writes, _, _ := benchmarkBuffers(batch, throughputPacketSize)
			packet := throughputEchoPacket()
			reads, sizes, _ := benchmarkBuffers(dev.BatchSize(), 2048)
			if _, err := dev.Write([][]byte{bytes.Clone(packet)}, 0); err != nil {
				b.Fatal(err)
			}
			if _, err := dev.Read(reads, sizes, 0); err != nil {
				b.Fatal(err)
			}
			reply := reads[0][:sizes[0]]
			if len(reply) != len(packet) || reply[20] != 0 || !bytes.Equal(reply[24:], packet[24:]) {
				b.Fatal("NetTUN echo payload mismatch")
			}
			b.SetBytes(int64(batch * throughputPacketSize))
			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				// Input may modify an ICMP request into its reply. Restore every
				// request rather than timing a dropped echo reply after iteration one.
				for i := range writes {
					copy(writes[i], packet)
				}
				if _, err := dev.Write(writes, 0); err != nil {
					b.Fatal(err)
				}
				for remaining := batch; remaining > 0; {
					n, err := dev.Read(reads, sizes, 0)
					if err != nil {
						b.Fatal(err)
					}
					remaining -= n
				}
			}
			b.StopTimer()
			b.ReportMetric(float64(b.N*batch)/b.Elapsed().Seconds(), "packets/s")
		})
	}
}

func newThroughputBind(tb testing.TB, network, address string) (*bind, conn.ReceiveFunc, *net.UDPConn) {
	tb.Helper()
	udp, err := net.ListenUDP(network, net.UDPAddrFromAddrPort(netip.MustParseAddrPort(address)))
	if err != nil {
		tb.Fatal(err)
	}
	b := &bind{ctx: context.Background(), batchEnabled: true, listenFunc: func(context.Context) (net.PacketConn, error) { return udp, nil }}
	fns, _, err := b.Open(0)
	if err != nil {
		udp.Close()
		tb.Fatal(err)
	}
	tb.Cleanup(func() { b.Close() })
	// bind retries receive errors; close it instead of setting a socket deadline.
	timer := time.AfterFunc(30*time.Second, func() { b.Close() })
	tb.Cleanup(func() { timer.Stop() })
	return b, fns[0], udp
}

func BenchmarkBindUDP(b *testing.B) {
	for _, batch := range []int{1, conn.IdealBatchSize} {
		b.Run(fmt.Sprintf("batch=%d", batch), func(b *testing.B) {
			sender, _, _ := newThroughputBind(b, "udp4", "127.0.0.1:0")
			receiver, receive, udp := newThroughputBind(b, "udp4", "127.0.0.1:0")
			port := uint16(udp.LocalAddr().(*net.UDPAddr).Port)
			ep, err := sender.ParseEndpoint(netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), port).String())
			if err != nil {
				b.Fatal(err)
			}
			writes, _, _ := benchmarkBuffers(batch, throughputPacketSize)
			reads, sizes, eps := benchmarkBuffers(receiver.BatchSize(), throughputPacketSize)
			done := make(chan error, 1)
			go func() {
				for range b.N {
					remaining := batch
					for remaining > 0 {
						n, err := receive(reads, sizes, eps)
						if err != nil {
							done <- err
							return
						}
						remaining -= n
					}
					done <- nil
				}
			}()
			b.SetBytes(int64(batch * throughputPacketSize))
			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				if err := sender.Send(writes, ep); err != nil {
					b.Fatal(err)
				}
				if err := <-done; err != nil {
					b.Fatal(err)
				}
			}
			b.StopTimer()
			b.ReportMetric(float64(b.N*batch)/b.Elapsed().Seconds(), "packets/s")
		})
	}
}

func newBenchmarkWireGuardDevices(tb testing.TB, tuns [2]tun.Device) {
	tb.Helper()
	var devs [2]*device.Device
	var ports [2]int
	var private, public [2][32]byte
	for i, tdev := range tuns {
		binding := &bind{ctx: context.Background(), batchEnabled: true, listenFunc: func(context.Context) (net.PacketConn, error) {
			return net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		}}
		devs[i] = device.NewDevice(tdev, binding, device.NewLogger(device.LogLevelError, ""))
		tb.Cleanup(devs[i].Close)
		private[i][0] = byte(8 * (i + 1))
		curve25519.ScalarBaseMult(&public[i], &private[i])
		if err := devs[i].IpcSet(fmt.Sprintf("private_key=%s\n", hex.EncodeToString(private[i][:]))); err != nil {
			tb.Fatal(err)
		}
		if err := devs[i].Up(); err != nil {
			tb.Fatal(err)
		}
		cfg, err := devs[i].IpcGet()
		if err != nil {
			tb.Fatal(err)
		}
		for _, line := range strings.Split(cfg, "\n") {
			if value, ok := strings.CutPrefix(line, "listen_port="); ok {
				ports[i], err = strconv.Atoi(value)
				if err != nil {
					tb.Fatal(err)
				}
			}
		}
		if ports[i] == 0 {
			tb.Fatal("WireGuard did not publish a listening port")
		}
	}
	for i, dev := range devs {
		peer := 1 - i
		cfg := fmt.Sprintf("public_key=%s\nendpoint=127.0.0.1:%d\nallowed_ip=10.77.0.%d/32\n",
			hex.EncodeToString(public[peer][:]), ports[peer], peer+1)
		if err := dev.IpcSet(cfg); err != nil {
			tb.Fatal(err)
		}
	}
}

type benchmarkTCPHandler struct {
	accepted chan net.Conn
}

func (h benchmarkTCPHandler) HandleConnection(c xnet.Conn, _ xnet.Destination) {
	h.accepted <- c
}

func newWireGuardTCPPair(tb testing.TB) (net.Conn, net.Conn) {
	tb.Helper()
	accepted := make(chan net.Conn, 1)
	serverTUN, _, err := CreateNetTUN([]netip.Addr{netip.MustParseAddr("10.77.0.2")}, nil, 1420, benchmarkTCPHandler{accepted})
	if err != nil {
		tb.Fatal(err)
	}
	tb.Cleanup(func() { serverTUN.Close() })
	clientTUN, network, err := CreateNetTUN([]netip.Addr{netip.MustParseAddr("10.77.0.1")}, nil, 1420, nil)
	if err != nil {
		tb.Fatal(err)
	}
	tb.Cleanup(func() { clientTUN.Close() })
	newBenchmarkWireGuardDevices(tb, [2]tun.Device{clientTUN, serverTUN})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	client, err := network.DialContextTCPAddrPort(ctx, netip.MustParseAddrPort("10.77.0.2:12345"))
	if err != nil {
		tb.Fatal(err)
	}
	tb.Cleanup(func() { client.Close() })
	select {
	case server := <-accepted:
		tb.Cleanup(func() { server.Close() })
		return client, server
	case <-ctx.Done():
		tb.Fatal(ctx.Err())
		return nil, nil
	}
}

func benchmarkTCPStream(b *testing.B, client, server net.Conn) {
	// proxy/tun streams end on Close rather than SetDeadline.
	timer := time.AfterFunc(30*time.Second, func() { client.Close(); server.Close() })
	defer timer.Stop()
	payload := bytes.Repeat([]byte("WireGuard TCP payload\x00\xff"), (64<<10)/23+1)[:64<<10]
	// Verify one full payload before timing; the hot loop measures transport only.
	verified := make(chan error, 1)
	go func() {
		got := make([]byte, len(payload))
		_, err := io.ReadFull(server, got)
		if err == nil && !bytes.Equal(got, payload) {
			err = fmt.Errorf("WireGuard TCP payload mismatch")
		}
		verified <- err
	}()
	if n, err := client.Write(payload); err != nil {
		b.Fatal(err)
	} else if n != len(payload) {
		b.Fatal(io.ErrShortWrite)
	}
	if err := <-verified; err != nil {
		b.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := io.CopyN(io.Discard, server, int64(b.N)*int64(len(payload)))
		done <- err
	}()
	b.SetBytes(64 << 10)
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		n, err := client.Write(payload)
		if err != nil {
			b.Fatal(err)
		}
		if n != len(payload) {
			b.Fatal(io.ErrShortWrite)
		}
	}
	if err := <-done; err != nil {
		b.Fatal(err)
	}
	b.StopTimer()
}

func BenchmarkWireGuardTCP(b *testing.B) {
	client, server := newWireGuardTCPPair(b)
	benchmarkTCPStream(b, client, server)
}
