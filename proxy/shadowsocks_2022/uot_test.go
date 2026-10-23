package shadowsocks_2022

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	gonet "net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/pipe"
)

func uotRequestBytes(t *testing.T, connect bool, dest net.Destination) []byte {
	t.Helper()
	var b bytes.Buffer
	if connect {
		b.WriteByte(1)
	} else {
		b.WriteByte(0)
	}
	if err := uotRequestAddress.WriteAddressPort(&b, dest.Address, dest.Port); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func TestUoTFraming(t *testing.T) {
	for _, address := range []net.Address{net.ParseAddress("192.0.2.1"), net.ParseAddress("2001:db8::1"), net.DomainAddress("example.invalid")} {
		dest := net.UDPDestination(address, 443)
		for _, connect := range []bool{false, true} {
			request, err := readUoTRequest(bytes.NewReader(uotRequestBytes(t, connect, dest)), false)
			if err != nil || request.connect != connect || request.destination != dest {
				t.Fatalf("request: %+v, %v", request, err)
			}
			for _, size := range []int{0, 1, 8192, 65535} {
				payload := bytes.Repeat([]byte{0xa5}, size)
				var frame bytes.Buffer
				if err := writeUoTPacket(&frame, request, dest, payload); err != nil {
					t.Fatal(err)
				}
				packet, target, err := readUoTPacket(&frame, request)
				if err != nil {
					t.Fatal(err)
				}
				if target != dest || !bytes.Equal(packet.Bytes(), payload) || frame.Len() != 0 {
					t.Fatal("packet, destination or frame boundary changed")
				}
				packet.Release()
			}
		}
	}
	// These independent wire bytes verify the non-SOCKS packet address mapping.
	wire := []byte{0, 192, 0, 2, 1, 0x01, 0xbb, 0, 1, 'x'}
	b, dest, err := readUoTPacket(bytes.NewReader(wire), uotRequest{})
	if err != nil || dest.NetAddr() != "192.0.2.1:443" || string(b.Bytes()) != "x" {
		t.Fatalf("legacy wire: %v %v", dest, err)
	}
	b.Release()
	if request, err := readUoTRequest(bytes.NewReader(nil), true); err != nil || request.connect {
		t.Fatal("v1 unexpectedly consumes a v2 request header")
	}
}

func TestUoTRejectsInvalidFrames(t *testing.T) {
	for _, request := range [][]byte{{}, {2}, {1, 9}, {1, 1, 192}, {1, 3, 0, 0, 53}} {
		if _, err := readUoTRequest(bytes.NewReader(request), false); err == nil {
			t.Fatalf("accepted invalid request %x", request)
		}
	}
	for _, packet := range [][]byte{{9}, {0, 192}, {0, 192, 0, 2, 1, 0, 0, 0, 0}, {0, 192, 0, 2, 1, 0, 53, 0}, {0, 192, 0, 2, 1, 0, 53, 0, 2, 'x'}} {
		if b, _, err := readUoTPacket(bytes.NewReader(packet), uotRequest{}); err == nil {
			b.Release()
			t.Fatalf("accepted invalid packet %x", packet)
		}
	}
	dest := net.UDPDestination(net.ParseAddress("192.0.2.1"), 53)
	if err := writeUoTPacket(io.Discard, uotRequest{}, dest, make([]byte, 65536)); err == nil {
		t.Fatal("oversized datagram accepted")
	}
	if err := writeUoTPacket(uotShortWriter{}, uotRequest{}, dest, []byte("x")); err != io.ErrShortWrite {
		t.Fatalf("short write: %v", err)
	}
	for _, dest := range []net.Destination{net.UDPDestination(net.DomainAddress(uotV2Domain), 1), net.TCPDestination(net.DomainAddress("x."+uotV2Domain), 0), net.TCPDestination(net.LocalHostIP, 0)} {
		if isSingUoT(dest) {
			t.Fatalf("non-magic destination recognized: %v", dest)
		}
	}
}

type uotShortWriter struct{}

func (uotShortWriter) Write(p []byte) (int, error) { return len(p) - 1, nil }

type uotDispatchRecord struct {
	dest   net.Destination
	user   *protocol.MemoryUser
	source net.Destination
}

type uotEchoDispatcher struct {
	routing.Dispatcher
	records chan uotDispatchRecord
	active  atomic.Int32
	wg      sync.WaitGroup
}

func (d *uotEchoDispatcher) Dispatch(ctx context.Context, dest net.Destination) (*transport.Link, error) {
	inbound := session.InboundFromContext(ctx)
	d.records <- uotDispatchRecord{dest, inbound.User, inbound.Source}
	input, requests := pipe.New()
	responses, output := pipe.New()
	d.active.Add(1)
	d.wg.Add(1)
	go func() {
		defer d.wg.Done()
		defer d.active.Add(-1)
		defer common.Interrupt(input)
		defer common.Interrupt(output)
		for {
			mb, err := input.ReadMultiBuffer()
			if err != nil {
				buf.ReleaseMulti(mb)
				return
			}
			if err := output.WriteMultiBuffer(mb); err != nil {
				return
			}
		}
	}()
	return &transport.Link{Reader: responses, Writer: requests}, nil
}

func TestUoTRoutesDestinationsAndRetainsIdentity(t *testing.T) {
	for _, version := range []int{1, 2} {
		t.Run(string(rune('0'+version)), func(t *testing.T) {
			client, server := gonet.Pipe()
			defer client.Close()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			user := &protocol.MemoryUser{Email: "uot@example.invalid"}
			source := net.TCPDestination(net.ParseAddress("198.51.100.9"), 1234)
			ctx = session.ContextWithInbound(ctx, &session.Inbound{Name: "shadowsocks-2022-multi", User: user, Source: source})
			dispatcher := &uotEchoDispatcher{records: make(chan uotDispatchRecord, 8)}
			magic := uotV1Domain
			var early []byte
			if version == 2 {
				magic = uotV2Domain
				early = uotRequestBytes(t, false, net.UDPDestination(net.AnyIP, 0))
			}
			finished := make(chan error, 1)
			go func() {
				finished <- processSingUoT(ctx, server, net.TCPDestination(net.DomainAddress(magic), 0), early, server, server, dispatcher, policy.SessionDefault())
			}()
			for _, address := range []string{"192.0.2.1", "example.invalid", "192.0.2.1"} {
				dest := net.UDPDestination(net.ParseAddress(address), 53)
				if err := client.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
					t.Fatal(err)
				}
				if err := writeUoTPacket(client, uotRequest{}, dest, []byte("payload")); err != nil {
					t.Fatal(err)
				}
				packet, got, err := readUoTPacket(client, uotRequest{})
				if err != nil {
					t.Fatal(err)
				}
				if got != dest || string(packet.Bytes()) != "payload" {
					t.Fatal("reply boundary or destination changed")
				}
				packet.Release()
			}
			if len(dispatcher.records) != 2 {
				t.Fatal("distinct destinations did not use distinct reusable routes")
			}
			for range 2 {
				record := <-dispatcher.records
				if record.dest.Network != net.Network_UDP || record.user != user || record.source != source {
					t.Fatal("authenticated routing context changed")
				}
			}
			cancel()
			select {
			case <-finished:
			case <-time.After(2 * time.Second):
				t.Fatal("cancellation left stream reader blocked")
			}
			dispatcher.wg.Wait()
			if dispatcher.active.Load() != 0 {
				t.Fatal("route goroutines survived session cancellation")
			}
		})
	}
}

func TestUoTConnectFramingTruncation(t *testing.T) {
	request := uotRequest{connect: true, destination: net.UDPDestination(net.ParseAddress("192.0.2.1"), 53)}
	var frame bytes.Buffer
	binary.Write(&frame, binary.BigEndian, uint16(65535))
	frame.WriteByte(1)
	if packet, _, err := readUoTPacket(&frame, request); err == nil {
		packet.Release()
		t.Fatal("truncated maximum-length frame accepted")
	}
}

func TestUoTBackpressureAndEOFReleaseRoutes(t *testing.T) {
	for _, ending := range []string{"cancel", "eof", "idle"} {
		t.Run(ending, func(t *testing.T) {
			client, server := gonet.Pipe()
			defer client.Close()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			ctx = session.ContextWithInbound(ctx, &session.Inbound{Name: "shadowsocks-2022"})
			dispatcher := &uotEchoDispatcher{records: make(chan uotDispatchRecord, 8)}
			p := policy.SessionDefault()
			if ending == "idle" {
				p.Timeouts.ConnectionIdle = 20 * time.Millisecond
			}
			finished := make(chan error, 1)
			go func() {
				finished <- processSingUoT(ctx, server, net.TCPDestination(net.DomainAddress(uotV1Domain), 0), nil, server, server, dispatcher, p)
			}()
			// Do not read the reply: the response worker must be interrupted even
			// while encrypted output is backpressured by the client.
			if err := writeUoTPacket(client, uotRequest{}, net.UDPDestination(net.LocalHostIP, 53), []byte("blocked reply")); err != nil {
				t.Fatal(err)
			}
			select {
			case <-dispatcher.records:
			case <-time.After(time.Second):
				t.Fatal("not dispatched")
			}
			if ending == "cancel" {
				cancel()
			}
			if ending == "eof" {
				client.Close()
			}
			select {
			case <-finished:
			case <-time.After(2 * time.Second):
				t.Fatal("reader/writer did not end")
			}
			dispatcher.wg.Wait()
			if dispatcher.active.Load() != 0 {
				t.Fatal("routes survived stream end")
			}
		})
	}
}

func TestUoTEarlyDataContainsRequestAndFirstPacket(t *testing.T) {
	client, server := gonet.Pipe()
	defer client.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ctx = session.ContextWithInbound(ctx, &session.Inbound{Name: "shadowsocks-2022"})
	dest := net.UDPDestination(net.ParseAddress("2001:db8::1"), 443)
	request := uotRequest{connect: true, destination: dest}
	var early bytes.Buffer
	early.Write(uotRequestBytes(t, true, dest))
	if err := writeUoTPacket(&early, request, dest, []byte("first")); err != nil {
		t.Fatal(err)
	}
	dispatcher := &uotEchoDispatcher{records: make(chan uotDispatchRecord, 8)}
	finished := make(chan error, 1)
	go func() {
		finished <- processSingUoT(ctx, server, net.TCPDestination(net.DomainAddress(uotV2Domain), 0), early.Bytes(), server, server, dispatcher, policy.SessionDefault())
	}()
	client.SetDeadline(time.Now().Add(2 * time.Second))
	packet, got, err := readUoTPacket(client, request)
	if err != nil {
		t.Fatal(err)
	}
	if got != dest || string(packet.Bytes()) != "first" {
		t.Fatal("early data lost or misframed")
	}
	packet.Release()
	if err := writeUoTPacket(client, request, dest, []byte("next")); err != nil {
		t.Fatal(err)
	}
	packet, _, err = readUoTPacket(client, request)
	if err != nil {
		t.Fatal(err)
	}
	if string(packet.Bytes()) != "next" {
		t.Fatal("stream after early data changed")
	}
	packet.Release()
	client.Close()
	select {
	case <-finished:
	case <-time.After(2 * time.Second):
		t.Fatal("EOF did not stop session")
	}
	dispatcher.wg.Wait()
}

type uotGateDispatcher struct {
	routing.Dispatcher
	entered chan struct{}
	active  atomic.Int32
}

func (d *uotGateDispatcher) Dispatch(ctx context.Context, dest net.Destination) (*transport.Link, error) {
	d.active.Add(1)
	defer d.active.Add(-1)
	close(d.entered)
	<-ctx.Done()
	return nil, ctx.Err()
}

func TestUoTCancelDuringDispatch(t *testing.T) {
	client, server := gonet.Pipe()
	defer client.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	dispatcher := &uotGateDispatcher{entered: make(chan struct{})}
	finished := make(chan error, 1)
	go func() {
		finished <- processSingUoT(ctx, server, net.TCPDestination(net.DomainAddress(uotV1Domain), 0), nil, server, server, dispatcher, policy.SessionDefault())
	}()
	if err := writeUoTPacket(client, uotRequest{}, net.UDPDestination(net.LocalHostIP, 53), []byte("x")); err != nil {
		t.Fatal(err)
	}
	select {
	case <-dispatcher.entered:
	case <-time.After(time.Second):
		t.Fatal("not dispatched")
	}
	cancel()
	select {
	case <-finished:
	case <-time.After(time.Second):
		t.Fatal("cancel did not reach dispatcher")
	}
	if dispatcher.active.Load() != 0 {
		t.Fatal("dispatch survived cancellation")
	}
}

func TestUoTBoundsRoutesAndReleasesThemOnMalformedTail(t *testing.T) {
	for _, ending := range []string{"limit", "malformed"} {
		t.Run(ending, func(t *testing.T) {
			client, server := gonet.Pipe()
			defer client.Close()
			ctx := session.ContextWithInbound(context.Background(), &session.Inbound{Name: "shadowsocks-2022"})
			dispatcher := &uotEchoDispatcher{records: make(chan uotDispatchRecord, uotMaxRoutes+1)}
			finished := make(chan error, 1)
			go func() {
				finished <- processSingUoT(ctx, server, net.TCPDestination(net.DomainAddress(uotV1Domain), 0), nil, server, server, dispatcher, policy.SessionDefault())
			}()
			count := 1
			if ending == "limit" {
				count = uotMaxRoutes
			}
			for n := 1; n <= count; n++ {
				client.SetDeadline(time.Now().Add(2 * time.Second))
				if err := writeUoTPacket(client, uotRequest{}, net.UDPDestination(net.LocalHostIP, net.Port(n)), []byte("x")); err != nil {
					t.Fatal(err)
				}
				packet, _, err := readUoTPacket(client, uotRequest{})
				if err != nil {
					t.Fatal(err)
				}
				packet.Release()
			}
			if ending == "limit" {
				writeUoTPacket(client, uotRequest{}, net.UDPDestination(net.LocalHostIP, net.Port(uotMaxRoutes+1)), []byte("over limit"))
			} else {
				client.Write([]byte{9}) // Invalid packet address family after a valid exchange.
			}
			select {
			case err := <-finished:
				if err == nil {
					t.Fatal("invalid session ending accepted")
				}
			case <-time.After(2 * time.Second):
				t.Fatal("invalid session did not end")
			}
			dispatcher.wg.Wait()
			if len(dispatcher.records) != count || dispatcher.active.Load() != 0 {
				t.Fatal("route limit or teardown violated")
			}
		})
	}
}

type uotContextDispatcher struct {
	*uotEchoDispatcher
	contexts  chan context.Context
	start     chan struct{}
	mutations sync.WaitGroup
}

func (d *uotContextDispatcher) Dispatch(ctx context.Context, dest net.Destination) (*transport.Link, error) {
	d.contexts <- ctx
	d.mutations.Add(1)
	go func() {
		defer d.mutations.Done()
		<-d.start
		for range 1000 {
			outbound := session.OutboundsFromContext(ctx)[0]
			outbound.Target, outbound.OriginalTarget, outbound.RouteTarget = dest, dest, dest
			content := session.ContentFromContext(ctx)
			content.Protocol = dest.String()
			content.SetAttribute("route", dest.String())
		}
	}()
	return d.uotEchoDispatcher.Dispatch(ctx, dest)
}

func TestUoTIsolatesMutableRoutingContexts(t *testing.T) {
	client, server := gonet.Pipe()
	defer client.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	parentOutbound := &session.Outbound{Tag: "parent"}
	parentContent := &session.Content{Protocol: "parent", Attributes: map[string]string{"forcedOutboundTag": "preserved"}}
	ctx = session.ContextWithOutbounds(ctx, []*session.Outbound{parentOutbound})
	ctx = session.ContextWithContent(ctx, parentContent)
	ctx = session.ContextWithInbound(ctx, &session.Inbound{Name: "shadowsocks-2022"})
	dispatcher := &uotContextDispatcher{
		uotEchoDispatcher: &uotEchoDispatcher{records: make(chan uotDispatchRecord, 8)},
		contexts:          make(chan context.Context, 2), start: make(chan struct{}),
	}
	finished := make(chan error, 1)
	go func() {
		finished <- processSingUoT(ctx, server, net.TCPDestination(net.DomainAddress(uotV1Domain), 0), nil, server, server, dispatcher, policy.SessionDefault())
	}()
	var contexts []context.Context
	for _, port := range []net.Port{53, 443} {
		client.SetDeadline(time.Now().Add(2 * time.Second))
		if err := writeUoTPacket(client, uotRequest{}, net.UDPDestination(net.LocalHostIP, port), []byte("x")); err != nil {
			t.Fatal(err)
		}
		packet, _, err := readUoTPacket(client, uotRequest{})
		if err != nil {
			t.Fatal(err)
		}
		packet.Release()
		contexts = append(contexts, <-dispatcher.contexts)
	}
	close(dispatcher.start)
	dispatcher.mutations.Wait()
	for n, context := range contexts {
		outbound := session.OutboundsFromContext(context)[0]
		content := session.ContentFromContext(context)
		expected := net.UDPDestination(net.LocalHostIP, []net.Port{53, 443}[n])
		if outbound == parentOutbound || outbound.Target != expected || content == parentContent ||
			content.Protocol != expected.String() || content.Attribute("route") != expected.String() || content.Attribute("forcedOutboundTag") != "preserved" {
			t.Error("per-destination routing state was shared or lost")
		}
	}
	if parentOutbound.Target.IsValid() || parentContent.Protocol != "parent" || parentContent.Attribute("route") != "" {
		t.Error("parent routing context was mutated")
	}
	cancel()
	select {
	case <-finished:
	case <-time.After(2 * time.Second):
		t.Fatal("session did not stop")
	}
	dispatcher.wg.Wait()
}

type uotDelayedReader struct {
	buf.Reader
	release <-chan struct{}
}

func (r *uotDelayedReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	mb, err := r.Reader.ReadMultiBuffer()
	if err != nil {
		<-r.release
	}
	return mb, err
}

func (r *uotDelayedReader) Interrupt() { common.Interrupt(r.Reader) }

type uotRetiringWriter struct {
	buf.Writer
	reader      buf.Reader
	retireFirst bool
	writes      atomic.Int32
	once        sync.Once
	interrupted chan struct{}
	interrupts  atomic.Int32
	settled     chan struct{}
}

func (w *uotRetiringWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	if w.writes.Add(1) != 2 {
		return w.Writer.WriteMultiBuffer(mb)
	}
	if w.retireFirst {
		// The read loop already selected this route. Retire it before the
		// selected writer completes, reproducing the idle-expiry race.
		common.Interrupt(w.reader)
		<-w.interrupted
	}
	buf.ReleaseMulti(mb) // Like pipe.Writer, the failing writer owns its input.
	return io.ErrClosedPipe
}

func (w *uotRetiringWriter) Interrupt() {
	common.Interrupt(w.Writer)
	w.once.Do(func() { close(w.interrupted) })
	if w.interrupts.Add(1) == 2 {
		close(w.settled)
	}
}

type uotRetiringDispatcher struct {
	*uotEchoDispatcher
	retireFirst bool
	releaseOld  <-chan struct{}
	calls       atomic.Int32
	firstWriter *uotRetiringWriter
}

func (d *uotRetiringDispatcher) Dispatch(ctx context.Context, dest net.Destination) (*transport.Link, error) {
	link, err := d.uotEchoDispatcher.Dispatch(ctx, dest)
	if d.calls.Add(1) == 1 {
		writer := &uotRetiringWriter{Writer: link.Writer, reader: link.Reader, retireFirst: d.retireFirst, interrupted: make(chan struct{}), settled: make(chan struct{})}
		d.firstWriter = writer
		link.Writer = writer
		if !d.retireFirst {
			link.Reader = &uotDelayedReader{Reader: link.Reader, release: d.releaseOld}
		}
	}
	return link, err
}

func TestUoTRetiringRouteDoesNotEndOtherDestinations(t *testing.T) {
	for _, retireFirst := range []bool{true, false} {
		t.Run(map[bool]string{true: "retired-before-write-error", false: "old-worker-finishes-after-replacement"}[retireFirst], func(t *testing.T) {
			client, server := gonet.Pipe()
			defer client.Close()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			ctx = session.ContextWithInbound(ctx, &session.Inbound{Name: "shadowsocks-2022"})
			release := make(chan struct{})
			var releaseOnce sync.Once
			releaseOld := func() { releaseOnce.Do(func() { close(release) }) }
			defer releaseOld()
			dispatcher := &uotRetiringDispatcher{uotEchoDispatcher: &uotEchoDispatcher{records: make(chan uotDispatchRecord, 8)}, retireFirst: retireFirst, releaseOld: release}
			finished := make(chan error, 1)
			go func() {
				finished <- processSingUoT(ctx, server, net.TCPDestination(net.DomainAddress(uotV1Domain), 0), nil, server, server, dispatcher, policy.SessionDefault())
			}()
			exchange := func(port net.Port, value string) {
				t.Helper()
				client.SetDeadline(time.Now().Add(2 * time.Second))
				dest := net.UDPDestination(net.LocalHostIP, port)
				if err := writeUoTPacket(client, uotRequest{}, dest, []byte(value)); err != nil {
					t.Fatal(err)
				}
				packet, got, err := readUoTPacket(client, uotRequest{})
				if err != nil {
					t.Fatal(err)
				}
				defer packet.Release()
				if got != dest || string(packet.Bytes()) != value {
					t.Fatal("packet replayed, duplicated or misrouted")
				}
			}
			exchange(53, "first A")
			exchange(443, "first B")
			if err := writeUoTPacket(client, uotRequest{}, net.UDPDestination(net.LocalHostIP, 53), []byte("failed A must not replay")); err != nil {
				t.Fatal(err)
			}
			exchange(443, "B stays alive")
			exchange(53, "fresh A route")
			releaseOld()
			select {
			case <-dispatcher.firstWriter.settled:
			case <-time.After(time.Second):
				t.Fatal("old route cleanup did not complete")
			}
			exchange(443, "B still same route")
			exchange(53, "replacement remains")
			if dispatcher.calls.Load() != 3 {
				t.Fatalf("route not reused or old worker deleted replacement: %d", dispatcher.calls.Load())
			}
			cancel()
			select {
			case <-finished:
			case <-time.After(2 * time.Second):
				t.Fatal("cleanup did not finish")
			}
			dispatcher.wg.Wait()
		})
	}
}
