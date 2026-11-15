package shadowsocks_2022

import (
	"context"
	"io"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/log"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/pipe"
)

type destinationTestWriter struct {
	fail    atomic.Bool
	mu      sync.Mutex
	blocked bool
	packets []net.Destination
}

func (w *destinationTestWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	defer buf.ReleaseMulti(mb)
	if w.fail.Load() {
		return io.ErrClosedPipe
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.blocked {
		for _, b := range mb {
			w.packets = append(w.packets, *b.UDP)
		}
	}
	return nil
}

type destinationTestRoute struct {
	ctx       context.Context
	writer    *destinationTestWriter
	responses *pipe.Writer
}

type destinationTestDispatcher struct {
	routing.Dispatcher
	mu     sync.Mutex
	routes map[string][]*destinationTestRoute
}

func (d *destinationTestDispatcher) Dispatch(ctx context.Context, dest net.Destination) (*transport.Link, error) {
	r, w := pipe.New()
	route := &destinationTestRoute{ctx: ctx, writer: &destinationTestWriter{blocked: dest.Port == 443}, responses: w}
	d.mu.Lock()
	if d.routes == nil {
		d.routes = make(map[string][]*destinationTestRoute)
	}
	d.routes[dest.String()] = append(d.routes[dest.String()], route)
	d.mu.Unlock()
	return &transport.Link{Reader: r, Writer: route.writer}, nil
}

func destinationTestPacket(t *testing.T, h *lifecycleHarness, dest net.Destination) []byte {
	t.Helper()
	packet, err := h.client.EncodePacket(dest, []byte("payload"))
	if err != nil {
		t.Fatal(err)
	}
	defer packet.Release()
	return append([]byte(nil), packet.Bytes()...)
}

// A native SS2022 session carries independently addressed datagrams. The first
// destination must neither blackhole later allowed traffic nor bypass a block.
func TestUDPRoutesEachDestination(t *testing.T) {
	lifecycleCases(t, func(t *testing.T, method string, multi bool) {
		for _, blockedFirst := range []bool{true, false} {
			name := "allowed-first"
			if blockedFirst {
				name = "blocked-first"
			}
			t.Run(name, func(t *testing.T) {
				h := newLifecycleHarness(t, method, multi)
				d := new(destinationTestDispatcher)
				allowed := net.UDPDestination(net.LocalHostIP, 80)
				blocked := net.UDPDestination(net.LocalHostIP, 443)
				destinations := []net.Destination{allowed, blocked, allowed}
				if blockedFirst {
					destinations = []net.Destination{blocked, allowed, allowed}
				}
				conn := newLifecycleConn()
				for _, dest := range destinations {
					conn.packet = destinationTestPacket(t, h, dest)
					_ = h.process(context.Background(), conn, d)
				}
				d.mu.Lock()
				defer d.mu.Unlock()
				if len(d.routes) != 2 {
					t.Fatalf("dispatched %d destinations, want 2", len(d.routes))
				}
				for key, routes := range d.routes {
					if len(routes) != 1 {
						t.Fatalf("destination %s dispatched %d times", key, len(routes))
					}
					w := routes[0].writer
					w.mu.Lock()
					defer w.mu.Unlock()
					if key == allowed.String() {
						if len(w.packets) != 2 {
							t.Fatalf("allowed route got %d packets, want 2", len(w.packets))
						}
						for _, got := range w.packets {
							if got != allowed {
								t.Fatalf("blocked destination escaped over allowed route: %v", got)
							}
						}
					}
				}
			})
		}
	})
}

func (d *destinationTestDispatcher) get(dest net.Destination) []*destinationTestRoute {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]*destinationTestRoute(nil), d.routes[dest.String()]...)
}

func waitDestinationClosed(t *testing.T, ctx context.Context) {
	t.Helper()
	select {
	case <-ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("destination context was not canceled")
	}
}

func TestUDPDestinationRetirement(t *testing.T) {
	lifecycleCases(t, func(t *testing.T, method string, multi bool) {
		h := newLifecycleHarness(t, method, multi)
		d := new(destinationTestDispatcher)
		a, b := net.UDPDestination(net.LocalHostIP, 80), net.UDPDestination(net.LocalHostIP, 81)
		conn := newLifecycleConn()
		send := func(packet []byte) {
			conn.packet = append([]byte(nil), packet...)
			_ = h.process(context.Background(), conn, d)
		}
		first := destinationTestPacket(t, h, a)
		send(first)
		send(destinationTestPacket(t, h, b))
		s := h.manager.GetOrCreate(h.client.clientSessionID)
		oldA, oldB := d.get(a)[0], d.get(b)[0]
		if err := oldA.responses.Close(); err != nil {
			t.Fatal(err)
		}
		waitDestinationClosed(t, oldA.ctx)
		if s.closed.Load() || h.manager.GetOrCreate(s.SessionID) != s {
			t.Fatal("one destination ending destroyed the authenticated session")
		}
		// Retirement must not reset the authenticated replay window.
		send(first)
		if len(d.get(a)) != 1 {
			t.Fatal("retirement accepted a replay")
		}
		send(destinationTestPacket(t, h, a))
		send(destinationTestPacket(t, h, b))
		if len(d.get(a)) != 2 || len(d.get(b)) != 1 {
			t.Fatal("read EOF did not recreate only its destination")
		}
		oldB.writer.fail.Store(true)
		send(destinationTestPacket(t, h, b))
		waitDestinationClosed(t, oldB.ctx)
		send(destinationTestPacket(t, h, b))
		if len(d.get(a)) != 2 || len(d.get(b)) != 2 {
			t.Fatal("write failure did not recreate only its destination")
		}
		newB := d.get(b)[1]
		newB.writer.mu.Lock()
		defer newB.writer.mu.Unlock()
		if len(newB.writer.packets) != 1 {
			t.Fatal("an ambiguous failed write was replayed")
		}
	})
}

func TestUDPDestinationResponseIdentity(t *testing.T) {
	lifecycleCases(t, func(t *testing.T, method string, multi bool) {
		h := newLifecycleHarness(t, method, multi)
		d := new(destinationTestDispatcher)
		a, b := net.UDPDestination(net.LocalHostIP, 80), net.UDPDestination(net.LocalHostIP, 81)
		oldConn, newConn := newLifecycleConn(), newLifecycleConn()
		first := destinationTestPacket(t, h, a)
		oldConn.packet = append([]byte(nil), first...)
		_ = h.process(context.Background(), oldConn, d)
		newConn.packet = destinationTestPacket(t, h, b)
		_ = h.process(context.Background(), newConn, d)
		oldConn.packet = append([]byte(nil), first...)
		_ = h.process(context.Background(), oldConn, d)
		actualSource := net.UDPDestination(net.ParseAddress("192.0.2.9"), 1234)
		for _, dest := range []net.Destination{a, b} {
			packet := buf.FromBytes([]byte("reply"))
			if dest == b {
				packet.UDP = &actualSource
			}
			if err := d.get(dest)[0].responses.WriteMultiBuffer(buf.MultiBuffer{packet}); err != nil {
				t.Fatal(err)
			}
		}
		seenDest, seenID := make(map[string]bool), make(map[uint64]bool)
		var serverID uint64
		for range 2 {
			select {
			case encrypted := <-newConn.replies:
				reply, err := h.client.DecodePacket(encrypted)
				if err != nil {
					t.Fatal(err)
				}
				if reply.ClientSessionID != h.client.clientSessionID || string(reply.Payload) != "reply" {
					t.Fatal("response identity or payload changed")
				}
				if serverID != 0 && serverID != reply.SessionID {
					t.Fatal("destinations did not share server session identity")
				}
				serverID = reply.SessionID
				if seenID[reply.PacketID] {
					t.Fatal("server packet ID was reused")
				}
				seenID[reply.PacketID], seenDest[reply.Destination.String()] = true, true
			case <-time.After(time.Second):
				t.Fatal("response did not use the authenticated current return path")
			}
		}
		if !seenDest[a.String()] || !seenDest[actualSource.String()] {
			t.Fatalf("incorrect response sources: %v", seenDest)
		}
		select {
		case <-oldConn.replies:
			t.Fatal("replay moved the return path backwards")
		default:
		}
	})
}

func TestUDPDestinationContextIsolation(t *testing.T) {
	s := &ServerUDPSession{User: &protocol.MemoryUser{Email: "user@example.invalid"}}
	defer s.Close()
	d := new(destinationTestDispatcher)
	inbound := &session.Inbound{Tag: "in", Source: net.UDPDestination(net.ParseAddress("192.0.2.1"), 12345)}
	content := &session.Content{Attributes: map[string]string{"original": "value"}}
	outbound := &session.Outbound{Tag: "original"}
	ctx := session.ContextWithInbound(context.Background(), inbound)
	ctx = session.ContextWithContent(ctx, content)
	ctx = session.ContextWithOutbounds(ctx, []*session.Outbound{outbound})
	a, b := net.UDPDestination(net.LocalHostIP, 80), net.UDPDestination(net.LocalHostIP, 81)
	for _, dest := range []net.Destination{a, b} {
		if _, err := s.ensureDestinationRoute(ctx, newLifecycleConn(), dest, d, lifecyclePolicy{idle: time.Hour}, nil); err != nil {
			t.Fatal(err)
		}
	}
	first, second := d.get(a)[0].ctx, d.get(b)[0].ctx
	for _, routeCtx := range []context.Context{first, second} {
		got := session.InboundFromContext(routeCtx)
		if got == inbound || got.User != s.User || got.Source != inbound.Source {
			t.Fatal("route lost user/source identity or shared the inbound")
		}
		access := log.AccessMessageFromContext(routeCtx)
		if access.Email != s.User.Email || access.From.(net.Addr).String() != "127.0.0.1:12345" {
			t.Fatal("incorrect access log identity")
		}
	}
	session.ContentFromContext(first).Attributes["original"] = "changed"
	session.OutboundsFromContext(first)[0].Tag = "changed"
	session.InboundFromContext(first).Tag = "changed"
	if content.Attributes["original"] != "value" || session.ContentFromContext(second).Attributes["original"] != "value" ||
		outbound.Tag != "original" || session.OutboundsFromContext(second)[0].Tag != "" || inbound.Tag != "in" || session.InboundFromContext(second).Tag != "in" || inbound.User != nil {
		t.Fatal("destination mutation leaked to another route or source worker")
	}
	s.User.Cancel()
	waitDestinationClosed(t, first)
	waitDestinationClosed(t, second)
}

func TestUDPDestinationRouteLimit(t *testing.T) {
	s := new(ServerUDPSession)
	defer s.Close()
	d := new(destinationTestDispatcher)
	var first *udpDestinationRoute
	for i := 1; i <= udpMaxDestinationRoutes; i++ {
		route, err := s.ensureDestinationRoute(context.Background(), newLifecycleConn(), net.UDPDestination(net.LocalHostIP, net.Port(i)), d, lifecyclePolicy{idle: time.Hour}, nil)
		if err != nil {
			t.Fatal(err)
		}
		if i == 1 {
			first = route
		}
	}
	get := func(port int) (*udpDestinationRoute, error) {
		return s.ensureDestinationRoute(context.Background(), newLifecycleConn(), net.UDPDestination(net.LocalHostIP, net.Port(port)), d, lifecyclePolicy{idle: time.Hour}, nil)
	}
	if _, err := get(udpMaxDestinationRoutes + 1); err == nil {
		t.Fatal("unbounded destination table")
	}
	if got, err := get(1); err != nil || got != first {
		t.Fatal("full table broke an existing route")
	}
	s.retireDestinationRoute(first)
	if _, err := get(udpMaxDestinationRoutes + 1); err != nil {
		t.Fatal("retired route did not release capacity", err)
	}
}

func TestUDPDestinationConcurrentInitialization(t *testing.T) {
	s := new(ServerUDPSession)
	defer s.Close()
	d := new(destinationTestDispatcher)
	dest := net.UDPDestination(net.LocalHostIP, 80)
	start := make(chan struct{})
	results := make(chan *udpDestinationRoute, 32)
	var workers sync.WaitGroup
	for range 32 {
		workers.Add(1)
		go func() {
			defer workers.Done()
			<-start
			route, err := s.ensureDestinationRoute(context.Background(), newLifecycleConn(), dest, d, lifecyclePolicy{idle: time.Hour}, nil)
			if err != nil {
				t.Error(err)
			}
			results <- route
		}()
	}
	close(start)
	workers.Wait()
	close(results)
	if len(d.get(dest)) != 1 {
		t.Fatal("concurrent packets created duplicate routes")
	}
	var first *udpDestinationRoute
	for route := range results {
		if first == nil {
			first = route
		}
		if route == nil || route != first {
			t.Fatal("concurrent callers did not share one destination route")
		}
	}
}

func TestUDPDestinationCloseDuringDispatch(t *testing.T) {
	s := new(ServerUDPSession)
	defer s.Close()
	d := new(destinationTestDispatcher)
	gate := &lifecycleGateDispatcher{Dispatcher: d, entered: make(chan struct{}), release: make(chan struct{})}
	defer close(gate.release)
	dest := net.UDPDestination(net.LocalHostIP, 80)
	result := make(chan error, 1)
	go func() {
		_, err := s.ensureDestinationRoute(context.Background(), newLifecycleConn(), dest, gate, lifecyclePolicy{idle: time.Hour}, nil)
		result <- err
	}()
	<-gate.entered
	closed := make(chan struct{})
	go func() { s.Close(); close(closed) }()
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("blocked dispatch prevented session cleanup")
	}
	// A dispatcher may return a link after cancellation; it must be discarded.
	gate.release <- struct{}{}
	select {
	case err := <-result:
		if err == nil {
			t.Fatal("closed session published a late route")
		}
	case <-time.After(time.Second):
		t.Fatal("dispatch never finished")
	}
	late := d.get(dest)[0]
	waitDestinationClosed(t, late.ctx)
	packet := buf.FromBytes([]byte("late"))
	if err := late.responses.WriteMultiBuffer(buf.MultiBuffer{packet}); err == nil {
		t.Fatal("late response pipe remained open")
	}
}

type destinationFailureDispatcher struct {
	routing.Dispatcher
	failed bool
	ctx    context.Context
}

func (d *destinationFailureDispatcher) Dispatch(ctx context.Context, dest net.Destination) (*transport.Link, error) {
	if !d.failed {
		d.failed = true
		d.ctx = ctx
		return nil, io.ErrUnexpectedEOF
	}
	return d.Dispatcher.Dispatch(ctx, dest)
}

func TestUDPDestinationDispatchFailure(t *testing.T) {
	s := new(ServerUDPSession)
	defer s.Close()
	d := &destinationFailureDispatcher{Dispatcher: new(destinationTestDispatcher)}
	dest := net.UDPDestination(net.LocalHostIP, 80)
	get := func() (*udpDestinationRoute, error) {
		return s.ensureDestinationRoute(context.Background(), newLifecycleConn(), dest, d, lifecyclePolicy{idle: time.Hour}, nil)
	}
	if route, err := get(); route != nil || err == nil {
		t.Fatal("dispatch failure returned a usable route")
	}
	waitDestinationClosed(t, d.ctx)
	if route, err := get(); route == nil || err != nil {
		t.Fatal("dispatch failure poisoned the next packet", err)
	}
}

type destinationPendingDispatcher struct {
	routing.Dispatcher
	entered chan struct{}
}

func (d *destinationPendingDispatcher) Dispatch(ctx context.Context, _ net.Destination) (*transport.Link, error) {
	d.entered <- struct{}{}
	<-ctx.Done()
	return nil, ctx.Err()
}

func TestUDPDestinationPendingLimit(t *testing.T) {
	s := new(ServerUDPSession)
	defer s.Close()
	d := &destinationPendingDispatcher{entered: make(chan struct{}, udpMaxDestinationRoutes)}
	results := make(chan error, udpMaxDestinationRoutes)
	for port := 1; port <= udpMaxDestinationRoutes; port++ {
		go func(port int) {
			_, err := s.ensureDestinationRoute(context.Background(), newLifecycleConn(), net.UDPDestination(net.LocalHostIP, net.Port(port)), d, lifecyclePolicy{idle: time.Hour}, nil)
			results <- err
		}(port)
	}
	for range udpMaxDestinationRoutes {
		select {
		case <-d.entered:
		case <-time.After(time.Second):
			t.Fatal("independent pending routes blocked each other")
		}
	}
	if _, err := s.ensureDestinationRoute(context.Background(), newLifecycleConn(), net.UDPDestination(net.LocalHostIP, udpMaxDestinationRoutes+1), d, lifecyclePolicy{idle: time.Hour}, nil); err == nil {
		t.Fatal("pending dispatches escaped the destination bound")
	}
	s.Close()
	for range udpMaxDestinationRoutes {
		select {
		case err := <-results:
			if err == nil {
				t.Fatal("closed pending dispatch succeeded")
			}
		case <-time.After(time.Second):
			t.Fatal("pending dispatch did not exit on session cleanup")
		}
	}
}

func TestUDPDestinationIdleCleanup(t *testing.T) {
	s := new(ServerUDPSession)
	defer s.Close()
	d := new(destinationTestDispatcher)
	dest := net.UDPDestination(net.LocalHostIP, 80)
	if _, err := s.ensureDestinationRoute(context.Background(), newLifecycleConn(), dest, d, lifecyclePolicy{idle: 2 * time.Millisecond}, nil); err != nil {
		t.Fatal(err)
	}
	waitDestinationClosed(t, d.get(dest)[0].ctx)
	deadline := time.Now().Add(time.Second)
	for {
		s.destinationRoutes.Lock()
		empty := len(s.destinationRoutes.routes) == 0
		s.destinationRoutes.Unlock()
		if s.closed.Load() && empty {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("idle session retained destination links")
		}
		time.Sleep(time.Millisecond)
	}
}
