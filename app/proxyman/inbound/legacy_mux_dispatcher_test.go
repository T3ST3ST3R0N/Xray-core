package inbound

import (
	"context"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport"
)

type legacyMuxPacket struct {
	destination net.Destination
	payload     string
}

type legacyMuxTestRouter struct {
	routing.Dispatcher
	packets chan legacyMuxPacket
}

var errLegacyMuxDirectDispatch = errors.New("destination passed to ordinary routing")

func (*legacyMuxTestRouter) Dispatch(context.Context, net.Destination) (*transport.Link, error) {
	return nil, errLegacyMuxDirectDispatch
}

func (r *legacyMuxTestRouter) DispatchLink(_ context.Context, destination net.Destination, link *transport.Link) error {
	defer common.Close(link.Writer)
	packet, err := link.Reader.(buf.TimeoutReader).ReadMultiBufferTimeout(time.Second)
	defer buf.ReleaseMulti(packet)
	if err == nil {
		r.packets <- legacyMuxPacket{destination, packet.String()}
	}
	return err
}

func TestLegacyMuxDispatchesXUDP(t *testing.T) {
	packets := make(chan legacyMuxPacket, 1)
	dispatcher := &legacyMuxDispatcher{Dispatcher: &legacyMuxTestRouter{packets: packets}}
	ctx := session.ContextWithInbound(t.Context(), &session.Inbound{
		Name: "shadowsocks-2022-multi",
		User: &protocol.MemoryUser{Email: "test@example.com"},
	})
	link, err := dispatcher.Dispatch(ctx, net.TCPDestination(net.DomainAddress("v1.mux.cool"), 9527))
	if err != nil {
		t.Fatal(err)
	}
	defer common.Interrupt(link.Reader)
	defer common.Interrupt(link.Writer)

	// Legacy XUDP New frame with an IPv4 destination and a nonzero global ID.
	frame := buf.New()
	common.Must2(frame.Write([]byte{0, 20, 0, 1, 1, 1, 2, 0, 53, 1, 192, 0, 2, 1}))
	// A new ID avoids reusing a retained association when the test is repeated.
	common.Must2(rand.Read(frame.Extend(8)))
	common.Must2(frame.Write([]byte{0, 4, 'p', 'i', 'n', 'g'}))
	if err := link.Writer.WriteMultiBuffer(buf.MultiBuffer{frame}); err != nil {
		t.Fatal(err)
	}
	want := legacyMuxPacket{net.UDPDestination(net.ParseAddress("192.0.2.1"), 53), "ping"}
	select {
	case got := <-packets:
		if got != want {
			t.Fatalf("routed packet = %+v, want %+v", got, want)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("legacy XUDP packet was not routed")
	}
}

func TestLegacyMuxLeavesHTTPToRouting(t *testing.T) {
	dispatcher := &legacyMuxDispatcher{Dispatcher: &legacyMuxTestRouter{}}
	ctx := session.ContextWithInbound(t.Context(), &session.Inbound{
		Name: "http",
		User: &protocol.MemoryUser{},
	})
	link, err := dispatcher.Dispatch(ctx, net.TCPDestination(net.DomainAddress("v1.mux.cool"), 9527))
	if link != nil {
		common.Interrupt(link.Writer)
		common.Interrupt(link.Reader)
	}
	if !errors.Is(err, errLegacyMuxDirectDispatch) {
		t.Fatalf("HTTP passed through legacy mux, err = %v", err)
	}
}
