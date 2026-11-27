package inbound

import (
	"context"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/proxy/vless/multiplex"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/pipe"
)

var legacyMuxDestination = net.TCPDestination(net.DomainAddress("v1.mux.cool"), 9527)

// Released clients can still request a mux carrier through protocols such as
// Shadowsocks. VLESS and VMess handle their own carriers before dispatch.
type legacyMuxDispatcher struct {
	routing.Dispatcher
}

func (d *legacyMuxDispatcher) Dispatch(ctx context.Context, dest net.Destination) (*transport.Link, error) {
	if dest != legacyMuxDestination {
		return d.Dispatcher.Dispatch(ctx, dest)
	}
	inbound := session.InboundFromContext(ctx)
	if inbound == nil || inbound.User == nil {
		return d.Dispatcher.Dispatch(ctx, dest)
	}
	switch inbound.Name {
	case "shadowsocks", "shadowsocks-2022", "shadowsocks-2022-multi", "trojan":
	default:
		return d.Dispatcher.Dispatch(ctx, dest)
	}

	inbound.CanSpliceCopy = 3
	opts := pipe.OptionsFromContext(ctx)
	uplinkReader, uplinkWriter := pipe.New(opts...)
	downlinkReader, downlinkWriter := pipe.New(opts...)
	multiplex.NewServerWorker(ctx, d.Dispatcher.DispatchLink, &transport.Link{
		Reader: uplinkReader,
		Writer: downlinkWriter,
	})
	return &transport.Link{Reader: downlinkReader, Writer: uplinkWriter}, nil
}
