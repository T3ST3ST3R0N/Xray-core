package shadowsocks_2022

import (
	"context"
	"maps"
	"sync"
	"sync/atomic"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/log"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/signal"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet/stat"
)

const udpMaxDestinationRoutes = 256

// Native SS2022 datagrams share authentication, replay protection and a reply
// path, but not a routing decision. Opaque relays still use the single link.
type udpDestinationRoutes struct {
	sync.Mutex
	ctx    context.Context
	cancel context.CancelFunc
	routes map[string]*udpDestinationRoute
}

type udpDestinationRoute struct {
	once   sync.Once
	key    string
	cancel context.CancelFunc
	ready  chan struct{}
	err    error // published by closing ready
	link   atomic.Pointer[transport.Link]
}

func (r *udpDestinationRoute) close() {
	r.once.Do(func() {
		r.cancel()
		if link := r.link.Load(); link != nil {
			common.Interrupt(link.Reader)
			common.Interrupt(link.Writer)
		}
	})
}

func (s *ServerUDPSession) closeDestinationRoutes() {
	s.destinationRoutes.Lock()
	cancel := s.destinationRoutes.cancel
	routes := s.destinationRoutes.routes
	s.destinationRoutes.routes = nil
	s.destinationRoutes.Unlock()
	if cancel != nil {
		cancel()
	}
	for _, route := range routes {
		route.close()
	}
}

func (s *ServerUDPSession) retireDestinationRoute(route *udpDestinationRoute) {
	s.destinationRoutes.Lock()
	if s.destinationRoutes.routes[route.key] == route {
		delete(s.destinationRoutes.routes, route.key)
	}
	s.destinationRoutes.Unlock()
	route.close()
}

func (s *ServerUDPSession) ensureDestinationRoute(ctx context.Context, conn stat.Connection, dest net.Destination, dispatcher routing.Dispatcher, policyManager policy.Manager, encode func(net.Destination, []byte) ([]byte, error)) (*udpDestinationRoute, error) {
	s.userMu.RLock()
	user := s.User
	s.userMu.RUnlock()
	key := dest.String()
	s.destinationRoutes.Lock()
	if s.closed.Load() {
		s.destinationRoutes.Unlock()
		return nil, errors.New("udp session closed")
	}
	if s.destinationRoutes.ctx == nil {
		// A session may rebind. Only its current authenticated return path,
		// user removal or inactivity should cancel all destination routes.
		sessCtx, cancel := context.WithCancel(context.WithoutCancel(ctx))
		s.destinationRoutes.ctx, s.destinationRoutes.cancel = sessCtx, cancel
		s.destinationRoutes.routes = make(map[string]*udpDestinationRoute)
		var level uint32
		if user != nil {
			level = user.Level
			stop := context.AfterFunc(user.Context(), cancel)
			context.AfterFunc(sessCtx, func() { stop() })
		}
		s.timer.Store(signal.CancelAfterInactivity(sessCtx, cancel, policyManager.ForLevel(level).Timeouts.ConnectionIdle))
		context.AfterFunc(sessCtx, s.end)
	}
	sessCtx := s.destinationRoutes.ctx
	if route := s.destinationRoutes.routes[key]; route != nil {
		s.destinationRoutes.Unlock()
		select {
		case <-route.ready:
			return route, route.err
		case <-sessCtx.Done():
			return nil, sessCtx.Err()
		}
	}
	// Count pending dispatches as well, so concurrent new destinations cannot
	// exceed the bound. Existing routes remain usable when the table is full.
	if len(s.destinationRoutes.routes) >= udpMaxDestinationRoutes {
		s.destinationRoutes.Unlock()
		return nil, errors.New("too many UDP destinations")
	}
	routeCtx, cancel := context.WithCancel(sessCtx)
	route := &udpDestinationRoute{key: key, cancel: cancel, ready: make(chan struct{})}
	s.destinationRoutes.routes[key] = route
	s.destinationRoutes.Unlock()

	// Routing and sniffing mutate these values. Never share them between
	// destinations, or overwrite the source worker's authenticated metadata.
	routeCtx = session.ContextWithOutbounds(routeCtx, []*session.Outbound{{}})
	content := new(session.Content)
	if parent := session.ContentFromContext(ctx); parent != nil {
		*content = *parent
		content.Attributes = maps.Clone(parent.Attributes)
	}
	routeCtx = session.ContextWithContent(routeCtx, content)
	if inbound := session.InboundFromContext(ctx); inbound != nil {
		copy := *inbound
		copy.User = user
		routeCtx = session.ContextWithInbound(routeCtx, &copy)
	}
	var email string
	if user != nil {
		email = user.Email
	}
	routeCtx = log.ContextWithAccessMessage(routeCtx, &log.AccessMessage{
		From: conn.RemoteAddr(), To: dest, Status: log.AccessAccepted, Email: email,
	})

	// Dispatch may block. Other destinations and session cleanup must not wait
	// under the route-map lock for it to finish.
	link, err := dispatcher.Dispatch(routeCtx, dest)
	s.destinationRoutes.Lock()
	if err == nil && (s.closed.Load() || routeCtx.Err() != nil) {
		err = errors.New("udp session closed")
	}
	if err != nil {
		if s.destinationRoutes.routes[key] == route {
			delete(s.destinationRoutes.routes, key)
		}
	} else {
		route.link.Store(link)
	}
	route.err = err
	close(route.ready)
	s.destinationRoutes.Unlock()
	if err != nil {
		cancel()
		if link != nil {
			common.Interrupt(link.Reader)
			common.Interrupt(link.Writer)
		}
		return nil, err
	}
	go s.handleDestinationResponse(route, dest, encode)
	return route, nil
}

func (s *ServerUDPSession) writeDestinationPacket(route *udpDestinationRoute, packet *buf.Buffer) {
	if err := route.link.Load().Writer.WriteMultiBuffer(buf.MultiBuffer{packet}); err != nil {
		// A writer owns the buffer and may have consumed the datagram even on
		// error. Retire this route; let the next packet recreate it, never replay.
		s.retireDestinationRoute(route)
	}
}

func (s *ServerUDPSession) handleDestinationResponse(route *udpDestinationRoute, fallback net.Destination, encode func(net.Destination, []byte) ([]byte, error)) {
	defer s.retireDestinationRoute(route)
	for {
		mb, readErr := route.link.Load().Reader.ReadMultiBuffer()
		for n, b := range mb {
			dest := fallback
			if b.UDP != nil {
				dest = *b.UDP
			}
			packet, err := encode(dest, b.Bytes())
			b.Release()
			if err != nil {
				continue
			}
			if err := s.WriteToClient(packet); err != nil {
				buf.ReleaseMulti(mb[n+1:])
				s.end()
				return
			}
			s.updateActivity()
		}
		if readErr != nil {
			return
		}
	}
}
