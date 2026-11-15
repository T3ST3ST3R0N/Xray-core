package shadowsocks_2022

import (
	"context"
	"sync"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/log"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/signal"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/proxy"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet/stat"
)

// udpReturnPath keeps the connection and authenticated high-water mark together.
// Only a fully validated packet may move an authenticated session's return path.
type udpReturnPath struct {
	sync.RWMutex
	conn     stat.Connection
	packetID uint64
	stop     func() bool
}

// UpdateConn is used only by relays, which cannot authenticate the inner payload.
func (s *ServerUDPSession) UpdateConn(ctx context.Context, conn stat.Connection) {
	s.currentConn.Lock()
	s.setConn(ctx, conn)
	s.currentConn.Unlock()
	s.updateActivity()
}

func (s *ServerUDPSession) UpdateAuthenticatedConn(ctx context.Context, conn stat.Connection, packetID uint64) {
	s.currentConn.Lock()
	if s.currentConn.conn == nil || packetID > s.currentConn.packetID {
		s.setConn(ctx, conn)
		s.currentConn.packetID = packetID
	}
	s.currentConn.Unlock()
	s.updateActivity()
}

// setConn requires currentConn to be locked. The inbound worker cancels a
// connection's context once it has been idle for a while, so the session ends
// with the connection that carries its replies, not the one that created it.
func (s *ServerUDPSession) setConn(ctx context.Context, conn stat.Connection) {
	if s.currentConn.conn == conn {
		return
	}
	if s.currentConn.stop != nil {
		s.currentConn.stop()
	}
	s.currentConn.conn = conn
	s.currentConn.stop = context.AfterFunc(ctx, func() {
		s.currentConn.RLock()
		current := s.currentConn.conn == conn
		s.currentConn.RUnlock()
		if current {
			s.end()
		}
	})
}

func (s *ServerUDPSession) updateActivity() {
	s.LastActive.Store(time.Now().Unix())
	if timer := s.timer.Load(); timer != nil {
		timer.Update()
	}
}

func (s *ServerUDPSession) WriteToClient(b []byte) error {
	s.currentConn.RLock()
	conn := s.currentConn.conn
	s.currentConn.RUnlock()
	if conn == nil {
		return errors.New("client connection closed")
	}
	_, err := conn.Write(b)
	return err
}

func (s *ServerUDPSession) end() {
	if s.manager != nil {
		s.manager.Delete(s)
	}
	s.Close()
}

func (s *ServerUDPSession) Close() {
	s.closed.Store(true)
	s.closeDestinationRoutes()
	s.currentConn.Lock()
	if s.currentConn.stop != nil {
		s.currentConn.stop()
	}
	s.currentConn.Unlock()
	if timer := s.timer.Load(); timer != nil {
		timer.SetTimeout(0)
	}
	if link := s.link.Load(); link != nil {
		common.Interrupt(link.Reader)
		common.Interrupt(link.Writer)
	}
}

func (s *ServerUDPSession) EnsureLink(
	ctx context.Context,
	conn stat.Connection,
	dest net.Destination,
	dispatcher routing.Dispatcher,
	policyManager policy.Manager,
	responseEncoder func(dest net.Destination, payload []byte) ([]byte, error),
) (*transport.Link, error) {
	s.Lock()
	defer s.Unlock()

	if s.closed.Load() {
		return nil, errors.New("udp session closed")
	}
	if link := s.link.Load(); link != nil {
		return link, nil
	}

	// The client can move to another source address, so the context of the
	// connection that created the session must not end it (see setConn).
	sessCtx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	s.userMu.RLock()
	user := s.User
	s.userMu.RUnlock()
	if inbound := session.InboundFromContext(sessCtx); inbound != nil && user != nil {
		// Sessions from one source address share its Inbound.
		sessInbound := *inbound
		sessInbound.User = user
		sessCtx = session.ContextWithInbound(sessCtx, &sessInbound)
	}
	var email string
	var level uint32
	if user != nil {
		email = user.Email
		level = user.Level
	}
	sessCtx = log.ContextWithAccessMessage(sessCtx, &log.AccessMessage{
		From:   conn.RemoteAddr(),
		To:     dest,
		Status: log.AccessAccepted,
		Email:  email,
	})

	link, err := dispatcher.Dispatch(sessCtx, dest)
	if err != nil {
		cancel()
		return nil, err
	}

	sessionPolicy := policyManager.ForLevel(level)
	timer := signal.CancelAfterInactivity(sessCtx, func() {
		s.end()
		cancel()
	}, sessionPolicy.Timeouts.ConnectionIdle)
	s.timer.Store(timer)
	s.link.Store(link)
	// Timeout or cleanup can win while Dispatch or timer creation is running.
	if s.closed.Load() {
		s.Close()
		cancel()
		return nil, errors.New("udp session closed")
	}
	if user != nil {
		// Removing the user ends the session the way its idle timeout does.
		stop := context.AfterFunc(user.Context(), func() {
			timer.SetTimeout(0)
		})
		context.AfterFunc(sessCtx, func() {
			stop()
		})
	}

	go handleUDPResponse(s, link, dest, responseEncoder)
	return link, nil
}

// ResetTCPConn sets SO_LINGER to 0 per SIP022 §3.1.4 to consistently send RST on close
// when handshake or header validation fails.
func ResetTCPConn(conn net.Conn) {
	rawConn, _, _ := proxy.UnwrapRawConn(conn)
	if tcpConn, ok := rawConn.(*net.TCPConn); ok {
		_ = tcpConn.SetLinger(0)
	}
}

func handleUDPResponse(s *ServerUDPSession, link *transport.Link, fallbackDest net.Destination, encode func(dest net.Destination, payload []byte) ([]byte, error)) {
	defer s.Close()
	for {
		resMb, err := link.Reader.ReadMultiBuffer()
		if err != nil {
			return
		}
		s.updateActivity()
		for i, rb := range resMb {
			b := rb.Bytes()
			if encode != nil {
				replyDest := fallbackDest
				if rb.UDP != nil {
					replyDest = *rb.UDP
				}
				encPacket, err := encode(replyDest, b)
				rb.Release()
				if err != nil {
					continue
				}
				if err := s.WriteToClient(encPacket); err != nil {
					buf.ReleaseMulti(resMb[i+1:])
					return
				}
			} else {
				err := s.WriteToClient(b)
				rb.Release()
				if err != nil {
					buf.ReleaseMulti(resMb[i+1:])
					return
				}
			}
		}
	}
}

const (
	HeaderTypeClient              = 0
	HeaderTypeServer              = 1
	MaxPaddingLength              = 900
	PacketNonceSize               = 24
	MaxPacketSize                 = 65535
	RequestHeaderFixedChunkLength = 1 + 8 + 2 // Type (1B) + Timestamp (8B) + VarHeaderLen (2B)
	PacketMinimalHeaderSize       = 30
	StreamNonceSize               = 12
	AESBlockSize                  = 16
	AEADTagSize                   = 16
)

var zeroPadding [MaxPaddingLength]byte

const (
	MethodAES128GCM        = "2022-blake3-aes-128-gcm"
	MethodAES256GCM        = "2022-blake3-aes-256-gcm"
	MethodChaCha20Poly1305 = "2022-blake3-chacha20-poly1305"
)

var (
	ErrBadKey            = errors.New("bad key")
	ErrBadHeaderType     = errors.New("bad header type")
	ErrBadTimestamp      = errors.New("bad timestamp")
	ErrSaltNotUnique     = errors.New("salt not unique")
	ErrPacketIdNotUnique = errors.New("packet id not unique")
	ErrPacketTooShort    = errors.New("packet too short")
	ErrPacketTooLarge    = errors.New("packet too large")
	ErrNoPadding         = errors.New("bad request: missing payload or padding")
	ErrInvalidRequest    = errors.New("invalid request")
)
