package shadowsocks_2022

import (
	"bytes"
	"crypto/cipher"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/signal"
	"github.com/xtls/xray-core/common/utils"
	"github.com/xtls/xray-core/transport"
)

const (
	swBlockBitLog = 6                                // 1<<6 == 64 bits
	swBlockBits   = 1 << swBlockBitLog               // 64
	swRingBlocks  = 1 << 7                           // 128
	swBlockMask   = swRingBlocks - 1                 // 127
	swBitMask     = swBlockBits - 1                  // 63
	swSize        = (swRingBlocks - 1) * swBlockBits // 8128
)

type SlidingWindow struct {
	last uint64
	ring [swRingBlocks]uint64
}

func (f *SlidingWindow) Reset() {
	*f = SlidingWindow{}
}

func (f *SlidingWindow) Check(counter uint64) bool {
	switch {
	case counter > f.last:
		return true
	case f.last-counter > swSize:
		return false
	}

	blockIndex := (counter >> swBlockBitLog) & swBlockMask
	bitIndex := counter & swBitMask
	return (f.ring[blockIndex]>>bitIndex)&1 == 0
}

func (f *SlidingWindow) Add(counter uint64) {
	blockIndex := counter >> swBlockBitLog

	if counter > f.last {
		lastBlockIndex := f.last >> swBlockBitLog
		diff := blockIndex - lastBlockIndex
		if diff > swRingBlocks {
			diff = swRingBlocks
		}

		for i := 0; i < int(diff); i++ {
			lastBlockIndex = (lastBlockIndex + 1) & swBlockMask
			f.ring[lastBlockIndex] = 0
		}

		f.last = counter
	}

	blockIndex &= swBlockMask
	bitIndex := counter & swBitMask
	f.ring[blockIndex] |= 1 << bitIndex
}

func (f *SlidingWindow) CheckAndAdd(counter uint64) bool {
	if !f.Check(counter) {
		return false
	}
	f.Add(counter)
	return true
}

type ServerUDPSession struct {
	sync.Mutex
	SessionID  uint64
	Window     *SlidingWindow
	User       *protocol.MemoryUser
	UserPSK    []byte
	LastActive atomic.Int64 // Unix timestamp in seconds

	// receiveMu protects cipher initialization and authenticated replay acceptance.
	// It is never held during routing or packet writes.
	receiveMu        sync.Mutex
	replayMu         sync.Mutex
	userMu           sync.RWMutex
	clientBodyCipher cipher.AEAD

	ServerSessionID   uint64
	ServerPacketID    atomic.Uint64
	serverBodyCipher  cipher.AEAD
	serverHeaderBlock cipher.Block
	serverChaCha      cipher.AEAD

	manager     *UDPSessionManager
	link        atomic.Pointer[transport.Link]
	timer       atomic.Pointer[signal.ActivityTimer]
	currentConn udpReturnPath
	closed      atomic.Bool

	destinationRoutes udpDestinationRoutes
}

func (s *ServerUDPSession) CheckPacketID(packetID uint64) bool {
	s.replayMu.Lock()
	defer s.replayMu.Unlock()
	if s.Window == nil {
		s.Window = new(SlidingWindow)
	}
	return s.Window.Check(packetID)
}

func (s *ServerUDPSession) AcceptPacketID(packetID uint64) bool {
	s.replayMu.Lock()
	defer s.replayMu.Unlock()
	if s.Window == nil {
		s.Window = new(SlidingWindow)
	}
	return s.Window.CheckAndAdd(packetID)
}

type UDPSessionManager struct {
	sessions  *utils.TypedSyncMap[uint64, *ServerUDPSession]
	timeout   time.Duration
	lastClean atomic.Int64 // Unix timestamp in seconds
	// ended keeps sessions deleted while their packets could still pass the
	// timestamp check, so a new session for the same ID takes over their
	// replay window instead of accepting those packets again.
	ended *utils.TypedSyncMap[uint64, *ServerUDPSession]
}

// A packet passes the timestamp check up to 30 seconds either side of its
// timestamp, so it can be replayed for up to a minute after it arrived.
const replayableSeconds = 60

func NewUDPSessionManager(timeout time.Duration) *UDPSessionManager {
	return &UDPSessionManager{
		sessions: utils.NewTypedSyncMap[uint64, *ServerUDPSession](),
		timeout:  timeout,
		ended:    utils.NewTypedSyncMap[uint64, *ServerUDPSession](),
	}
}

func (m *UDPSessionManager) GetOrCreate(sessionID uint64) *ServerUDPSession {
	now := time.Now().Unix()
	if s, ok := m.sessions.Load(sessionID); ok {
		s.LastActive.Store(now)
		return s
	}

	s := m.newSession(sessionID)
	s.LastActive.Store(now)

	actual, loaded := m.sessions.LoadOrStore(sessionID, s)
	if loaded {
		actual.LastActive.Store(now)
		return actual
	}

	// Trigger cleanup if at least 30 seconds have passed since last cleanup
	last := m.lastClean.Load()
	if now-last > 30 && m.lastClean.CompareAndSwap(last, now) {
		go m.cleanup(now)
	}

	return s
}

// Load returns the session stored for sessionID, or a new one that Store
// publishes once a packet for it authenticates, so packets that fail
// authentication cannot fill the map.
func (m *UDPSessionManager) Load(sessionID uint64) (*ServerUDPSession, bool) {
	if s, ok := m.sessions.Load(sessionID); ok {
		s.LastActive.Store(time.Now().Unix())
		return s, true
	}
	return m.newSession(sessionID), false
}

func (m *UDPSessionManager) newSession(sessionID uint64) *ServerUDPSession {
	s := &ServerUDPSession{SessionID: sessionID, manager: m}
	if old, ok := m.ended.Load(sessionID); ok {
		old.replayMu.Lock()
		if old.Window != nil {
			window := *old.Window
			s.Window = &window
		}
		old.replayMu.Unlock()
	}
	return s
}

// Store publishes a new session from Load after packetID authenticated on it.
// If another packet stored a session for the same ID first, that session is
// returned, and the packet counts only if it is new to it and was decrypted
// with the same key.
func (m *UDPSessionManager) Store(s *ServerUDPSession, packetID uint64) (*ServerUDPSession, bool) {
	now := time.Now().Unix()
	s.LastActive.Store(now)
	actual, loaded := m.sessions.LoadOrStore(s.SessionID, s)
	if !loaded {
		last := m.lastClean.Load()
		if now-last > 30 && m.lastClean.CompareAndSwap(last, now) {
			go m.cleanup(now)
		}
		return s, true
	}
	actual.LastActive.Store(now)
	actual.receiveMu.Lock()
	defer actual.receiveMu.Unlock()
	actual.userMu.RLock()
	sameKey := bytes.Equal(actual.UserPSK, s.UserPSK)
	actual.userMu.RUnlock()
	return actual, sameKey && actual.AcceptPacketID(packetID)
}

func (m *UDPSessionManager) cleanup(now int64) {
	timeoutSec := int64(m.timeout.Seconds())
	if timeoutSec <= 0 {
		timeoutSec = 60
	}
	m.sessions.Range(func(k uint64, v *ServerUDPSession) bool {
		if now-v.LastActive.Load() > timeoutSec {
			if m.sessions.CompareAndDelete(k, v) {
				v.Close()
			}
		}
		return true
	})
	m.ended.Range(func(k uint64, v *ServerUDPSession) bool {
		if now-v.LastActive.Load() > replayableSeconds {
			m.ended.CompareAndDelete(k, v)
		}
		return true
	})
}

func (m *UDPSessionManager) Delete(session *ServerUDPSession) {
	// A late timeout must not delete a replacement with the same wire ID.
	if m.sessions.CompareAndDelete(session.SessionID, session) &&
		time.Now().Unix()-session.LastActive.Load() <= replayableSeconds {
		m.ended.Store(session.SessionID, session)
	}
}
