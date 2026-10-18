package wireguard

import (
	"context"
	goerrors "errors"
	"io"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"syscall"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/features/stats"
	"golang.org/x/net/ipv6"
	"golang.zx2c4.com/wireguard/conn"
)

const (
	// socketBufferSize matches wireguard-go's StdNetBind.
	socketBufferSize = 7 << 20

	// maxGSOSegments is the kernel's limit of datagrams in one UDP_SEGMENT send.
	maxGSOSegments = 64
	// A UDP_SEGMENT send must fit in one IP packet before it is split.
	maxGSOPayload4 = 1<<16 - 1 - 20 - 8
	maxGSOPayload6 = 1<<16 - 1 - 8
)

// batchConn reads and writes many datagrams per syscall (recvmmsg/sendmmsg).
// ipv4.PacketConn and ipv6.PacketConn both implement it.
type batchConn interface {
	ReadBatch(ms []ipv6.Message, flags int) (int, error)
	WriteBatch(ms []ipv6.Message, flags int) (int, error)
}

type bind struct {
	ctx         context.Context
	resolveFunc func(host string) (net.IP, error)
	listenFunc  func(ctx context.Context) (net.PacketConn, error)
	downFunc    func() error
	reserved    []byte

	// batchEnabled opts a known native listener into Linux batching before
	// NewDevice allocates its lifetime-sized pools. Custom/masked listeners
	// default to one packet; Open may disable batching, but never enable it.
	batchEnabled bool

	net.PacketConn
	// batch is set when the conn is a plain UDP socket on Linux. The traffic
	// counters are then applied here, since PacketCounterConnection is bypassed.
	batch        batchConn
	gso          bool // batch takes UDP_SEGMENT
	udp          *net.UDPConn
	raw          syscall.RawConn
	readCounter  stats.Counter
	writeCounter stats.Counter
	msgsPool     sync.Pool
	closeCh      chan struct{}
	mu           sync.Mutex
}

type bindMessages struct {
	messages [conn.IdealBatchSize]ipv6.Message
	control  [conn.IdealBatchSize][24]byte // Largest Linux CmsgSpace(sizeof(uint16)).
	used     int                           // High-water mark across send chunks.
	addr     net.UDPAddr
	ip       [16]byte
	send     bindSendmsg
}

// nativeUDPConn unwraps only the transparent traffic counter, never a mask.
func nativeUDPConn(c net.PacketConn) (*net.UDPConn, stats.Counter, stats.Counter) {
	var rc, wc stats.Counter
	if pc, ok := c.(*PacketCounterConnection); ok {
		c, rc, wc = pc.PacketConn, pc.ReadCounter, pc.WriteCounter
	}
	if udp, ok := c.(*net.UDPConn); ok {
		return udp, rc, wc
	}
	return nil, nil, nil
}

func (b *bind) SetCtx(ctx context.Context) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.ctx = ctx
}

func (b *bind) Open(port uint16) (fns []conn.ReceiveFunc, actualPort uint16, err error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.PacketConn != nil {
		return nil, 0, conn.ErrBindAlreadyOpen
	}

	c, err := b.listenFunc(b.ctx)
	if err != nil {
		return nil, 0, err
	}
	b.PacketConn = c
	b.udp, b.readCounter, b.writeCounter = nativeUDPConn(c)
	if b.batchEnabled {
		b.batch, b.gso = newBatchConn(b.udp)
		if b.batch == nil {
			b.batchEnabled = false
		}
	}
	if b.batch != nil {
		b.raw, _ = b.udp.SyscallConn()
	}
	ch := make(chan struct{})
	b.closeCh = ch

	recv := b.makeReceive(c, b.udp, b.readCounter, ch)
	if b.batch != nil {
		recv = b.makeReceiveBatch(b.batch, b.readCounter, ch)
	}
	return []conn.ReceiveFunc{recv}, uint16(c.LocalAddr().(*net.UDPAddr).Port), nil
}

// readFailed handles a read error and reports whether the bind is closed.
func (b *bind) readFailed(err error, ch chan struct{}) bool {
	if goerrors.Is(err, io.EOF) || goerrors.Is(err, io.ErrClosedPipe) || goerrors.Is(err, net.ErrClosed) {
		select {
		case <-ch:
		default:
			errors.LogErrorInner(context.Background(), err, "unexpected closed")
			if b.downFunc != nil {
				go func() {
					common.Must(b.downFunc())
				}()
			}
		}
		return true
	}
	errors.LogErrorInner(context.Background(), err, "bind recv err")
	return false
}

func (b *bind) makeReceive(c net.PacketConn, udp *net.UDPConn, rc stats.Counter, ch chan struct{}) conn.ReceiveFunc {
	return func(bufs [][]byte, sizes []int, eps []conn.Endpoint) (n int, err error) {
		for {
			var addr netip.AddrPort
			if udp != nil {
				n, addr, err = udp.ReadFromUDPAddrPort(bufs[0])
			} else {
				var rawAddr net.Addr
				n, rawAddr, err = c.ReadFrom(bufs[0])
				if err == nil {
					addr = rawAddr.(*net.UDPAddr).AddrPort()
				}
			}
			if err != nil {
				if b.readFailed(err, ch) {
					return 0, net.ErrClosed
				}
				continue
			}
			if n > 3 {
				bufs[0][1] = 0
				bufs[0][2] = 0
				bufs[0][3] = 0
			}
			sizes[0] = n
			eps[0] = &conn.StdNetEndpoint{AddrPort: addr}
			if rc != nil {
				rc.Add(int64(n))
			}
			return 1, nil
		}
	}
}

// makeReceiveBatch reads up to len(bufs) datagrams per call. wireguard-go calls
// each ReceiveFunc from a single goroutine, so msgs is not shared.
func (b *bind) makeReceiveBatch(bc batchConn, rc stats.Counter, ch chan struct{}) conn.ReceiveFunc {
	msgs := make([]ipv6.Message, conn.IdealBatchSize)
	for i := range msgs {
		msgs[i].Buffers = make(net.Buffers, 1)
	}
	return func(bufs [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
		count := min(len(bufs), len(msgs))
		for i := 0; i < count; i++ {
			msgs[i].Buffers[0] = bufs[i]
			msgs[i].N = 0
			msgs[i].Addr = nil
		}
		for {
			n, err := bc.ReadBatch(msgs[:count], 0)
			if err != nil {
				if b.readFailed(err, ch) {
					return 0, net.ErrClosed
				}
				continue
			}
			var total int64
			for i := 0; i < n; i++ {
				m := &msgs[i]
				if m.N > 3 {
					bufs[i][1] = 0
					bufs[i][2] = 0
					bufs[i][3] = 0
				}
				sizes[i] = m.N
				eps[i] = &conn.StdNetEndpoint{AddrPort: m.Addr.(*net.UDPAddr).AddrPort()}
				total += int64(m.N)
			}
			if rc != nil {
				rc.Add(total)
			}
			return n, nil
		}
	}
}

func (b *bind) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.PacketConn != nil {
		close(b.closeCh)
		_ = b.PacketConn.Close()
		b.PacketConn = nil
		b.batch = nil
		b.udp = nil
		b.raw = nil
		b.gso = false
	}
	return nil
}

func (b *bind) SetMark(mark uint32) error {
	return nil
}

func (b *bind) Send(bufs [][]byte, ep conn.Endpoint) error {
	b.mu.Lock()
	c, udp, raw, bc, gso, wc := b.PacketConn, b.udp, b.raw, b.batch, b.gso, b.writeCounter
	b.mu.Unlock()

	if c == nil {
		return syscall.EAFNOSUPPORT
	}

	if len(b.reserved) == 3 {
		for i := range bufs {
			if len(bufs[i]) > 3 {
				bufs[i][1] = b.reserved[0]
				bufs[i][2] = b.reserved[1]
				bufs[i][3] = b.reserved[2]
			}
		}
	}
	addrPort := ep.(*conn.StdNetEndpoint).AddrPort
	if udp != nil && (bc == nil || len(bufs) == 1) {
		var total int64
		for _, buf := range bufs {
			n, err := udp.WriteToUDPAddrPort(buf, addrPort)
			if err != nil {
				if wc != nil {
					wc.Add(total)
				}
				errors.LogErrorInner(context.Background(), err, "bind send err")
				return err
			}
			total += int64(n)
		}
		if wc != nil {
			wc.Add(total)
		}
		return nil
	}
	if bc == nil {
		addr := net.UDPAddrFromAddrPort(addrPort)
		for i := range bufs {
			if _, err := c.WriteTo(bufs[i], addr); err != nil {
				errors.LogErrorInner(context.Background(), err, "bind send err")
				return err
			}
		}
		return nil
	}

	msgs := b.getMsgs()
	defer b.putMsgs(msgs)
	msgs.ip = addrPort.Addr().As16()
	msgs.addr = net.UDPAddr{IP: msgs.ip[:], Port: int(addrPort.Port()), Zone: addrPort.Addr().Zone()}
	if addrPort.Addr().Is4() {
		msgs.addr.IP = msgs.ip[12:]
	}
	sent, failedGSO, err := sendBatch(bc, raw, msgs, bufs, gso)
	if failedGSO {
		// Retry only the unsent suffix of a failed UDP_SEGMENT send, using
		// ordinary batching. A plain-message error must never disable GSO.
		errors.LogInfoInner(context.Background(), err, "bind: UDP GSO disabled")
		b.mu.Lock()
		if b.batch == bc {
			b.gso = false
		}
		b.mu.Unlock()
		var more int
		more, _, err = sendBatch(bc, raw, msgs, bufs[sent:], false)
		sent += more
	}
	if wc != nil {
		var total int64
		for _, buf := range bufs[:sent] {
			total += int64(len(buf))
		}
		wc.Add(total)
	}
	if err != nil {
		errors.LogErrorInner(context.Background(), err, "bind send err")
	}
	return err
}

// sendBatch reports the exact completed datagram prefix, even when WriteBatch
// returns both progress and an error. failedGSO describes the first unsent
// message, not merely whether any message in the call used UDP_SEGMENT.
func sendBatch(bc batchConn, raw syscall.RawConn, msgs *bindMessages, bufs [][]byte, gso bool) (sent int, failedGSO bool, err error) {
	for sent < len(bufs) {
		n, _ := packMsgs(msgs.messages[:], bufs[sent:], &msgs.addr, gso)
		msgs.used = max(msgs.used, n)
		for i := 0; i < n; {
			k, err := writeBatch(bc, raw, &msgs.send, msgs.messages[i:n])
			// x/net can pass sendmmsg's raw -1 completion count through.
			if k < 0 {
				k = 0
			}
			for _, m := range msgs.messages[i : i+k] {
				sent += len(m.Buffers)
			}
			i += k
			if err != nil {
				return sent, i < n && len(msgs.messages[i].OOB) > 0 && gsoFailed(err), err
			}
			if k == 0 {
				return sent, false, io.ErrShortWrite
			}
		}
	}
	return sent, false, nil
}

// packMsgs fills msgs from the start of bufs and returns the number of
// messages used and of datagrams in them. Each message holds one datagram, or
// with gso a run of datagrams of one size (only the last may be shorter) that
// the kernel splits again (UDP_SEGMENT).
func packMsgs(msgs []ipv6.Message, bufs [][]byte, addr *net.UDPAddr, gso bool) (n, i int) {
	maxPayload := maxGSOPayload6
	if addr.IP.To4() != nil {
		maxPayload = maxGSOPayload4
	}
	for ; i < len(bufs) && n < len(msgs); n++ {
		size := len(bufs[i])
		j, total := i+1, size
		for gso && size > 0 && j < len(bufs) && j-i < maxGSOSegments && len(bufs[j]) > 0 && len(bufs[j]) <= size && total+len(bufs[j]) <= maxPayload {
			total += len(bufs[j])
			j++
			if len(bufs[j-1]) < size {
				break
			}
		}
		m := &msgs[n]
		m.Buffers = bufs[i:j]
		m.Addr = addr
		m.OOB = m.OOB[:0]
		if j-i > 1 {
			m.OOB = setGSOSize(m.OOB, size)
		}
		i = j
	}
	return n, i
}

func (b *bind) getMsgs() *bindMessages {
	if m, ok := b.msgsPool.Get().(*bindMessages); ok {
		return m
	}
	msgs := new(bindMessages)
	for i := range msgs.messages {
		msgs.messages[i].OOB = msgs.control[i][:0]
	}
	return msgs
}

func (b *bind) putMsgs(msgs *bindMessages) {
	for i := 0; i < msgs.used; i++ {
		msgs.messages[i].Buffers = nil
		msgs.messages[i].Addr = nil
	}
	msgs.used = 0
	b.msgsPool.Put(msgs)
}

func (b *bind) ParseEndpoint(s string) (conn.Endpoint, error) {
	if b.resolveFunc == nil {
		e, err := netip.ParseAddrPort(s)
		if err != nil {
			return nil, err
		}
		return &conn.StdNetEndpoint{
			AddrPort: e,
		}, nil
	}
	host, sport, err := net.SplitHostPort(s)
	if err != nil {
		return nil, err
	}
	port, err := strconv.Atoi(sport)
	if err != nil {
		return nil, err
	}
	if port < 0 || port > 65535 {
		return nil, errors.New("invalid port " + sport)
	}
	ip, err := b.resolveFunc(host)
	if err != nil {
		return nil, err
	}
	addr, _ := netip.AddrFromSlice(ip)
	return &conn.StdNetEndpoint{
		AddrPort: netip.AddrPortFrom(addr, uint16(port)),
	}, nil
}

func (b *bind) BatchSize() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.batchEnabled {
		return batchSize
	}
	return 1
}
