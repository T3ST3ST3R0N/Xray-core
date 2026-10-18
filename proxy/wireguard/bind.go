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

	net.PacketConn
	// batch is set when the conn is a plain UDP socket on Linux. The traffic
	// counters are then applied here, since PacketCounterConnection is bypassed.
	batch        batchConn
	gso          bool // batch takes UDP_SEGMENT
	readCounter  stats.Counter
	writeCounter stats.Counter
	msgsPool     sync.Pool
	closeCh      chan struct{}
	mu           sync.Mutex
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
	b.batch, b.gso, b.readCounter, b.writeCounter = newBatchConn(c)
	ch := make(chan struct{})
	b.closeCh = ch

	recv := b.makeReceive(c, ch)
	if b.batch != nil {
		recv = b.makeReceiveBatch(b.batch, ch)
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

func (b *bind) makeReceive(c net.PacketConn, ch chan struct{}) conn.ReceiveFunc {
	return func(bufs [][]byte, sizes []int, eps []conn.Endpoint) (n int, err error) {
		for {
			n, addr, err := c.ReadFrom(bufs[0])
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
			eps[0] = &conn.StdNetEndpoint{AddrPort: addr.(*net.UDPAddr).AddrPort()}
			return 1, nil
		}
	}
}

// makeReceiveBatch reads up to len(bufs) datagrams per call. wireguard-go calls
// each ReceiveFunc from a single goroutine, so msgs is not shared.
func (b *bind) makeReceiveBatch(bc batchConn, ch chan struct{}) conn.ReceiveFunc {
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
			if b.readCounter != nil {
				b.readCounter.Add(total)
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
	}
	return nil
}

func (b *bind) SetMark(mark uint32) error {
	return nil
}

func (b *bind) Send(bufs [][]byte, ep conn.Endpoint) error {
	b.mu.Lock()
	c, bc, gso, wc := b.PacketConn, b.batch, b.gso, b.writeCounter
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
	addr := net.UDPAddrFromAddrPort(ep.(*conn.StdNetEndpoint).AddrPort)

	if bc == nil {
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
	sent, err := sendBatch(bc, *msgs, bufs, addr, gso)
	if err != nil && gso && gsoFailed(err) {
		// The route does not take UDP_SEGMENT, e.g. no checksum offload or a
		// path MTU below the datagram size. Send the rest one by one from now on.
		errors.LogInfoInner(context.Background(), err, "bind: UDP GSO disabled")
		b.mu.Lock()
		if b.batch == bc {
			b.gso = false
		}
		b.mu.Unlock()
		var more int
		more, err = sendBatch(bc, *msgs, bufs[sent:], addr, false)
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

// sendBatch sends bufs to addr and returns how many of them went out before
// an error.
func sendBatch(bc batchConn, msgs []ipv6.Message, bufs [][]byte, addr *net.UDPAddr, gso bool) (int, error) {
	sent := 0
	for sent < len(bufs) {
		n, count := packMsgs(msgs, bufs[sent:], addr, gso)
		for i := 0; i < n; {
			k, err := bc.WriteBatch(msgs[i:n], 0)
			if err != nil {
				for _, m := range msgs[:i] {
					sent += len(m.Buffers)
				}
				return sent, err
			}
			i += k
		}
		sent += count
	}
	return sent, nil
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
		for gso && j < len(bufs) && j-i < maxGSOSegments && len(bufs[j]) <= size && total+len(bufs[j]) <= maxPayload {
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

func (b *bind) getMsgs() *[]ipv6.Message {
	if m, ok := b.msgsPool.Get().(*[]ipv6.Message); ok {
		return m
	}
	msgs := make([]ipv6.Message, conn.IdealBatchSize)
	for i := range msgs {
		msgs[i].OOB = make([]byte, 0, gsoControlSize)
	}
	return &msgs
}

func (b *bind) putMsgs(msgs *[]ipv6.Message) {
	for i := range *msgs {
		(*msgs)[i].Buffers = nil
		(*msgs)[i].Addr = nil
	}
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
	return batchSize
}
