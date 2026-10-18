//go:build linux

package wireguard

import (
	"encoding/binary"
	goerrors "errors"
	"net"
	"os"
	"syscall"
	"unsafe"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/conn"
)

const batchSize = conn.IdealBatchSize

var gsoControlSize = unix.CmsgSpace(2)

// newBatchConn batches only native UDP sockets on Linux. Callers must opt in
// before creating the WireGuard device, whose pool sizes cannot grow later.
func newBatchConn(udp *net.UDPConn) (batchConn, bool) {
	if udp == nil {
		return nil, false
	}
	setSocketBuffers(udp)
	gso := supportsGSO(udp)
	if la, ok := udp.LocalAddr().(*net.UDPAddr); ok && la.IP.To4() != nil {
		return ipv4.NewPacketConn(udp), gso
	}
	return ipv6.NewPacketConn(udp), gso
}

// setSocketBuffers preserves the native bind's existing 7 MiB target, subject
// to the system limits. Never require CAP_NET_ADMIN to bypass those limits.
func setSocketBuffers(c *net.UDPConn) {
	_ = c.SetReadBuffer(socketBufferSize)
	_ = c.SetWriteBuffer(socketBufferSize)
}

// supportsGSO reports whether the kernel takes UDP_SEGMENT on c (Linux 4.18+).
func supportsGSO(c *net.UDPConn) bool {
	rc, err := c.SyscallConn()
	if err != nil {
		return false
	}
	var gso bool
	_ = rc.Control(func(fd uintptr) {
		_, err := unix.GetsockoptInt(int(fd), unix.IPPROTO_UDP, unix.UDP_SEGMENT)
		gso = err == nil
	})
	return gso
}

// Keep the GSO sendmsg iovecs in the pooled metadata; SendmsgBuffers would
// allocate an iovec slice for runs longer than two datagrams.
type bindSendmsg struct {
	iov   [maxGSOSegments]unix.Iovec
	hdr   unix.Msghdr
	addr4 unix.RawSockaddrInet4
	addr6 unix.RawSockaddrInet6
	write func(uintptr) bool
	err   error
}

func (m *bindSendmsg) send(fd uintptr) bool {
	for {
		_, _, errno := unix.Syscall(unix.SYS_SENDMSG, fd, uintptr(unsafe.Pointer(&m.hdr)), 0)
		if errno == unix.EINTR {
			continue
		}
		if errno == unix.EAGAIN || errno == unix.EWOULDBLOCK {
			return false // RawConn.Write waits for writability and honors deadlines.
		}
		if errno != 0 {
			m.err = os.NewSyscallError("sendmsg", errno)
		}
		return true
	}
}

func writeBatch(bc batchConn, raw syscall.RawConn, send *bindSendmsg, msgs []ipv6.Message) (int, error) {
	if len(msgs) != 1 || len(msgs[0].OOB) == 0 || raw == nil {
		return bc.WriteBatch(msgs, 0)
	}
	message := &msgs[0]
	addr := message.Addr.(*net.UDPAddr)
	if addr.Zone != "" {
		return bc.WriteBatch(msgs, 0)
	}
	send.err = nil
	send.hdr = unix.Msghdr{}
	if ip := addr.IP.To4(); ip != nil {
		send.addr4 = unix.RawSockaddrInet4{Family: unix.AF_INET}
		binary.BigEndian.PutUint16((*[2]byte)(unsafe.Pointer(&send.addr4.Port))[:], uint16(addr.Port))
		copy(send.addr4.Addr[:], ip)
		send.hdr.Name = (*byte)(unsafe.Pointer(&send.addr4))
		send.hdr.Namelen = unix.SizeofSockaddrInet4
	} else {
		send.addr6 = unix.RawSockaddrInet6{Family: unix.AF_INET6}
		binary.BigEndian.PutUint16((*[2]byte)(unsafe.Pointer(&send.addr6.Port))[:], uint16(addr.Port))
		copy(send.addr6.Addr[:], addr.IP)
		send.hdr.Name = (*byte)(unsafe.Pointer(&send.addr6))
		send.hdr.Namelen = unix.SizeofSockaddrInet6
	}
	for i, buf := range message.Buffers {
		send.iov[i].Base = &buf[0] // GSO groups contain only nonempty datagrams.
		send.iov[i].SetLen(len(buf))
	}
	send.hdr.Iov = &send.iov[0]
	send.hdr.SetIovlen(len(message.Buffers))
	send.hdr.Control = &message.OOB[0]
	send.hdr.SetControllen(len(message.OOB))
	if send.write == nil {
		send.write = send.send
	}
	err := raw.Write(send.write)
	clear(send.iov[:len(message.Buffers)])
	send.hdr = unix.Msghdr{}
	if err != nil {
		return 0, err
	}
	if send.err != nil {
		return 0, send.err
	}
	return 1, nil
}

// setGSOSize returns oob[:0] holding a UDP_SEGMENT control message.
func setGSOSize(oob []byte, size int) []byte {
	if cap(oob) < gsoControlSize {
		oob = make([]byte, gsoControlSize)
	}
	oob = oob[:gsoControlSize]
	h := (*unix.Cmsghdr)(unsafe.Pointer(&oob[0]))
	h.Level = unix.SOL_UDP
	h.Type = unix.UDP_SEGMENT
	h.SetLen(unix.CmsgLen(2))
	binary.NativeEndian.PutUint16(oob[unix.CmsgLen(0):], uint16(size))
	return oob
}

// gsoFailed reports whether a send failed because the route cannot take
// UDP_SEGMENT: EIO without checksum offload, EMSGSIZE (EINVAL on older
// kernels) when a segment is larger than the path MTU, where a plain send
// would be fragmented.
func gsoFailed(err error) bool {
	return goerrors.Is(err, unix.EIO) || goerrors.Is(err, unix.EMSGSIZE) ||
		goerrors.Is(err, unix.EINVAL) || goerrors.Is(err, unix.ENOPROTOOPT) ||
		goerrors.Is(err, unix.EOPNOTSUPP)
}
