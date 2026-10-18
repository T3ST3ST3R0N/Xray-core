//go:build !linux

package wireguard

import (
	"net"
	"syscall"

	"golang.org/x/net/ipv6"
)

// Without recvmmsg/sendmmsg x/net would send and receive one datagram per
// syscall anyway, so the bind keeps its plain path.
const batchSize = 1

const gsoControlSize = 0

func newBatchConn(*net.UDPConn) (batchConn, bool) {
	return nil, false
}

func setGSOSize(oob []byte, _ int) []byte {
	return oob
}

func gsoFailed(error) bool {
	return false
}

type bindSendmsg struct{}

func writeBatch(bc batchConn, _ syscall.RawConn, _ *bindSendmsg, msgs []ipv6.Message) (int, error) {
	return bc.WriteBatch(msgs, 0)
}
