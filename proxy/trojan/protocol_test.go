package trojan_test

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	gonet "net"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/protocol/tls/cert"
	. "github.com/xtls/xray-core/proxy/trojan"
)

func toAccount(a *Account) protocol.Account {
	account, err := a.AsAccount()
	common.Must(err)
	return account
}

func TestTCPRequest(t *testing.T) {
	user := &protocol.MemoryUser{
		Email: "love@example.com",
		Account: toAccount(&Account{
			Password: "password",
		}),
	}
	payload := []byte("test string")
	data := buf.New()
	common.Must2(data.Write(payload))

	buffer := buf.New()
	defer buffer.Release()

	destination := net.Destination{Network: net.Network_TCP, Address: net.LocalHostIP, Port: 1234}
	writer := &ConnWriter{Writer: buffer, Target: destination, Account: user.Account.(*MemoryAccount)}
	common.Must(writer.WriteMultiBuffer(buf.MultiBuffer{data}))

	reader := &ConnReader{Reader: buffer}
	common.Must(reader.ParseHeader())

	if r := cmp.Diff(reader.Target, destination); r != "" {
		t.Error("destination: ", r)
	}

	decodedData, err := reader.ReadMultiBuffer()
	common.Must(err)
	if r := cmp.Diff(decodedData[0].Bytes(), payload); r != "" {
		t.Error("data: ", r)
	}
}

func TestUDPRequest(t *testing.T) {
	user := &protocol.MemoryUser{
		Email: "love@example.com",
		Account: toAccount(&Account{
			Password: "password",
		}),
	}
	payload := []byte("test string")
	data := buf.New()
	common.Must2(data.Write(payload))

	buffer := buf.New()
	defer buffer.Release()

	destination := net.Destination{Network: net.Network_UDP, Address: net.LocalHostIP, Port: 1234}
	writer := &PacketWriter{Writer: &ConnWriter{Writer: buffer, Target: destination, Account: user.Account.(*MemoryAccount)}, Target: destination}
	common.Must(writer.WriteMultiBuffer(buf.MultiBuffer{data}))

	connReader := &ConnReader{Reader: buffer}
	common.Must(connReader.ParseHeader())

	packetReader := &PacketReader{Reader: connReader}
	mb, err := packetReader.ReadMultiBuffer()
	common.Must(err)

	if mb.IsEmpty() {
		t.Error("no request data")
	}

	mb2, b := buf.SplitFirst(mb)
	defer buf.ReleaseMulti(mb2)

	dest := *b.UDP
	if r := cmp.Diff(dest, destination); r != "" {
		t.Error("destination: ", r)
	}

	if r := cmp.Diff(b.Bytes(), payload); r != "" {
		t.Error("data: ", r)
	}
}

func TestUDPFullPayloadAndErrors(t *testing.T) {
	for _, address := range []net.Address{net.LocalHostIP, net.LocalHostIPv6, net.DomainAddress(strings.Repeat("a", 255))} {
		dest := net.UDPDestination(address, 1234)
		t.Run(address.String(), func(t *testing.T) {
			var wire bytes.Buffer
			writer := &PacketWriter{Writer: &wire, Target: dest}
			payload := bytes.Repeat([]byte{0x6b}, 8192)
			for range 2 {
				b := buf.FromBytes(payload)
				if err := writer.WriteMultiBuffer(buf.MultiBuffer{b}); err != nil {
					t.Fatal(err)
				}
			}
			encoded := append([]byte(nil), wire.Bytes()...)
			reader := &PacketReader{Reader: &wire}
			for range 2 {
				mb, err := reader.ReadMultiBuffer()
				if err != nil {
					t.Fatal(err)
				}
				if len(mb) != 1 || !bytes.Equal(mb[0].Bytes(), payload) || *mb[0].UDP != dest {
					t.Fatal("full payload or destination changed")
				}
				buf.ReleaseMulti(mb)
			}
			for _, length := range []int{0, 1, len(encoded)/2 - 1} {
				mb, err := (&PacketReader{Reader: bytes.NewReader(encoded[:length])}).ReadMultiBuffer()
				buf.ReleaseMulti(mb)
				if err == nil {
					t.Fatal("truncated frame accepted")
				}
			}
			if err := writer.WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes(make([]byte, 8193))}); err == nil {
				t.Fatal("oversize payload accepted")
			}
		})
	}
	dest := net.UDPDestination(net.LocalHostIP, 1234)
	for _, out := range []io.Writer{shortPacketWriter{}, failingPacketWriter{}} {
		err := (&PacketWriter{Writer: out, Target: dest}).WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes([]byte("payload"))})
		if err == nil {
			t.Fatal("write failure hidden")
		}
		if _, ok := out.(shortPacketWriter); ok && !errors.Is(err, io.ErrShortWrite) {
			t.Fatalf("short write: %v", err)
		}
	}
}

type shortPacketWriter struct{}

func (shortPacketWriter) Write(p []byte) (int, error) { return len(p) - 1, nil }

type failingPacketWriter struct{}

func (failingPacketWriter) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }

func TestUDPFramesOverTLSLoopback(t *testing.T) {
	ct, err := cert.Generate(nil, cert.DNSNames("localhost"))
	if err != nil {
		t.Fatal(err)
	}
	certPEM, keyPEM := ct.ToPEM()
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(certPEM)
	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS13})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	dest := net.UDPDestination(net.DomainAddress("example.com"), 1234)
	payload := bytes.Repeat([]byte{0x8c}, 8192)
	serverResult := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			serverResult <- err
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		reader := &ConnReader{Reader: conn}
		if err := reader.ParseHeader(); err != nil {
			serverResult <- err
			return
		}
		if reader.Target != dest {
			serverResult <- errors.New("TLS handshake destination changed")
			return
		}
		mb, err := (&PacketReader{Reader: reader}).ReadMultiBuffer()
		if err != nil {
			serverResult <- err
			return
		}
		if len(mb) != 1 || !bytes.Equal(mb[0].Bytes(), payload) || *mb[0].UDP != dest {
			buf.ReleaseMulti(mb)
			serverResult <- errors.New("TLS packet changed")
			return
		}
		serverResult <- (&PacketWriter{Writer: conn}).WriteMultiBuffer(mb)
	}()
	dialer := &gonet.Dialer{Timeout: 5 * time.Second}
	conn, err := tls.DialWithDialer(dialer, "tcp", listener.Addr().String(), &tls.Config{RootCAs: roots, ServerName: "localhost", MinVersion: tls.VersionTLS13})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	account := toAccount(&Account{Password: "tls password"}).(*MemoryAccount)
	writer := &PacketWriter{Writer: &ConnWriter{Writer: conn, Target: dest, Account: account}, Target: dest}
	if err := writer.WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes(payload)}); err != nil {
		t.Fatal(err)
	}
	mb, err := (&PacketReader{Reader: conn}).ReadMultiBuffer()
	if err != nil {
		t.Fatal(err)
	}
	defer buf.ReleaseMulti(mb)
	if len(mb) != 1 || !bytes.Equal(mb[0].Bytes(), payload) || *mb[0].UDP != dest {
		t.Fatal("TLS reply changed")
	}
	if err := <-serverResult; err != nil {
		t.Fatal(err)
	}
}
