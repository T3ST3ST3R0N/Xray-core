package scenarios

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	gorillaws "github.com/gorilla/websocket"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/protocol/tls/cert"
	xraytls "github.com/xtls/xray-core/transport/internet/tls"
	xrayws "github.com/xtls/xray-core/transport/internet/websocket"
)

// Exercise the public writers over real TLS records and WebSocket messages.
// These contracts also apply without PR #4. To cover #4's optimized writer
// paths, compose that independent implementation separately and run:
// go test ./testing/scenarios -run '^TestTransportWriter' -count=1
// No PR #4 production implementation is included with these regression tests.
func transportWriterPair(t *testing.T, transport string) (buf.Writer, func([]string) error, func()) {
	t.Helper()
	if transport == "TLS" {
		generated, err := cert.Generate(nil, cert.DNSNames("localhost"))
		if err != nil {
			t.Fatal(err)
		}
		pemCert, pemKey := generated.ToPEM()
		key, err := tls.X509KeyPair(pemCert, pemKey)
		if err != nil {
			t.Fatal(err)
		}
		roots := x509.NewCertPool()
		if !roots.AppendCertsFromPEM(pemCert) {
			t.Fatal("certificate pool")
		}
		clientRaw, serverRaw := net.Pipe()
		clientRaw.SetDeadline(time.Now().Add(5 * time.Second))
		serverRaw.SetDeadline(time.Now().Add(5 * time.Second))
		t.Cleanup(func() { clientRaw.Close(); serverRaw.Close() })
		server := tls.Server(serverRaw, &tls.Config{Certificates: []tls.Certificate{key}})
		ready := make(chan error, 1)
		go func() { ready <- server.Handshake() }()
		client := xraytls.Client(clientRaw, &tls.Config{RootCAs: roots, ServerName: "localhost"}).(*xraytls.Conn)
		if err := client.Handshake(); err != nil {
			t.Fatal(err)
		}
		if err := <-ready; err != nil {
			t.Fatal(err)
		}
		return client, func(want []string) error {
			data := []byte(strings.Join(want, ""))
			got := make([]byte, len(data))
			if _, err := io.ReadFull(server, got); err != nil {
				return err
			}
			if !bytes.Equal(got, data) {
				return io.ErrUnexpectedEOF
			}
			return nil
		}, func() { clientRaw.Close() }
	}

	accepted := make(chan *gorillaws.Conn, 1)
	upgrader := gorillaws.Upgrader{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err == nil {
			accepted <- conn
		}
	}))
	t.Cleanup(server.Close)
	client, _, err := gorillaws.DefaultDialer.Dial("ws"+strings.TrimPrefix(server.URL, "http"), nil)
	if err != nil {
		t.Fatal(err)
	}
	peer := <-accepted
	t.Cleanup(func() { client.Close(); peer.Close() })
	client.SetWriteDeadline(time.Now().Add(5 * time.Second))
	peer.SetReadDeadline(time.Now().Add(5 * time.Second))
	return xrayws.NewConnection(client, client.RemoteAddr(), nil, 0), func(want []string) error {
		// WriteMultiBuffer preserves bytes, not a particular message grouping.
		expected := strings.Join(want, "")
		var received []byte
		for len(received) < len(expected) {
			kind, got, err := peer.ReadMessage()
			if err != nil {
				return err
			}
			if kind != gorillaws.BinaryMessage {
				return io.ErrUnexpectedEOF
			}
			received = append(received, got...)
		}
		if string(received) != expected {
			return io.ErrUnexpectedEOF
		}
		return nil
	}, func() { client.Close() }
}

func TestTransportWriterPayloadAndOwnership(t *testing.T) {
	for _, transport := range []string{"TLS", "WebSocket"} {
		for _, tc := range []struct {
			name  string
			parts []string
		}{
			{"nil", nil},
			{"singleton_empty", []string{""}},
			{"singleton", []string{"hello"}},
			{"multiple", []string{"ab", "cd"}},
			{"full_buffer_and_tail", []string{strings.Repeat("a", buf.Size), "tail"}},
		} {
			t.Run(transport+"/"+tc.name, func(t *testing.T) {
				writer, receive, _ := transportWriterPair(t, transport)
				var mb buf.MultiBuffer
				for _, part := range tc.parts {
					b := buf.New()
					if _, err := b.WriteString(part); err != nil {
						t.Fatal(err)
					}
					mb = append(mb, b)
				}
				owned := append(buf.MultiBuffer(nil), mb...)
				defer buf.ReleaseMulti(owned)
				// A following payload also exercises empty inputs without pinning framing.
				want := append(append([]string(nil), tc.parts...), "sentinel")
				received := make(chan error, 1)
				go func() { received <- receive(want) }()
				if err := writer.WriteMultiBuffer(mb); err != nil {
					t.Fatal(err)
				}
				for _, b := range owned {
					if b.Bytes() != nil {
						t.Fatal("writer retained an owned payload buffer")
					}
				}
				last := buf.New()
				last.WriteString("sentinel")
				if err := writer.WriteMultiBuffer(buf.MultiBuffer{last}); err != nil {
					t.Fatal(err)
				}
				if err := <-received; err != nil {
					t.Fatal("payload or framing mismatch:", err)
				}
			})
		}
	}
}

func TestTransportWriterErrorReleasesBuffers(t *testing.T) {
	for _, transport := range []string{"TLS", "WebSocket"} {
		for _, count := range []int{1, 2} {
			t.Run(transport+strings.Repeat("/buffer", count), func(t *testing.T) {
				writer, _, stop := transportWriterPair(t, transport)
				stop()
				mb := make(buf.MultiBuffer, count)
				for i := range mb {
					mb[i] = buf.New()
					mb[i].Extend(buf.Size)
				}
				owned := append(buf.MultiBuffer(nil), mb...)
				defer buf.ReleaseMulti(owned)
				if err := writer.WriteMultiBuffer(mb); err == nil {
					t.Fatal("closed writer accepted payload")
				}
				for _, b := range owned {
					if b.Bytes() != nil {
						t.Fatal("write error retained an owned payload buffer")
					}
				}
			})
		}
	}
}
