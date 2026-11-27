//go:build unix

package reality

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/tls"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	utls "github.com/refraction-networking/utls"
	"github.com/xtls/reality"
	"github.com/xtls/xray-core/common"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol/tls/cert"
)

func TestREALITYKeyShares(t *testing.T) {
	for _, tc := range []struct {
		name        string
		fingerprint string
		group       utls.CurveID
		shortID     [8]byte
	}{
		{"classical", "hellochrome_106_shuffle", utls.X25519, [8]byte{1}},
		{"hybrid", "chrome", utls.X25519MLKEM768, [8]byte{1}},
		{"wrong short ID", "hellochrome_106_shuffle", 0, [8]byte{2}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			const serverName = "example.com"
			deadline := time.Now().Add(5 * time.Second)
			ctx, cancel := context.WithDeadline(t.Context(), deadline)
			defer cancel()

			// Unix socket paths have a small platform-specific length limit.
			socketDir := common.Must2(os.MkdirTemp("", "xray-"))
			t.Cleanup(func() { os.Remove(socketDir) })

			target := listenREALITYTestSocket(t, filepath.Join(socketDir, "target.sock"))
			testingCert, _ := cert.MustGenerate(nil, cert.CommonName(serverName), cert.DNSNames(serverName))
			certPEM, keyPEM := testingCert.ToPEM()
			pair := common.Must2(tls.X509KeyPair(certPEM, keyPEM))
			targetConfig := &tls.Config{
				Certificates:     []tls.Certificate{pair},
				CurvePreferences: []tls.CurveID{tls.X25519MLKEM768, tls.X25519},
				NextProtos:       []string{"h2", "http/1.1"},
			}
			go func() {
				conn, err := target.Accept()
				if err != nil {
					return
				}
				defer conn.Close()
				conn.SetDeadline(deadline)
				tls.Server(conn, targetConfig).HandshakeContext(ctx)
			}()

			privateKey := common.Must2(ecdh.X25519().GenerateKey(rand.Reader))
			serverConfig := (&Config{
				Type:        "unix",
				Dest:        target.Addr().String(),
				ServerNames: []string{serverName},
				PrivateKey:  privateKey.Bytes(),
				ShortIds:    [][]byte{{1, 0, 0, 0, 0, 0, 0, 0}},
			}).GetREALITYConfig()

			// The local target has no application data following its handshake.
			for _, alpn := range []string{"0", "1", "2"} {
				key := serverConfig.Dest + " " + serverName + " " + alpn
				reality.GlobalPostHandshakeRecordsLens.Store(key, []int{})
				t.Cleanup(func() { reality.GlobalPostHandshakeRecordsLens.Delete(key) })
			}

			listener := listenREALITYTestSocket(t, filepath.Join(socketDir, "reality.sock"))
			serverDone := make(chan error, 1)
			go func() {
				conn, err := listener.Accept()
				if err != nil {
					serverDone <- err
					return
				}
				defer conn.Close()
				conn.SetDeadline(deadline)
				_, err = Server(conn, serverConfig)
				serverDone <- err
			}()

			raw := common.Must2(net.Dial("unix", listener.Addr().String()))
			defer raw.Close()
			common.Must(raw.SetDeadline(deadline))
			client, clientErr := UClient(raw, &Config{
				Fingerprint: tc.fingerprint,
				ServerName:  serverName,
				PublicKey:   privateKey.PublicKey().Bytes(),
				ShortId:     tc.shortID[:],
				SpiderY:     make([]int64, 10),
			}, ctx, xnet.TCPDestination(xnet.DomainAddress(serverName), 443))

			if clientErr != nil {
				raw.Close()
			}
			var serverErr error
			select {
			case serverErr = <-serverDone:
			case <-ctx.Done():
				t.Fatalf("REALITY server did not finish: %v", ctx.Err())
			}
			if tc.group == 0 {
				if clientErr == nil || serverErr == nil {
					t.Fatalf("wrong short ID was accepted: client error %v, server error %v", clientErr, serverErr)
				}
				return
			}
			if clientErr != nil || serverErr != nil {
				t.Fatalf("REALITY handshake failed: client error %v, server error %v", clientErr, serverErr)
			}
			hello := client.(*UConn).HandshakeState.ServerHello
			if hello.ServerShare.Group != tc.group {
				t.Fatalf("negotiated group %v, want %v", hello.ServerShare.Group, tc.group)
			}
		})
	}
}

func listenREALITYTestSocket(t *testing.T, path string) net.Listener {
	t.Helper()
	listener := common.Must2(net.Listen("unix", path))
	t.Cleanup(func() { listener.Close() })
	return listener
}
