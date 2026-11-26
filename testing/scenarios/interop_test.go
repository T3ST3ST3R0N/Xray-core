package scenarios

import (
	"crypto/rand"
	gotls "crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol/tls/cert"
	"github.com/xtls/xray-core/testing/servers/tcp"
	"github.com/xtls/xray-core/testing/servers/udp"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/sync/errgroup"
)

type obj = map[string]any

// TestUpstreamClient connects an official Xray release, the binary at
// XRAY_UPSTREAM, as the client to this build as the server. Configs are JSON,
// so that older releases read them the way their users' configs are read.
// XRAY_SERVER, if set, runs that binary as the server instead, e.g. the
// official release this build is based on, to tell our failures from upstream's.
func TestUpstreamClient(t *testing.T) {
	upstream := os.Getenv("XRAY_UPSTREAM")
	if upstream == "" {
		t.Skip("XRAY_UPSTREAM is not set")
	}
	version, err := exec.Command(upstream, "version").Output()
	common.Must(err)
	t.Log(strings.SplitN(string(version), "\n", 2)[0])

	tcpServer := tcp.Server{MsgProcessor: xor}
	tcpDest, err := tcpServer.Start()
	common.Must(err)
	defer tcpServer.Close()
	udpServer := udp.Server{MsgProcessor: xor}
	udpDest, err := udpServer.Start()
	common.Must(err)
	defer udpServer.Close()

	ct, _ := cert.MustGenerate(nil, cert.CommonName("example.com"), cert.DNSNames("example.com"))
	certPEM, keyPEM := ct.ToPEM()
	certLines := strings.Split(strings.TrimSpace(string(certPEM)), "\n")
	keyLines := strings.Split(strings.TrimSpace(string(keyPEM)), "\n")
	realityTarget := startTLSServer(t, certPEM, keyPEM)

	id := uuid.New().String()
	realityPrivate, realityPublic := x25519Keys(base64.RawURLEncoding)
	wgServerPrivate, wgServerPublic := x25519Keys(base64.StdEncoding)
	wgClientPrivate, wgClientPublic := x25519Keys(base64.StdEncoding)
	ssServerKey, ssUserKey := randomKey(), randomKey()

	serverTLS := obj{"certificates": []obj{{"certificate": certLines, "key": keyLines}}}
	clientTLS := obj{"serverName": "example.com", "certificates": []obj{{"usage": "verify", "certificate": certLines}}}
	stream := func(network, security string, settings obj) obj {
		s := obj{"network": network}
		switch network {
		case "ws":
			s["wsSettings"] = obj{"path": "/ws"}
		case "grpc":
			s["grpcSettings"] = obj{"serviceName": "g"}
		case "xhttp":
			s["xhttpSettings"] = obj{"path": "/x"}
		}
		if security != "" {
			s["security"] = security
			s[security+"Settings"] = settings
		}
		return s
	}
	vnext := func(protocol string, port net.Port, user obj) obj {
		return obj{"protocol": protocol, "settings": obj{"vnext": []obj{{"address": "127.0.0.1", "port": port, "users": []obj{user}}}}}
	}
	server := func(port net.Port) obj { return obj{"servers": []obj{{"address": "127.0.0.1", "port": port}}} }
	with := func(o obj, kv ...any) obj {
		for i := 0; i < len(kv); i += 2 {
			o[kv[i].(string)] = kv[i+1]
		}
		return o
	}

	cases := []struct {
		name   string
		udp    bool // the server listens on UDP
		server func(port net.Port) obj
		client func(port net.Port) obj
	}{
		{name: "VLESS", server: func(port net.Port) obj {
			return obj{"protocol": "vless", "settings": obj{"clients": []obj{{"id": id}}, "decryption": "none"}}
		}, client: func(port net.Port) obj {
			return vnext("vless", port, obj{"id": id, "encryption": "none"})
		}},
		{name: "VLESSVisionTLS", server: func(port net.Port) obj {
			return obj{
				"protocol": "vless", "settings": obj{"clients": []obj{{"id": id, "flow": "xtls-rprx-vision"}}, "decryption": "none"},
				"streamSettings": stream("raw", "tls", serverTLS),
			}
		}, client: func(port net.Port) obj {
			return with(vnext("vless", port, obj{"id": id, "encryption": "none", "flow": "xtls-rprx-vision"}), "streamSettings", stream("raw", "tls", clientTLS))
		}},
		{name: "VLESSVisionREALITY", server: func(port net.Port) obj {
			return obj{
				"protocol": "vless", "settings": obj{"clients": []obj{{"id": id, "flow": "xtls-rprx-vision"}}, "decryption": "none"},
				"streamSettings": stream("raw", "reality", obj{"target": realityTarget, "serverNames": []string{"example.com"}, "privateKey": realityPrivate, "shortIds": []string{"0123abcd"}}),
			}
		}, client: func(port net.Port) obj {
			return with(vnext("vless", port, obj{"id": id, "encryption": "none", "flow": "xtls-rprx-vision"}),
				"streamSettings", stream("raw", "reality", obj{"serverName": "example.com", "password": realityPublic, "shortId": "0123abcd", "fingerprint": "chrome"}))
		}},
		{name: "VLESSWebSocketTLS", server: func(port net.Port) obj {
			return obj{"protocol": "vless", "settings": obj{"clients": []obj{{"id": id}}, "decryption": "none"}, "streamSettings": stream("ws", "tls", serverTLS)}
		}, client: func(port net.Port) obj {
			return with(vnext("vless", port, obj{"id": id, "encryption": "none"}), "streamSettings", stream("ws", "tls", clientTLS))
		}},
		{name: "VLESSgRPCTLS", server: func(port net.Port) obj {
			return obj{"protocol": "vless", "settings": obj{"clients": []obj{{"id": id}}, "decryption": "none"}, "streamSettings": stream("grpc", "tls", serverTLS)}
		}, client: func(port net.Port) obj {
			return with(vnext("vless", port, obj{"id": id, "encryption": "none"}), "streamSettings", stream("grpc", "tls", clientTLS))
		}},
		{name: "VLESSXHTTPTLS", server: func(port net.Port) obj {
			return obj{"protocol": "vless", "settings": obj{"clients": []obj{{"id": id}}, "decryption": "none"}, "streamSettings": stream("xhttp", "tls", serverTLS)}
		}, client: func(port net.Port) obj {
			return with(vnext("vless", port, obj{"id": id, "encryption": "none"}), "streamSettings", stream("xhttp", "tls", clientTLS))
		}},
		{name: "VMess", server: func(port net.Port) obj {
			return obj{"protocol": "vmess", "settings": obj{"clients": []obj{{"id": id}}}}
		}, client: func(port net.Port) obj {
			return vnext("vmess", port, obj{"id": id, "security": "aes-128-gcm"})
		}},
		{name: "VMessWebSocketMux", server: func(port net.Port) obj {
			return obj{"protocol": "vmess", "settings": obj{"clients": []obj{{"id": id}}}, "streamSettings": stream("ws", "", nil)}
		}, client: func(port net.Port) obj {
			outbound := vnext("vmess", port, obj{"id": id, "security": "chacha20-poly1305"})
			outbound["settings"].(obj)["multiplex"] = obj{"concurrency": 8}
			return with(outbound, "streamSettings", stream("ws", "", nil),
				"mux", obj{"enabled": true, "concurrency": 8})
		}},
		{name: "TrojanTLS", server: func(port net.Port) obj {
			return obj{"protocol": "trojan", "settings": obj{"clients": []obj{{"password": id}}}, "streamSettings": stream("raw", "tls", serverTLS)}
		}, client: func(port net.Port) obj {
			s := server(port)
			s["servers"].([]obj)[0]["password"] = id
			return obj{"protocol": "trojan", "settings": s, "streamSettings": stream("raw", "tls", clientTLS)}
		}},
		{name: "Shadowsocks", server: func(port net.Port) obj {
			return obj{"protocol": "shadowsocks", "settings": obj{"method": "aes-128-gcm", "password": id, "network": "tcp,udp"}}
		}, client: func(port net.Port) obj {
			s := server(port)
			with(s["servers"].([]obj)[0], "method", "aes-128-gcm", "password", id)
			return obj{"protocol": "shadowsocks", "settings": s}
		}},
		{name: "Shadowsocks2022", server: func(port net.Port) obj {
			return obj{"protocol": "shadowsocks", "settings": obj{"method": "2022-blake3-aes-128-gcm", "password": ssServerKey, "network": "tcp,udp"}}
		}, client: func(port net.Port) obj {
			s := server(port)
			with(s["servers"].([]obj)[0], "method", "2022-blake3-aes-128-gcm", "password", ssServerKey)
			return obj{"protocol": "shadowsocks", "settings": s}
		}},
		{name: "Shadowsocks2022MultiUser", server: func(port net.Port) obj {
			return obj{"protocol": "shadowsocks", "settings": obj{
				"method": "2022-blake3-aes-128-gcm", "password": ssServerKey,
				"clients": []obj{{"password": ssUserKey, "email": "user@example.com"}}, "network": "tcp,udp",
			}}
		}, client: func(port net.Port) obj {
			s := server(port)
			with(s["servers"].([]obj)[0], "method", "2022-blake3-aes-128-gcm", "password", ssServerKey+":"+ssUserKey)
			return obj{"protocol": "shadowsocks", "settings": s}
		}},
		{name: "Shadowsocks2022MultiUserXUDP", server: func(port net.Port) obj {
			return obj{"protocol": "shadowsocks", "settings": obj{
				"method": "2022-blake3-aes-128-gcm", "password": ssServerKey,
				"clients": []obj{{"password": ssUserKey, "email": "user@example.com"}}, "network": "tcp,udp",
			}}
		}, client: func(port net.Port) obj {
			s := server(port)
			with(s["servers"].([]obj)[0], "method", "2022-blake3-aes-128-gcm", "password", ssServerKey+":"+ssUserKey)
			return obj{
				"protocol": "shadowsocks", "settings": s,
				"mux": obj{"enabled": true, "concurrency": -1, "xudpConcurrency": 8, "xudpProxyUDP443": "allow"},
			}
		}},
		{name: "Hysteria2", udp: true, server: func(port net.Port) obj {
			return obj{
				"protocol": "hysteria", "settings": obj{"version": 2, "clients": []obj{{"auth": id}}},
				"streamSettings": with(stream("hysteria", "tls", with(obj{"alpn": []string{"h3"}}, "certificates", serverTLS["certificates"])),
					"hysteriaSettings", obj{"version": 2}),
			}
		}, client: func(port net.Port) obj {
			return obj{
				"protocol": "hysteria", "settings": obj{"version": 2, "address": "127.0.0.1", "port": port},
				"streamSettings": with(stream("hysteria", "tls", with(obj{"alpn": []string{"h3"}}, "serverName", "example.com", "certificates", clientTLS["certificates"])),
					"hysteriaSettings", obj{"version": 2, "auth": id}),
			}
		}},
		{name: "WireGuard", udp: true, server: func(port net.Port) obj {
			return obj{"protocol": "wireguard", "settings": obj{
				"secretKey": wgServerPrivate, "address": []string{"10.0.0.1"},
				"peers": []obj{{"publicKey": wgClientPublic, "allowedIPs": []string{"10.0.0.2/32"}}},
			}}
		}, client: func(port net.Port) obj {
			return obj{"protocol": "wireguard", "settings": obj{
				"secretKey": wgClientPrivate, "address": []string{"10.0.0.2/32"}, "noKernelTun": true,
				"peers": []obj{{"publicKey": wgServerPublic, "endpoint": fmt.Sprintf("127.0.0.1:%d", port), "allowedIPs": []string{"0.0.0.0/0"}}},
			}}
		}},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if c.name == "Hysteria2" && strings.HasPrefix(string(version), "Xray 25.12.8 ") {
				t.Skip("official v25.12.8 does not implement the Hysteria transport")
			}
			serverPort := pickTCPUDPPort(t)
			if c.udp {
				serverPort = udp.PickPort()
			}
			inbound := with(c.server(serverPort), "listen", "127.0.0.1", "port", serverPort)
			// The client asks for a test address; the server sends it to the echo servers.
			redirect := func(tag string, dest net.Destination) obj {
				return obj{"tag": tag, "protocol": "freedom", "settings": obj{"redirect": dest.NetAddr(), "finalRules": []obj{{"action": "allow"}}}}
			}
			serverConfig := obj{
				"log":       obj{"loglevel": "warning"},
				"inbounds":  []obj{inbound},
				"outbounds": []obj{redirect("tcp", tcpDest), redirect("udp", udpDest)},
				"routing": obj{"rules": []obj{
					{"network": "tcp", "outboundTag": "tcp"},
					{"network": "udp", "outboundTag": "udp"},
				}},
			}
			clientTCPPort, clientUDPPort := tcp.PickPort(), udp.PickPort()
			dokodemo := func(port net.Port, network string) obj {
				return obj{
					"listen": "127.0.0.1", "port": port, "protocol": "dokodemo-door",
					"settings": obj{"address": "192.0.2.1", "port": 7, "network": network},
				}
			}
			clientConfig := obj{
				"log":       obj{"loglevel": "warning"},
				"inbounds":  []obj{dokodemo(clientTCPPort, "tcp"), dokodemo(clientUDPPort, "udp")},
				"outbounds": []obj{c.client(serverPort)},
			}

			var servers []*exec.Cmd
			if bin := os.Getenv("XRAY_SERVER"); bin != "" {
				servers = []*exec.Cmd{runJSON(bin, marshal(serverConfig))}
				time.Sleep(2 * time.Second)
			} else {
				servers = startXrayJSON(t, marshal(serverConfig))
			}
			defer CloseAllServers(servers)
			client := runJSON(upstream, marshal(clientConfig))
			defer CloseAllServers([]*exec.Cmd{client})
			waitForPort(t, clientTCPPort)

			var errg errgroup.Group
			for range 2 {
				errg.Go(testTCPConn(clientTCPPort, 64*1024, 10*time.Second))
			}
			errg.Go(testUDPConn(clientUDPPort, 1024, 10*time.Second))
			if err := errg.Wait(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

// runJSON starts an Xray binary other than this build with a JSON config.
func runJSON(bin, config string) *exec.Cmd {
	cmd := exec.Command(bin, "run", "-config=stdin:", "-format=json")
	cmd.Stdin = strings.NewReader(config)
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	common.Must(cmd.Start())
	return cmd
}

func marshal(v any) string {
	b, err := json.Marshal(v)
	common.Must(err)
	return string(b)
}

func randomKey() string {
	var k [16]byte
	common.Must2(rand.Read(k[:]))
	return base64.StdEncoding.EncodeToString(k[:])
}

func x25519Keys(enc *base64.Encoding) (private, public string) {
	var k [32]byte
	common.Must2(rand.Read(k[:]))
	k[0] &= 248
	k[31] = k[31]&127 | 64
	p, err := curve25519.X25519(k[:], curve25519.Basepoint)
	common.Must(err)
	return enc.EncodeToString(k[:]), enc.EncodeToString(p)
}

// startTLSServer is the site REALITY borrows: it completes TLS 1.3 handshakes
// and returns its address.
func startTLSServer(t *testing.T, certPEM, keyPEM []byte) string {
	pair, err := gotls.X509KeyPair(certPEM, keyPEM)
	common.Must(err)
	l, err := gotls.Listen("tcp", "127.0.0.1:0", &gotls.Config{Certificates: []gotls.Certificate{pair}, NextProtos: []string{"h2", "http/1.1"}})
	common.Must(err)
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(10 * time.Second))
				_ = conn.(*gotls.Conn).Handshake()
				var b [1]byte
				_, _ = conn.Read(b[:])
			}()
		}
	}()
	return l.Addr().String()
}

func waitForPort(t *testing.T, port net.Port) {
	t.Helper()
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); time.Sleep(100 * time.Millisecond) {
		if conn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port)); err == nil {
			conn.Close()
			return
		}
	}
	t.Fatalf("the client did not listen on %d", port)
}
