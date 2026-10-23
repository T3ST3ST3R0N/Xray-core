package scenarios

import (
	"fmt"
	"os"
	"os/exec"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/testing/servers/tcp"
	"github.com/xtls/xray-core/testing/servers/udp"
)

// TestSingUoTClient uses an official release that implements sing UoT (for
// example v26.3.27). The server is TCP-only: silently ignoring the client's uot
// option and falling back to native UDP must not make this test pass.
func TestSingUoTClient(t *testing.T) {
	clientBinary := os.Getenv("XRAY_UOT_CLIENT")
	if clientBinary == "" {
		t.Skip("XRAY_UOT_CLIENT is not set")
	}
	version, err := exec.Command(clientBinary, "version").Output()
	common.Must(err)
	t.Logf("UoT client: %s", version)
	for _, multi := range []bool{false, true} {
		for _, version := range []int{1, 2} {
			t.Run(fmt.Sprintf("multi=%v/version=%d", multi, version), func(t *testing.T) {
				echo := udp.Server{MsgProcessor: xor}
				dest, err := echo.Start()
				common.Must(err)
				defer echo.Close()
				serverPort := tcp.PickPort()
				serverKey, userKey := randomKey(), randomKey()
				settings := obj{"method": "2022-blake3-aes-128-gcm", "password": serverKey, "network": "tcp"}
				password := serverKey
				if multi {
					settings["clients"] = []obj{{"password": userKey, "email": "uot@example.invalid"}}
					password += ":" + userKey
				}
				serverConfig := obj{
					"log":      obj{"loglevel": "warning"},
					"inbounds": []obj{{"listen": "127.0.0.1", "port": serverPort, "protocol": "shadowsocks", "settings": settings}},
					"outbounds": []obj{
						{"tag": "block", "protocol": "blackhole"},
						{"tag": "echo", "protocol": "freedom", "settings": obj{"redirect": dest.NetAddr(), "finalRules": []obj{{"action": "allow"}}}},
					},
					"routing": obj{"rules": []obj{{"network": "udp", "outboundTag": "echo"}}},
				}
				var servers []*exec.Cmd
				if binary := os.Getenv("XRAY_SERVER"); binary != "" {
					servers = []*exec.Cmd{runJSON(binary, marshal(serverConfig))}
				} else {
					servers = startXrayJSON(t, marshal(serverConfig))
				}
				defer CloseAllServers(servers)
				waitForPort(t, serverPort)
				clientPort := pickTCPUDPPort(t)
				client := runJSON(clientBinary, marshal(obj{
					"log": obj{"loglevel": "warning"},
					"inbounds": []obj{{
						"listen": "127.0.0.1", "port": clientPort, "protocol": "dokodemo-door",
						"settings": obj{"address": "192.0.2.1", "port": 7, "network": "tcp,udp"},
					}},
					"outbounds": []obj{{"protocol": "shadowsocks", "settings": obj{"servers": []obj{{
						"address": "127.0.0.1", "port": serverPort, "method": "2022-blake3-aes-128-gcm",
						"password": password, "uot": true, "uotVersion": version,
					}}}}},
				}))
				defer CloseAllServers([]*exec.Cmd{client})
				waitForPort(t, clientPort)
				if err := testUDPConn(clientPort, 1024, 5*time.Second)(); err != nil {
					t.Fatal(err)
				}
			})
		}
	}
	// Decoding UoT must not bypass freedom's policy for the inner destination.
	// Use the same real client and loopback target for a denied/allowed pair.
	for _, allow := range []bool{false, true} {
		t.Run(fmt.Sprintf("private-destination/allow=%v", allow), func(t *testing.T) {
			var received atomic.Int32
			echo := udp.Server{MsgProcessor: func(data []byte) []byte {
				received.Add(1)
				return xor(data)
			}}
			dest, err := echo.Start()
			common.Must(err)
			defer echo.Close()
			serverPort := tcp.PickPort()
			serverKey, userKey := randomKey(), randomKey()
			freedom := obj{}
			if allow {
				freedom["finalRules"] = []obj{{"action": "allow", "network": "udp", "ip": []string{"127.0.0.1/32"}, "port": fmt.Sprint(dest.Port)}}
			}
			serverConfig := obj{
				"log": obj{"loglevel": "warning"},
				"inbounds": []obj{{"listen": "127.0.0.1", "port": serverPort, "protocol": "shadowsocks", "settings": obj{
					"method": "2022-blake3-aes-128-gcm", "password": serverKey, "network": "tcp",
					"clients": []obj{{"password": userKey, "email": "uot@example.invalid"}},
				}}},
				"outbounds": []obj{{"protocol": "freedom", "settings": freedom}},
			}
			var servers []*exec.Cmd
			if binary := os.Getenv("XRAY_SERVER"); binary != "" {
				servers = []*exec.Cmd{runJSON(binary, marshal(serverConfig))}
			} else {
				servers = startXrayJSON(t, marshal(serverConfig))
			}
			defer CloseAllServers(servers)
			waitForPort(t, serverPort)
			clientPort := pickTCPUDPPort(t)
			client := runJSON(clientBinary, marshal(obj{
				"log": obj{"loglevel": "warning"},
				"inbounds": []obj{{
					"listen": "127.0.0.1", "port": clientPort, "protocol": "dokodemo-door",
					"settings": obj{"address": "127.0.0.1", "port": dest.Port, "network": "tcp,udp"},
				}},
				"outbounds": []obj{{"protocol": "shadowsocks", "settings": obj{"servers": []obj{{
					"address": "127.0.0.1", "port": serverPort, "method": "2022-blake3-aes-128-gcm",
					"password": serverKey + ":" + userKey, "uot": true, "uotVersion": 2,
				}}}}},
			}))
			defer CloseAllServers([]*exec.Cmd{client})
			waitForPort(t, clientPort)
			err = testUDPConn(clientPort, 1024, time.Second)()
			if allow && (err != nil || received.Load() == 0) {
				t.Fatalf("explicitly allowed inner destination: received=%d err=%v", received.Load(), err)
			}
			if !allow && (err == nil || received.Load() != 0) {
				t.Fatalf("private inner destination bypassed freedom policy: received=%d err=%v", received.Load(), err)
			}
		})
	}
}
