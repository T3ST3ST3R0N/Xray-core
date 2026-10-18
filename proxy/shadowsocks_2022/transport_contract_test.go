package shadowsocks_2022_test

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	gonet "net"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	. "github.com/xtls/xray-core/proxy/shadowsocks_2022"
)

func TestStreamMixedReadsAndRetainedPayload(t *testing.T) {
	for _, name := range []string{MethodAES128GCM, MethodAES256GCM, MethodChaCha20Poly1305} {
		t.Run(name, func(t *testing.T) {
			method, _ := GetCipherMethod(name)
			key := bytes.Repeat([]byte{7}, method.KeySaltLength)
			wc, err := method.NewAEAD(key)
			if err != nil {
				t.Fatal(err)
			}
			rc, err := method.NewAEAD(key)
			if err != nil {
				t.Fatal(err)
			}
			var wire bytes.Buffer
			writer := NewStreamWriter(&wire, wc)
			chunks := [][]byte{bytes.Repeat([]byte{1}, 64), bytes.Repeat([]byte{2}, 8192), bytes.Repeat([]byte{3}, 32768), bytes.Repeat([]byte{4}, 65535), []byte("last")}
			for _, chunk := range chunks {
				if err := writer.WriteChunk(chunk); err != nil {
					t.Fatal(err)
				}
			}
			reader := NewStreamReader(&wire, rc)
			if n, err := reader.Read(nil); n != 0 || err != nil {
				t.Fatalf("zero read: %d %v", n, err)
			}
			prefix := make([]byte, 13)
			if n, err := reader.Read(prefix); n != len(prefix) || err != nil || !bytes.Equal(prefix, chunks[0][:13]) {
				t.Fatal("prefix read changed")
			}
			retained, err := reader.ReadMultiBuffer()
			if err != nil {
				t.Fatal(err)
			}
			defer buf.ReleaseMulti(retained)
			if !bytes.Equal(retained[0].Bytes(), chunks[0][13:]) {
				t.Fatal("cached remainder changed")
			}
			var prior buf.MultiBuffer
			for _, chunk := range chunks[1:] {
				mb, err := reader.ReadMultiBuffer()
				if err != nil {
					t.Fatal(err)
				}
				got := make([]byte, mb.Len())
				mb.Copy(got)
				if !bytes.Equal(got, chunk) {
					t.Fatal("chunk dropped or duplicated")
				}
				for _, b := range mb {
					if b.Len() > buf.Size {
						t.Fatal("consumer buffer exceeds regular size")
					}
				}
				if !bytes.Equal(retained[0].Bytes(), chunks[0][13:]) {
					t.Fatal("cached returned bytes overwritten")
				}
				if prior != nil {
					if !bytes.Equal(prior[0].Bytes(), chunks[1]) {
						t.Fatal("owned plaintext overwritten by next read")
					}
				}
				if prior == nil {
					prior = mb
					defer buf.ReleaseMulti(prior)
				} else {
					buf.ReleaseMulti(mb)
				}
			}
			if _, err := reader.ReadMultiBuffer(); !errors.Is(err, io.EOF) {
				t.Fatalf("end: %v", err)
			}
			if !bytes.Equal(reader.Nonce(), writer.Nonce()) {
				t.Fatal("length/payload nonce progression differs")
			}
		})
	}
}

type shortStreamWriter struct{}

func (shortStreamWriter) Write(p []byte) (int, error) { return len(p) - 1, nil }

func TestStreamErrors(t *testing.T) {
	method, _ := GetCipherMethod(MethodAES128GCM)
	key := bytes.Repeat([]byte{9}, method.KeySaltLength)
	c, _ := method.NewAEAD(key)
	if err := NewStreamWriter(shortStreamWriter{}, c).WriteChunk([]byte("payload")); !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("short write: %v", err)
	}
	if err := NewStreamWriter(io.Discard, c).WriteChunk(make([]byte, 65536)); err == nil {
		t.Fatal("oversize chunk accepted")
	}
	if _, err := WriteTCPRequest(shortStreamWriter{}, method, [][]byte{key}, net.TCPDestination(net.LocalHostIP, 443), key, []byte("payload")); !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("short request header: %v", err)
	}
	if _, err := NewServerStreamWriter(shortStreamWriter{}, method, key, key).Write([]byte("payload")); !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("short response header: %v", err)
	}
	var wire bytes.Buffer
	c, _ = method.NewAEAD(key)
	if err := NewStreamWriter(&wire, c).WriteChunk([]byte("payload")); err != nil {
		t.Fatal(err)
	}
	pristine := append([]byte(nil), wire.Bytes()...)
	for _, length := range []int{1, 17, len(pristine) - 1} {
		c, _ = method.NewAEAD(key)
		mb, err := NewStreamReader(bytes.NewReader(pristine[:length]), c).ReadMultiBuffer()
		buf.ReleaseMulti(mb)
		if err == nil {
			t.Fatal("truncated chunk accepted")
		}
	}
	for _, index := range []int{0, len(pristine) - 1} {
		damaged := append([]byte(nil), pristine...)
		damaged[index] ^= 1
		c, _ = method.NewAEAD(key)
		mb, err := NewStreamReader(bytes.NewReader(damaged), c).ReadMultiBuffer()
		buf.ReleaseMulti(mb)
		if err == nil || len(mb) != 0 {
			t.Fatal("tampered chunk returned plaintext")
		}
	}
}

type limitedStreamWriter struct {
	bytes.Buffer
	remaining int
	err       error
}

func (w *limitedStreamWriter) Write(p []byte) (int, error) {
	if len(p) > w.remaining {
		p = p[:w.remaining]
		n, _ := w.Buffer.Write(p)
		w.remaining -= n
		return n, w.err
	}
	n, err := w.Buffer.Write(p)
	w.remaining -= n
	return n, err
}

func TestStreamWriteProgressBeforeError(t *testing.T) {
	method, _ := GetCipherMethod(MethodAES128GCM)
	key := bytes.Repeat([]byte{9}, method.KeySaltLength)
	payload := bytes.Repeat([]byte{0x41}, MaxPacketSize+17)
	for _, failure := range []error{nil, io.ErrClosedPipe} {
		c, _ := method.NewAEAD(key)
		wire := &limitedStreamWriter{remaining: MaxPacketSize + 2 + 2*AEADTagSize + 5, err: failure}
		n, err := NewStreamWriter(wire, c).Write(payload)
		wantErr := failure
		if wantErr == nil {
			wantErr = io.ErrShortWrite
		}
		if n != MaxPacketSize || !errors.Is(err, wantErr) {
			t.Fatalf("Write = %d, %v; want %d, %v", n, err, MaxPacketSize, wantErr)
		}
		c, _ = method.NewAEAD(key)
		reader := NewStreamReader(wire, c)
		mb, err := reader.ReadMultiBuffer()
		if err != nil || mb.String() != string(payload[:MaxPacketSize]) {
			buf.ReleaseMulti(mb)
			t.Fatalf("completed chunk changed: %v", err)
		}
		buf.ReleaseMulti(mb)
		mb, err = reader.ReadMultiBuffer()
		buf.ReleaseMulti(mb)
		if err == nil {
			t.Fatal("partial next frame accepted")
		}
	}
}

func TestUDPConsumedInputAndAuthentication(t *testing.T) {
	for _, name := range []string{MethodAES128GCM, MethodAES256GCM, MethodChaCha20Poly1305} {
		t.Run(name, func(t *testing.T) {
			method, _ := GetCipherMethod(name)
			psk := bytes.Repeat([]byte{5}, method.KeySaltLength)
			codec, err := NewUDPPacketCodec(method, [][]byte{psk})
			if err != nil {
				t.Fatal(err)
			}
			client, err := codec.NewClientSession()
			if err != nil {
				t.Fatal(err)
			}
			server, err := NewUDPServerCodec(method, psk, time.Minute)
			if err != nil {
				t.Fatal(err)
			}
			dest := net.UDPDestination(net.LocalHostIPv6, 1234)
			payload := bytes.Repeat([]byte{0xab}, 1200)
			packet, err := client.EncodePacket(dest, payload)
			if err != nil {
				t.Fatal(err)
			}
			defer packet.Release()
			pristine := append([]byte(nil), packet.Bytes()...)
			for _, length := range []int{0, 15, len(pristine) - 1} {
				decoded, err := server.DecodePacket(append([]byte(nil), pristine[:length]...))
				if err == nil || decoded.Payload != nil {
					t.Fatal("truncated packet returned plaintext")
				}
			}
			damaged := append([]byte(nil), pristine...)
			damaged[len(damaged)-1] ^= 1
			if decoded, err := server.DecodePacket(damaged); err == nil || decoded.Payload != nil {
				t.Fatal("tampered packet returned plaintext")
			}
			stale := mutateUDPBody(t, method, psk, pristine, func(body []byte) { binary.BigEndian.PutUint64(body[1:9], uint64(time.Now().Unix()-120)) })
			if decoded, err := server.DecodePacket(stale); err != ErrBadTimestamp || decoded.Payload != nil {
				t.Fatalf("timestamp: %v", err)
			}
			wrongHeader := mutateUDPBody(t, method, psk, pristine, func(body []byte) { body[0] = 0xff })
			if decoded, err := server.DecodePacket(wrongHeader); err != ErrBadHeaderType || decoded.Payload != nil {
				t.Fatalf("header type: %v", err)
			}
			badPadding := mutateUDPBody(t, method, psk, pristine, func(body []byte) { binary.BigEndian.PutUint16(body[9:11], 65535) })
			if decoded, err := server.DecodePacket(badPadding); err != ErrNoPadding || decoded.Payload != nil {
				t.Fatalf("padding: %v", err)
			}
			malformed := mutateUDPBody(t, method, psk, pristine, func(body []byte) { body[11] = 0xff })
			if decoded, err := server.DecodePacket(malformed); err == nil || decoded.Payload != nil {
				t.Fatal("malformed address returned plaintext")
			}
			first, err := server.DecodePacket(packet.Bytes())
			if err != nil || first.Destination != dest || !bytes.Equal(first.Payload, payload) {
				t.Fatalf("valid after invalid controls: %v", err)
			}
			if _, err := server.DecodePacket(append([]byte(nil), pristine...)); err != ErrPacketIdNotUnique {
				t.Fatalf("replay: %v", err)
			}
			next, err := client.EncodePacket(dest, []byte("next"))
			if err != nil {
				t.Fatal(err)
			}
			defer next.Release()
			if _, err := server.DecodePacket(next.Bytes()); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(first.Payload, payload) {
				t.Fatal("payload overwritten by subsequent decode")
			}

			serverSession := server.Sessions().GetOrCreate(first.SessionID)
			if err := serverSession.EnsureServerState(method, psk); err != nil {
				t.Fatal(err)
			}
			reply, err := serverSession.EncodeServerPacket(method, client.ClientSessionID(), dest, payload)
			if err != nil {
				t.Fatal(err)
			}
			replyCopy := append([]byte(nil), reply...)
			decoded, err := client.DecodePacket(reply)
			if err != nil || decoded.Destination != dest || !bytes.Equal(decoded.Payload, payload) {
				t.Fatalf("reply: %v", err)
			}
			if _, err := client.DecodePacket(replyCopy); err != ErrPacketIdNotUnique {
				t.Fatalf("reply replay: %v", err)
			}
			wrong, err := serverSession.EncodeServerPacket(method, client.ClientSessionID()+1, dest, []byte("wrong binding"))
			if err != nil {
				t.Fatal(err)
			}
			if decoded, err := client.DecodePacket(wrong); err == nil || decoded.Payload != nil {
				t.Fatal("wrong client binding accepted")
			}

			overhead := 16 + 19 + AddrPortLength(dest) + AEADTagSize
			if method.IsChaCha {
				overhead = PacketNonceSize + 35 + AddrPortLength(dest) + AEADTagSize
			}
			capacityPayload := bytes.Repeat([]byte{0x34}, buf.Size-overhead)
			reply, err = serverSession.EncodeServerPacket(method, client.ClientSessionID(), dest, capacityPayload)
			if err != nil || len(reply) != buf.Size {
				t.Fatalf("capacity reply: %d %v", len(reply), err)
			}
			full, err := client.DecodePacket(reply)
			if err != nil || !bytes.Equal(full.Payload, capacityPayload) {
				t.Fatalf("capacity plaintext: %v", err)
			}
			if _, err := serverSession.EncodeServerPacket(method, client.ClientSessionID(), dest, append(capacityPayload, 1)); err != ErrPacketTooLarge {
				t.Fatalf("oversize reply: %v", err)
			}
			clientOverhead := 16 + 11 + AddrPortLength(dest) + AEADTagSize
			if method.IsChaCha {
				clientOverhead = PacketNonceSize + 27 + AddrPortLength(dest) + AEADTagSize
			}
			capacityPayload = bytes.Repeat([]byte{0x67}, buf.Size-clientOverhead)
			fullPacket, err := client.EncodePacket(dest, capacityPayload)
			if err != nil {
				t.Fatal(err)
			}
			defer fullPacket.Release()
			full, err = server.DecodePacket(fullPacket.Bytes())
			if err != nil || !bytes.Equal(full.Payload, capacityPayload) {
				t.Fatalf("capacity client plaintext: %v", err)
			}
			if _, err := client.EncodePacket(dest, append(capacityPayload, 1)); err != ErrPacketTooLarge {
				t.Fatalf("oversize client: %v", err)
			}
		})
	}
}

// Reauthenticate independently modified client plaintext to exercise post-AEAD
// validation without turning authentication failures into the expected outcome.
func mutateUDPBody(t *testing.T, method *CipherMethod, psk, packet []byte, mutate func([]byte)) []byte {
	t.Helper()
	output := append([]byte(nil), packet...)
	if method.IsChaCha {
		c, err := method.NewUDPCipher(psk)
		if err != nil {
			t.Fatal(err)
		}
		plain, err := c.Open(nil, output[:PacketNonceSize], output[PacketNonceSize:], nil)
		if err != nil {
			t.Fatal(err)
		}
		mutate(plain[16:])
		c.Seal(output[PacketNonceSize:PacketNonceSize], output[:PacketNonceSize], plain, nil)
	} else {
		block, err := method.NewBlock(psk)
		if err != nil {
			t.Fatal(err)
		}
		var header [16]byte
		block.Decrypt(header[:], output[:16])
		c, err := method.NewAEAD(DeriveSessionSubKey(psk, header[:8], method.KeySaltLength))
		if err != nil {
			t.Fatal(err)
		}
		plain, err := c.Open(nil, header[4:16], output[16:], nil)
		if err != nil {
			t.Fatal(err)
		}
		mutate(plain)
		c.Seal(output[16:16], header[4:16], plain, nil)
	}
	return output
}

func TestUDPReaderLoopbackRetainsOwnedPayload(t *testing.T) {
	for _, name := range []string{MethodAES128GCM, MethodAES256GCM, MethodChaCha20Poly1305} {
		t.Run(name, func(t *testing.T) {
			method, _ := GetCipherMethod(name)
			psk := bytes.Repeat([]byte{6}, method.KeySaltLength)
			codec, err := NewUDPPacketCodec(method, [][]byte{psk})
			if err != nil {
				t.Fatal(err)
			}
			client, err := codec.NewClientSession()
			if err != nil {
				t.Fatal(err)
			}
			server, err := NewUDPServerCodec(method, psk, time.Minute)
			if err != nil {
				t.Fatal(err)
			}
			listener, err := gonet.ListenUDP("udp", &gonet.UDPAddr{IP: gonet.IPv4(127, 0, 0, 1)})
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			_ = listener.SetDeadline(time.Now().Add(5 * time.Second))
			conn, err := gonet.DialUDP("udp", nil, listener.LocalAddr().(*gonet.UDPAddr))
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
			dest := net.UDPDestination(net.DomainAddress("owned.example"), 1234)
			payload := bytes.Repeat([]byte{0xc4}, 1200)
			serverSession := server.Sessions().GetOrCreate(client.ClientSessionID())
			if err := serverSession.EnsureServerState(method, psk); err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() {
				for range 2 {
					b := buf.New()
					n, remote, err := listener.ReadFromUDP(b.Extend(buf.Size))
					if err != nil {
						b.Release()
						done <- err
						return
					}
					b.Resize(0, int32(n))
					decoded, err := server.DecodePacket(b.Bytes())
					if err != nil {
						b.Release()
						done <- err
						return
					}
					if decoded.Destination != dest || !bytes.Equal(decoded.Payload, payload) {
						b.Release()
						done <- errors.New("UDP request changed")
						return
					}
					reply, err := serverSession.EncodeServerPacket(method, client.ClientSessionID(), decoded.Destination, decoded.Payload)
					b.Release()
					if err != nil {
						done <- err
						return
					}
					if _, err := listener.WriteToUDP(reply, remote); err != nil {
						done <- err
						return
					}
				}
				done <- nil
			}()
			reader := &UDPReader{Reader: conn, Session: client}
			writer := &UDPWriter{Writer: conn, Destination: dest, Session: client}
			var retained buf.MultiBuffer
			defer func() { buf.ReleaseMulti(retained) }()
			for range 2 {
				if err := writer.WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes(payload)}); err != nil {
					t.Fatal(err)
				}
				mb, err := reader.ReadMultiBuffer()
				if err != nil {
					t.Fatal(err)
				}
				if len(mb) != 1 || *mb[0].UDP != dest || !bytes.Equal(mb[0].Bytes(), payload) {
					t.Fatal("UDP reply changed")
				}
				if retained == nil {
					retained = mb
				} else {
					if !bytes.Equal(retained[0].Bytes(), payload) {
						t.Fatal("prior UDP plaintext was recycled")
					}
					buf.ReleaseMulti(mb)
				}
			}
			if err := <-done; err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestMultiUserUDPBodyOwnership(t *testing.T) {
	for _, name := range []string{MethodAES128GCM, MethodAES256GCM} {
		t.Run(name, func(t *testing.T) {
			method, _ := GetCipherMethod(name)
			master := bytes.Repeat([]byte{3}, method.KeySaltLength)
			psk := bytes.Repeat([]byte{4}, method.KeySaltLength)
			clientCodec, err := NewUDPPacketCodec(method, [][]byte{master, psk})
			if err != nil {
				t.Fatal(err)
			}
			client, err := clientCodec.NewClientSession()
			if err != nil {
				t.Fatal(err)
			}
			manager := NewUDPSessionManager(time.Minute)
			block, err := method.NewBlock(master)
			if err != nil {
				t.Fatal(err)
			}
			dest := net.UDPDestination(net.LocalHostIPv6, 1234)
			payload := bytes.Repeat([]byte{0xd3}, 1200)
			var retained []byte
			for range 2 {
				packet, err := client.EncodePacket(dest, payload)
				if err != nil {
					t.Fatal(err)
				}
				defer packet.Release()
				pristine := append([]byte(nil), packet.Bytes()...)
				var header [16]byte
				block.Decrypt(header[:], packet.Bytes()[:16])
				if DecryptUDPEIH(block, header[:], packet.Bytes()[16:32]) != DeriveUserPSKHash(psk) {
					t.Fatal("EIH changed")
				}
				sid := binary.BigEndian.Uint64(header[:8])
				pid := binary.BigEndian.Uint64(header[8:16])
				server := manager.GetOrCreate(sid)
				if !server.CheckPacketID(pid) {
					t.Fatal("fresh packet rejected")
				}
				damaged := append([]byte(nil), pristine[32:]...)
				damaged[len(damaged)-1] ^= 1
				if decoded, err := server.DecryptAESPayload(method, psk, sid, pid, header[:], damaged); err == nil || decoded.Payload != nil {
					t.Fatal("bad user body accepted")
				}
				if !server.CheckPacketID(pid) {
					t.Fatal("bad body consumed packet ID")
				}
				decoded, err := server.DecryptAESPayload(method, psk, sid, pid, header[:], packet.Bytes()[32:])
				if err != nil || decoded.Destination != dest || !bytes.Equal(decoded.Payload, payload) {
					t.Fatalf("multiuser body: %v", err)
				}
				if server.CheckPacketID(pid) {
					t.Fatal("multiuser replay accepted")
				}
				if !bytes.Equal(packet.Bytes()[:32], pristine[:32]) {
					t.Fatal("body decryption overwrote EIH or encrypted header")
				}
				if retained != nil && !bytes.Equal(retained, payload) {
					t.Fatal("prior multiuser plaintext changed")
				}
				retained = decoded.Payload
			}
		})
	}
}

func TestStreamRetainedReadAfterNextChunkFailure(t *testing.T) {
	for _, name := range []string{MethodAES128GCM, MethodAES256GCM, MethodChaCha20Poly1305} {
		for _, size := range []int{8192, 32768, 65535} {
			method, _ := GetCipherMethod(name)
			key := bytes.Repeat([]byte{8}, method.KeySaltLength)
			wc, _ := method.NewAEAD(key)
			var wire bytes.Buffer
			writer := NewStreamWriter(&wire, wc)
			payload := bytes.Repeat([]byte{0x41}, size)
			if err := writer.WriteChunk(payload); err != nil {
				t.Fatal(err)
			}
			boundary := wire.Len()
			if err := writer.WriteChunk(bytes.Repeat([]byte("x"), 8192)); err != nil {
				t.Fatal(err)
			}
			for _, index := range []int{boundary, wire.Len() - 1, -1} {
				data := append([]byte(nil), wire.Bytes()...)
				if index < 0 {
					data = data[:len(data)-1]
				} else {
					data[index] ^= 1
				}
				rc, _ := method.NewAEAD(key)
				reader := NewStreamReader(bytes.NewReader(data), rc)
				retained, err := reader.ReadMultiBuffer()
				if err != nil {
					t.Fatal(err)
				}
				failed, err := reader.ReadMultiBuffer()
				if err == nil || len(failed) != 0 {
					t.Fatal("next tampered chunk returned plaintext")
				}
				got := make([]byte, retained.Len())
				retained.Copy(got)
				buf.ReleaseMulti(retained)
				if !bytes.Equal(got, payload) {
					t.Fatal("failed next read corrupted retained plaintext")
				}
			}
		}
	}
}

func TestStreamTagSpillMixedReaderOwnership(t *testing.T) {
	for _, name := range []string{MethodAES128GCM, MethodAES256GCM, MethodChaCha20Poly1305} {
		t.Run(name, func(t *testing.T) {
			method, _ := GetCipherMethod(name)
			key := bytes.Repeat([]byte{0x4a}, method.KeySaltLength)
			wc, _ := method.NewAEAD(key)
			var wire bytes.Buffer
			writer := NewStreamWriter(&wire, wc)
			var payloads [][]byte
			for index, size := range []int{64, 8176, 8177, 8192, 8192, 8193, 8177, 64} {
				payload := bytes.Repeat([]byte{byte(index + 1)}, size)
				payloads = append(payloads, payload)
				if err := writer.WriteChunk(payload); err != nil {
					t.Fatal(err)
				}
			}
			rc, _ := method.NewAEAD(key)
			reader := NewStreamReader(&wire, rc)
			var retained []buf.MultiBuffer
			var expected [][]byte
			defer func() {
				for _, mb := range retained {
					buf.ReleaseMulti(mb)
				}
			}()
			for index, payload := range payloads {
				prefixLength := 0
				if index == 0 || index == 3 {
					prefixLength = 13
					prefix := make([]byte, prefixLength)
					if _, err := io.ReadFull(reader, prefix); err != nil || !bytes.Equal(prefix, payload[:prefixLength]) {
						t.Fatalf("mixed prefix read: %v", err)
					}
				}
				mb, err := reader.ReadMultiBuffer()
				if err != nil {
					t.Fatal(err)
				}
				retained = append(retained, mb)
				expected = append(expected, payload[prefixLength:])
				for priorIndex, prior := range retained {
					got := make([]byte, prior.Len())
					prior.Copy(got)
					if !bytes.Equal(got, expected[priorIndex]) {
						t.Fatal("subsequent read changed retained plaintext")
					}
					for _, b := range prior {
						if b.Len() > buf.Size {
							t.Fatal("returned plaintext exceeds consumer buffer limit")
						}
					}
				}
			}
			if _, err := reader.ReadMultiBuffer(); !errors.Is(err, io.EOF) {
				t.Fatalf("stream end: %v", err)
			}
			if !bytes.Equal(reader.Nonce(), writer.Nonce()) {
				t.Fatal("mixed chunk nonce progression differs")
			}
		})
	}
}
