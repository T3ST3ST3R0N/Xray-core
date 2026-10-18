package shadowsocks_test

import (
	"bytes"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	. "github.com/xtls/xray-core/proxy/shadowsocks"
)

func toAccount(a *Account) protocol.Account {
	account, err := a.AsAccount()
	common.Must(err)
	return account
}

func equalRequestHeader(x, y *protocol.RequestHeader) bool {
	return cmp.Equal(x, y, cmp.Comparer(func(x, y protocol.RequestHeader) bool {
		return x == y
	}))
}

func TestUDPEncodingDecoding(t *testing.T) {
	testRequests := []protocol.RequestHeader{
		{
			Version: Version,
			Command: protocol.RequestCommandUDP,
			Address: net.LocalHostIP,
			Port:    1234,
			User: &protocol.MemoryUser{
				Email: "love@example.com",
				Account: toAccount(&Account{
					Password:   "password",
					CipherType: CipherType_AES_128_GCM,
				}),
			},
		},
	}

	for _, request := range testRequests {
		data := buf.New()
		common.Must2(data.WriteString("test string"))
		encodedData, err := EncodeUDPPacket(&request, data.Bytes())
		common.Must(err)

		validator := new(Validator)
		validator.Add(request.User)
		decodedRequest, decodedData, err := DecodeUDPPacket(validator, encodedData)
		common.Must(err)

		if r := cmp.Diff(decodedData.Bytes(), data.Bytes()); r != "" {
			t.Error("data: ", r)
		}

		if equalRequestHeader(decodedRequest, &request) == false {
			t.Error("different request")
		}
	}
}

func TestUDPDecodingWithPayloadTooShort(t *testing.T) {
	testAccounts := []protocol.Account{
		toAccount(&Account{
			Password:   "password",
			CipherType: CipherType_AES_128_GCM,
		}),
	}

	for _, account := range testAccounts {
		data := buf.New()
		data.WriteString("short payload")
		validator := new(Validator)
		validator.Add(&protocol.MemoryUser{
			Account: account,
		})
		_, _, err := DecodeUDPPacket(validator, data)
		if err == nil {
			t.Fatal("expected error")
		}
	}
}

func TestTCPRequest(t *testing.T) {
	cases := []struct {
		request *protocol.RequestHeader
		payload []byte
	}{
		{
			request: &protocol.RequestHeader{
				Version: Version,
				Command: protocol.RequestCommandTCP,
				Address: net.LocalHostIP,
				Port:    1234,
				User: &protocol.MemoryUser{
					Email: "love@example.com",
					Account: toAccount(&Account{
						Password:   "tcp-password",
						CipherType: CipherType_AES_128_GCM,
					}),
				},
			},
			payload: []byte("test string"),
		},
		{
			request: &protocol.RequestHeader{
				Version: Version,
				Command: protocol.RequestCommandTCP,
				Address: net.LocalHostIPv6,
				Port:    1234,
				User: &protocol.MemoryUser{
					Email: "love@example.com",
					Account: toAccount(&Account{
						Password:   "password",
						CipherType: CipherType_AES_256_GCM,
					}),
				},
			},
			payload: []byte("test string"),
		},
		{
			request: &protocol.RequestHeader{
				Version: Version,
				Command: protocol.RequestCommandTCP,
				Address: net.DomainAddress("example.com"),
				Port:    1234,
				User: &protocol.MemoryUser{
					Email: "love@example.com",
					Account: toAccount(&Account{
						Password:   "password",
						CipherType: CipherType_CHACHA20_POLY1305,
					}),
				},
			},
			payload: []byte("test string"),
		},
	}

	runTest := func(request *protocol.RequestHeader, payload []byte) {
		data := buf.New()
		common.Must2(data.Write(payload))

		cache := buf.New()
		defer cache.Release()

		writer, err := WriteTCPRequest(request, cache)
		common.Must(err)

		common.Must(writer.WriteMultiBuffer(buf.MultiBuffer{data}))

		validator := new(Validator)
		validator.Add(request.User)
		decodedRequest, reader, err := ReadTCPSession(validator, cache)
		common.Must(err)
		if equalRequestHeader(decodedRequest, request) == false {
			t.Error("different request")
		}

		decodedData, err := reader.ReadMultiBuffer()
		common.Must(err)
		if r := cmp.Diff(decodedData[0].Bytes(), payload); r != "" {
			t.Error("data: ", r)
		}
	}

	for _, test := range cases {
		runTest(test.request, test.payload)
	}
}

func TestUDPReaderWriter(t *testing.T) {
	user := &protocol.MemoryUser{
		Account: toAccount(&Account{
			Password:   "test-password",
			CipherType: CipherType_CHACHA20_POLY1305,
		}),
	}
	cache := buf.New()
	defer cache.Release()

	writer := &UDPWriter{
		Writer: cache,
		Request: &protocol.RequestHeader{
			Version: Version,
			Address: net.DomainAddress("example.com"),
			Port:    123,
			User:    user,
		},
	}

	reader := &UDPReader{
		Reader: cache,
		User:   user,
	}

	{
		b := buf.New()
		common.Must2(b.WriteString("test payload"))
		common.Must(writer.WriteMultiBuffer(buf.MultiBuffer{b}))

		payload, err := reader.ReadMultiBuffer()
		common.Must(err)
		if payload[0].String() != "test payload" {
			t.Error("unexpected output: ", payload[0].String())
		}
	}

	{
		b := buf.New()
		common.Must2(b.WriteString("test payload 2"))
		common.Must(writer.WriteMultiBuffer(buf.MultiBuffer{b}))

		payload, err := reader.ReadMultiBuffer()
		common.Must(err)
		if payload[0].String() != "test payload 2" {
			t.Error("unexpected output: ", payload[0].String())
		}
	}
}

func TestValidatorMixedCiphersPreservesCiphertext(t *testing.T) {
	ciphers := []CipherType{CipherType_AES_128_GCM, CipherType_AES_256_GCM, CipherType_CHACHA20_POLY1305, CipherType_XCHACHA20_POLY1305}
	for selectedIndex, selected := range ciphers {
		t.Run(selected.String(), func(t *testing.T) {
			validator := new(Validator)
			for index := range ciphers {
				if selectedIndex%2 != 0 {
					index = len(ciphers) - 1 - index
				}
				kind := ciphers[index]
				common.Must(validator.Add(&protocol.MemoryUser{Account: toAccount(&Account{Password: "wrong password", CipherType: kind})}))
			}
			user := &protocol.MemoryUser{Account: toAccount(&Account{Password: "correct password", CipherType: selected})}
			common.Must(validator.Add(user))
			request := &protocol.RequestHeader{User: user, Address: net.LocalHostIPv6, Port: 1234}
			payload := bytes.Repeat([]byte("mixed ciphers"), 90)
			packet, err := EncodeUDPPacket(request, payload)
			common.Must(err)
			defer packet.Release()
			pristine := append([]byte(nil), packet.Bytes()...)
			matched, _, plain, _, err := validator.Get(packet.Bytes(), protocol.RequestCommandUDP)
			if err != nil || matched != user || !bytes.HasSuffix(plain, payload) {
				t.Fatalf("last candidate failed: %v", err)
			}
			if !bytes.Equal(packet.Bytes(), pristine) {
				t.Fatal("candidate trial corrupted ciphertext")
			}
			for _, size := range []int{0, 31, 32, 33} {
				if _, _, _, _, err := validator.Get(packet.Bytes()[:size], protocol.RequestCommandUDP); err == nil {
					t.Fatal("truncated ciphertext authenticated")
				}
			}
			packet.Bytes()[len(pristine)-1] ^= 1
			if _, _, _, _, err := validator.Get(packet.Bytes(), protocol.RequestCommandUDP); err == nil {
				t.Fatal("tampered ciphertext authenticated")
			}
			decoded, data, err := DecodeUDPPacket(validator, buf.FromBytes(pristine))
			if err != nil || decoded.User != user || decoded.Address != request.Address || decoded.Port != request.Port || !bytes.Equal(data.Bytes(), payload) {
				t.Fatalf("decoded packet mismatch: %v", err)
			}
		})
	}
}

func TestUDPReaderUserTransition(t *testing.T) {
	var wire bytes.Buffer
	reader := &UDPReader{Reader: &wire}
	var retained buf.MultiBuffer
	defer func() { buf.ReleaseMulti(retained) }()
	for index, kind := range []CipherType{CipherType_AES_128_GCM, CipherType_XCHACHA20_POLY1305} {
		user := &protocol.MemoryUser{Account: toAccount(&Account{Password: kind.String(), CipherType: kind})}
		reader.User = user
		for range 2 {
			payload := bytes.Repeat([]byte{byte(index + 1)}, 1200)
			request := &protocol.RequestHeader{User: user, Address: net.DomainAddress("example.com"), Port: 1234}
			packet, err := EncodeUDPPacket(request, payload)
			common.Must(err)
			wire.Write(packet.Bytes())
			packet.Release()
			mb, err := reader.ReadMultiBuffer()
			if err != nil || len(mb) != 1 || !bytes.Equal(mb[0].Bytes(), payload) || *mb[0].UDP != net.UDPDestination(request.Address, request.Port) {
				t.Fatalf("reader user transition failed: %v", err)
			}
			if retained != nil && retained[0].Byte(0) != 1 {
				t.Fatal("previous payload changed")
			}
			if retained == nil {
				retained = mb
			} else {
				buf.ReleaseMulti(mb)
			}
		}
	}
}
