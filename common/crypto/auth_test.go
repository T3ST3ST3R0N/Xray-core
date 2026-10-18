package crypto_test

import (
	"bytes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	. "github.com/xtls/xray-core/common/crypto"
	"github.com/xtls/xray-core/common/protocol"
	"golang.org/x/crypto/chacha20poly1305"
)

func TestAuthenticationReaderWriter(t *testing.T) {
	key := make([]byte, 16)
	rand.Read(key)

	aead := NewAesGcm(key)

	const payloadSize = 1024 * 80
	rawPayload := make([]byte, payloadSize)
	rand.Read(rawPayload)

	payload := buf.MergeBytes(nil, rawPayload)

	cache := bytes.NewBuffer(nil)
	iv := make([]byte, 12)
	rand.Read(iv)

	writer := NewAuthenticationWriter(&AEADAuthenticator{
		AEAD:                    aead,
		NonceGenerator:          GenerateStaticBytes(iv),
		AdditionalDataGenerator: GenerateEmptyBytes(),
	}, PlainChunkSizeParser{}, cache, protocol.TransferTypeStream, nil)

	common.Must(writer.WriteMultiBuffer(payload))
	common.Must(writer.WriteMultiBuffer(buf.MultiBuffer{}))

	reader := NewAuthenticationReader(&AEADAuthenticator{
		AEAD:                    aead,
		NonceGenerator:          GenerateStaticBytes(iv),
		AdditionalDataGenerator: GenerateEmptyBytes(),
	}, PlainChunkSizeParser{}, cache, protocol.TransferTypeStream, nil)

	var mb buf.MultiBuffer

	for mb.Len() < payloadSize {
		mb2, err := reader.ReadMultiBuffer()
		common.Must(err)

		mb, _ = buf.MergeMulti(mb, mb2)
	}

	if mb.Len() != payloadSize {
		t.Error("mb len: ", mb.Len())
	}

	mbContent := make([]byte, payloadSize)
	buf.SplitBytes(mb, mbContent)
	if r := cmp.Diff(mbContent, rawPayload); r != "" {
		t.Error(r)
	}

	_, err := reader.ReadMultiBuffer()
	if err != io.EOF {
		t.Error("error: ", err)
	}
}

func TestAuthenticationReaderWriterPacket(t *testing.T) {
	key := make([]byte, 16)
	common.Must2(rand.Read(key))

	aead := NewAesGcm(key)

	cache := buf.New()
	iv := make([]byte, 12)
	rand.Read(iv)

	writer := NewAuthenticationWriter(&AEADAuthenticator{
		AEAD:                    aead,
		NonceGenerator:          GenerateStaticBytes(iv),
		AdditionalDataGenerator: GenerateEmptyBytes(),
	}, PlainChunkSizeParser{}, cache, protocol.TransferTypePacket, nil)

	var payload buf.MultiBuffer
	pb1 := buf.New()
	pb1.Write([]byte("abcd"))
	payload = append(payload, pb1)

	pb2 := buf.New()
	pb2.Write([]byte("efgh"))
	payload = append(payload, pb2)

	common.Must(writer.WriteMultiBuffer(payload))

	common.Must(writer.WriteMultiBuffer(buf.MultiBuffer{}))

	reader := NewAuthenticationReader(&AEADAuthenticator{
		AEAD:                    aead,
		NonceGenerator:          GenerateStaticBytes(iv),
		AdditionalDataGenerator: GenerateEmptyBytes(),
	}, PlainChunkSizeParser{}, cache, protocol.TransferTypePacket, nil)

	mb, err := reader.ReadMultiBuffer()
	common.Must(err)

	mb, b1 := buf.SplitFirst(mb)
	if b1.String() != "abcd" {
		t.Error("b1: ", b1.String())
	}

	mb, b2 := buf.SplitFirst(mb)
	if b2.String() != "efgh" {
		t.Error("b2: ", b2.String())
	}

	if !mb.IsEmpty() {
		t.Error("not empty")
	}

	_, err = reader.ReadMultiBuffer()
	if err != io.EOF {
		t.Error("error: ", err)
	}
}

type streamTestPadding struct{}

func (streamTestPadding) MaxPaddingLen() uint16  { return 16 }
func (streamTestPadding) NextPaddingLen() uint16 { return 8 }

func TestAuthenticationStreamFraming(t *testing.T) {
	for _, mode := range []string{"aes", "chacha", "authenticated-length", "padding"} {
		t.Run(mode, func(t *testing.T) {
			var aead cipher.AEAD = NewAesGcm(make([]byte, 16))
			if mode == "chacha" {
				var err error
				aead, err = chacha20poly1305.New(make([]byte, 32))
				common.Must(err)
			}
			auth := &AEADAuthenticator{AEAD: aead, NonceGenerator: GenerateAEADNonceWithSize(aead.NonceSize())}
			referenceAuth := &AEADAuthenticator{AEAD: aead, NonceGenerator: GenerateAEADNonceWithSize(aead.NonceSize())}
			var parser ChunkSizeEncoder = PlainChunkSizeParser{}
			var referenceParser ChunkSizeEncoder = PlainChunkSizeParser{}
			if mode == "authenticated-length" {
				parser = &AEADChunkSizeParser{Auth: auth}
				referenceParser = &AEADChunkSizeParser{Auth: referenceAuth}
			}
			var padding PaddingLengthGenerator
			maxPadding, paddingSize := 0, 0
			if mode == "padding" {
				padding = &streamTestPadding{}
				maxPadding, paddingSize = 16, 8
			}
			limit := buf.Size - aead.Overhead() - int(parser.SizeBytes()) - maxPadding
			var wire bytes.Buffer
			writer := NewAuthenticationWriter(auth, parser, &wire, protocol.TransferTypeStream, padding)
			for _, shape := range []struct {
				name  string
				sizes []int
			}{
				{"small", []int{64}},
				{"limit", []int{limit}},
				{"over-limit", []int{limit + 1}},
				{"full", []int{buf.Size}},
				{"large-managed", []int{3*limit + 17}},
				{"exact-multiple", []int{3 * limit}},
				{"large-unmanaged", []int{5*limit + 23}},
				{"multi", []int{511, 513}},
				{"empty-prefix", []int{0, 64}},
				{"empty", []int{0}},
			} {
				t.Run(shape.name, func(t *testing.T) {
					var mb buf.MultiBuffer
					var plain []byte
					var unmanagedInput []byte
					var inputs []*buf.Buffer
					for _, size := range shape.sizes {
						payload := bytes.Repeat([]byte{byte(size)}, size)
						var b *buf.Buffer
						if shape.name == "large-unmanaged" {
							unmanagedInput = payload
							b = buf.FromBytes(payload)
						} else {
							if size > buf.Size {
								b = buf.NewWithSize(int32(size))
							} else {
								b = buf.New()
							}
							common.Must2(b.Write(payload))
							inputs = append(inputs, b)
						}
						mb = append(mb, b)
						plain = append(plain, payload...)
					}
					defer buf.ReleaseMulti(mb)
					wire.Reset()
					common.Must(writer.WriteMultiBuffer(mb))
					if unmanagedInput != nil && !bytes.Equal(unmanagedInput, plain) {
						t.Fatal("unmanaged plaintext overwritten")
					}
					got := wire.Bytes()
					chunks := 0
					for {
						size := min(len(plain), limit)
						encryptedSize := size + aead.Overhead()
						header := make([]byte, referenceParser.SizeBytes())
						referenceParser.Encode(uint16(encryptedSize+paddingSize), header)
						payload, err := referenceAuth.Seal(nil, plain[:size])
						common.Must(err)
						frameSize := len(header) + len(payload) + paddingSize
						if len(got) < frameSize || !bytes.Equal(got[:len(header)], header) || !bytes.Equal(got[len(header):len(header)+len(payload)], payload) {
							t.Fatalf("ciphertext/header differs at chunk %d: got %x", chunks, got)
						}
						got = got[frameSize:]
						plain = plain[size:]
						chunks++
						if len(plain) == 0 {
							break
						}
					}
					if len(got) != 0 {
						t.Fatalf("unexpected trailing wire bytes: %d", len(got))
					}
					if shape.name != "empty" {
						for _, input := range inputs {
							if input.Bytes() != nil {
								t.Fatal("writer did not consume/release input")
							}
						}
					}
				})
			}
		})
	}
}

type retainedAuthOutput struct {
	bytes.Buffer
	buffers buf.MultiBuffer
	err     error
}

func (w *retainedAuthOutput) WriteMultiBuffer(mb buf.MultiBuffer) error {
	w.buffers = mb
	if w.err != nil {
		buf.ReleaseMulti(mb)
	}
	return w.err
}

func TestAuthenticationStreamOwnershipAndErrors(t *testing.T) {
	for _, failure := range []string{"none", "nonce", "downstream"} {
		t.Run(failure, func(t *testing.T) {
			nonce := make([]byte, 12)
			if failure == "nonce" {
				nonce = nonce[:1]
			}
			auth := &AEADAuthenticator{AEAD: NewAesGcm(make([]byte, 16)), NonceGenerator: GenerateStaticBytes(nonce)}
			sink := &retainedAuthOutput{}
			if failure == "downstream" {
				sink.err = errors.New("downstream")
			}
			source := buf.New()
			common.Must2(source.Write([]byte("owned plaintext")))
			mb := buf.MultiBuffer{source}
			writer := NewAuthenticationWriter(auth, PlainChunkSizeParser{}, sink, protocol.TransferTypeStream, nil)
			err := writer.WriteMultiBuffer(mb)
			if (err != nil) != (failure != "none") || (failure == "downstream" && !errors.Is(err, sink.err)) {
				t.Fatalf("unexpected write error: %v", err)
			}
			if source.Bytes() != nil {
				t.Fatal("input retained after return")
			}
			defer buf.ReleaseMulti(sink.buffers)
			if failure == "none" {
				// The output remains valid after released input storage is reused.
				reused := buf.New()
				common.Must2(reused.Write(bytes.Repeat([]byte{0xff}, buf.Size)))
				defer reused.Release()
				ciphertext := sink.buffers[0].Bytes()
				if int(binary.BigEndian.Uint16(ciphertext[:2])) != len(ciphertext)-2 {
					t.Fatal("invalid output frame length")
				}
				plaintext, err := auth.Open(nil, ciphertext[2:])
				if err != nil || string(plaintext) != "owned plaintext" {
					t.Fatalf("output aliases consumed input: %q, %v", plaintext, err)
				}
			} else if failure == "nonce" && len(sink.buffers) != 0 {
				t.Fatal("sealed output delivered after seal failure")
			}
		})
	}
	// Unmanaged input must not become the ciphertext destination.
	payload := []byte("unmanaged plaintext")
	snapshot := append([]byte(nil), payload...)
	auth := &AEADAuthenticator{AEAD: NewAesGcm(make([]byte, 16)), NonceGenerator: GenerateStaticBytes(make([]byte, 12))}
	var sink bytes.Buffer
	writer := NewAuthenticationWriter(auth, PlainChunkSizeParser{}, &sink, protocol.TransferTypeStream, nil)
	common.Must(writer.WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes(payload)}))
	if !bytes.Equal(payload, snapshot) {
		t.Fatalf("plaintext overwritten: %x", payload)
	}
	ciphertext := sink.Bytes()
	if int(binary.BigEndian.Uint16(ciphertext[:2])) != len(ciphertext)-2 {
		t.Fatal("invalid unmanaged output frame length")
	}
	plaintext, err := auth.Open(nil, ciphertext[2:])
	if err != nil || !bytes.Equal(plaintext, snapshot) {
		t.Fatalf("unmanaged output plaintext: %q, %v", plaintext, err)
	}
}

type scratchAppendingAuthenticator struct {
	*AEADAuthenticator
}

func (a *scratchAppendingAuthenticator) Seal(dst, plaintext []byte) ([]byte, error) {
	_ = append(plaintext, 0xff)
	return a.AEADAuthenticator.Seal(dst, plaintext)
}

func TestAuthenticationOversizedOwnershipAndSealError(t *testing.T) {
	const limit = buf.Size - 16 - 2
	payload := bytes.Repeat([]byte{0x42}, 3*limit+17)
	for _, failure := range []string{"none", "scratch-append", "middle-seal", "downstream"} {
		t.Run(failure, func(t *testing.T) {
			nonce := GenerateAEADNonceWithSize(12)
			calls := 0
			auth := &AEADAuthenticator{
				AEAD: NewAesGcm(make([]byte, 16)),
				NonceGenerator: func() []byte {
					calls++
					n := nonce()
					if failure == "middle-seal" && calls == 2 {
						return n[:1]
					}
					return n
				},
			}
			sink := &retainedAuthOutput{}
			if failure == "downstream" {
				sink.err = errors.New("downstream")
			}
			source := buf.NewWithSize(int32(len(payload)))
			common.Must2(source.Write(payload))
			var writerAuth Authenticator = auth
			if failure == "scratch-append" {
				writerAuth = &scratchAppendingAuthenticator{auth}
			}
			writer := NewAuthenticationWriter(writerAuth, PlainChunkSizeParser{}, sink, protocol.TransferTypeStream, nil)
			err := writer.WriteMultiBuffer(buf.MultiBuffer{source})
			expectError := failure == "middle-seal" || failure == "downstream"
			if (err != nil) != expectError || failure == "downstream" && !errors.Is(err, sink.err) {
				t.Fatalf("unexpected write error: %v", err)
			}
			if source.Bytes() != nil {
				t.Fatal("input retained after return")
			}
			defer buf.ReleaseMulti(sink.buffers)
			if failure == "middle-seal" {
				if calls != 2 || len(sink.buffers) != 0 {
					t.Fatalf("partial ciphertext forwarded on second seal failure: calls=%d, frames=%d", calls, len(sink.buffers))
				}
				return
			}
			if failure == "downstream" {
				return
			}
			// Retained ciphertext must survive reuse of the released large input.
			reused := buf.NewWithSize(int32(len(payload)))
			common.Must2(reused.Write(bytes.Repeat([]byte{0xff}, len(payload))))
			defer reused.Release()
			reference := &AEADAuthenticator{AEAD: auth.AEAD, NonceGenerator: GenerateAEADNonceWithSize(12)}
			var plaintext []byte
			for _, frame := range sink.buffers {
				ciphertext := frame.Bytes()
				if int(binary.BigEndian.Uint16(ciphertext[:2])) != len(ciphertext)-2 {
					t.Fatal("invalid retained frame length")
				}
				p, err := reference.Open(nil, ciphertext[2:])
				common.Must(err)
				plaintext = append(plaintext, p...)
			}
			if calls != 4 || len(sink.buffers) != 4 || !bytes.Equal(plaintext, payload) {
				t.Fatalf("retained output changed: calls=%d, frames=%d, plaintext=%d", calls, len(sink.buffers), len(plaintext))
			}
		})
	}
}
