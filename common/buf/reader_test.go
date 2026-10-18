package buf_test

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/xtls/xray-core/common"
	. "github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/transport/pipe"
)

func TestBytesReaderWriteTo(t *testing.T) {
	pReader, pWriter := pipe.New(pipe.WithSizeLimit(1024))
	reader := &BufferedReader{Reader: pReader}
	b1 := New()
	b1.WriteString("abc")
	b2 := New()
	b2.WriteString("efg")
	common.Must(pWriter.WriteMultiBuffer(MultiBuffer{b1, b2}))
	pWriter.Close()

	pReader2, pWriter2 := pipe.New(pipe.WithSizeLimit(1024))
	writer := NewBufferedWriter(pWriter2)
	writer.SetBuffered(false)

	nBytes, err := io.Copy(writer, reader)
	common.Must(err)
	if nBytes != 6 {
		t.Error("copy: ", nBytes)
	}

	mb, err := pReader2.ReadMultiBuffer()
	common.Must(err)
	if s := mb.String(); s != "abcefg" {
		t.Error("content: ", s)
	}
}

func TestBytesReaderMultiBuffer(t *testing.T) {
	pReader, pWriter := pipe.New(pipe.WithSizeLimit(1024))
	reader := &BufferedReader{Reader: pReader}
	b1 := New()
	b1.WriteString("abc")
	b2 := New()
	b2.WriteString("efg")
	common.Must(pWriter.WriteMultiBuffer(MultiBuffer{b1, b2}))
	pWriter.Close()

	mbReader := NewReader(reader)
	mb, err := mbReader.ReadMultiBuffer()
	common.Must(err)
	if s := mb.String(); s != "abcefg" {
		t.Error("content: ", s)
	}
}

func TestReadByte(t *testing.T) {
	sr := strings.NewReader("abcd")
	reader := &BufferedReader{
		Reader: NewReader(sr),
	}
	b, err := reader.ReadByte()
	common.Must(err)
	if b != 'a' {
		t.Error("unexpected byte: ", b, " want a")
	}
	if reader.BufferedBytes() != 3 { // 3 bytes left in buffer
		t.Error("unexpected buffered Bytes: ", reader.BufferedBytes())
	}

	nBytes, err := reader.WriteTo(DiscardBytes)
	common.Must(err)
	if nBytes != 3 {
		t.Error("unexpect bytes written: ", nBytes)
	}
}

func TestReadBuffer(t *testing.T) {
	{
		sr := strings.NewReader("abcd")
		buf, err := ReadBuffer(sr)
		common.Must(err)

		if s := buf.String(); s != "abcd" {
			t.Error("unexpected str: ", s, " want abcd")
		}
		buf.Release()
	}
}

func TestReadAtMost(t *testing.T) {
	sr := strings.NewReader("abcd")
	reader := &BufferedReader{
		Reader: NewReader(sr),
	}

	mb, err := reader.ReadAtMost(3)
	common.Must(err)
	if s := mb.String(); s != "abc" {
		t.Error("unexpected read result: ", s)
	}

	nBytes, err := reader.WriteTo(DiscardBytes)
	common.Must(err)
	if nBytes != 1 {
		t.Error("unexpect bytes written: ", nBytes)
	}
}

func TestPacketReader_ReadMultiBuffer(t *testing.T) {
	const alpha = "abcefg"
	buf := bytes.NewBufferString(alpha)
	reader := &PacketReader{buf}
	mb, err := reader.ReadMultiBuffer()
	common.Must(err)
	if s := mb.String(); s != alpha {
		t.Error("content: ", s)
	}
}

type dataAndErrorReader struct {
	data []byte
	err  error
	next io.Reader
}

func (r *dataAndErrorReader) Read(p []byte) (int, error) {
	if len(r.data) == 0 {
		if r.next != nil {
			return r.next.Read(p)
		}
		return 0, io.EOF
	}
	n := copy(p, r.data)
	r.data = r.data[n:]
	if len(r.data) == 0 {
		return n, r.err
	}
	return n, nil
}

func TestBufferedReaderDataBeforeError(t *testing.T) {
	for _, terminal := range []error{io.EOF, errors.New("source failure")} {
		t.Run(terminal.Error(), func(t *testing.T) {
			reader := &BufferedReader{
				Reader: NewReader(&dataAndErrorReader{data: []byte("abcdef"), err: terminal}),
			}
			defer func() { ReleaseMulti(reader.Buffer) }()
			var payload [6]byte
			n, err := io.ReadFull(reader, payload[:])
			if n != 6 || err != nil || string(payload[:]) != "abcdef" {
				t.Fatalf("ReadFull = %d, %v, %q; want 6, nil, abcdef", n, err, payload[:])
			}
			n, err = reader.Read(payload[:])
			if n != 0 || err != terminal {
				t.Fatalf("terminal read = %d, %v; want 0, %v", n, err, terminal)
			}
		})
	}
}

func TestBufferedReaderErrorAcrossReadMethods(t *testing.T) {
	for _, terminal := range []error{io.EOF, errors.New("source failure")} {
		for _, first := range []string{"Read", "ReadAtMost"} {
			for _, last := range []string{"Read", "ReadAtMost", "ReadMultiBuffer", "WriteTo"} {
				t.Run(terminal.Error()+"/"+first+"/"+last, func(t *testing.T) {
					reader := &BufferedReader{
						Reader: NewReader(&dataAndErrorReader{
							data: []byte("abcdef"), err: terminal, next: strings.NewReader("next"),
						}),
					}
					defer func() { ReleaseMulti(reader.Buffer) }()
					if first == "Read" {
						var prefix [1]byte
						n, err := reader.Read(prefix[:])
						if n != 1 || err != nil || prefix[0] != 'a' {
							t.Fatalf("prefix = %d, %v, %q; want 1, nil, a", n, err, prefix[:])
						}
					} else {
						mb, err := reader.ReadAtMost(1)
						prefix := mb.String()
						ReleaseMulti(mb)
						if prefix != "a" || err != nil {
							t.Fatalf("prefix = %q, %v; want a, nil", prefix, err)
						}
					}

					var payload string
					var err error
					expectedErr := terminal
					switch last {
					case "Read":
						var data [5]byte
						n, readErr := io.ReadFull(reader, data[:])
						if n != 5 || readErr != nil {
							t.Fatalf("drain = %d, %v; want 5, nil", n, readErr)
						}
						payload = string(data[:])
						n, err = reader.Read(data[:])
						if n != 0 {
							t.Fatalf("terminal read returned %d bytes", n)
						}
					case "ReadAtMost", "ReadMultiBuffer":
						read := reader.ReadMultiBuffer
						if last == "ReadAtMost" {
							read = func() (MultiBuffer, error) { return reader.ReadAtMost(8) }
						}
						mb, readErr := read()
						payload = mb.String()
						ReleaseMulti(mb)
						if readErr != nil {
							t.Fatalf("draining bytes returned %v", readErr)
						}
						mb, err = read()
						empty := mb.IsEmpty()
						ReleaseMulti(mb)
						if !empty {
							t.Fatal("terminal read returned extra payload")
						}
					case "WriteTo":
						var output bytes.Buffer
						n, writeErr := reader.WriteTo(&output)
						payload, err = output.String(), writeErr
						if n != 5 {
							t.Fatalf("WriteTo count = %d; want 5", n)
						}
						if terminal == io.EOF {
							expectedErr = nil // WriteTo treats EOF as successful completion.
						}
					}
					if payload != "bcdef" || !errors.Is(err, expectedErr) {
						t.Fatalf("drain = %q, %v; want bcdef, %v", payload, err, expectedErr)
					}
					var next [4]byte
					n, readErr := io.ReadFull(reader, next[:])
					if n != 4 || readErr != nil || string(next[:]) != "next" {
						t.Fatalf("read after error = %d, %v, %q; want 4, nil, next", n, readErr, next[:])
					}
				})
			}
		}
	}
}

func TestReaderInterface(t *testing.T) {
	_ = io.Reader(new(ReadVReader))
	_ = Reader(new(ReadVReader))

	_ = Reader(new(BufferedReader))
	_ = io.Reader(new(BufferedReader))
	_ = io.ByteReader(new(BufferedReader))
	_ = io.WriterTo(new(BufferedReader))
}
