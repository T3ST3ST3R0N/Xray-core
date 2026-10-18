package buf_test

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"syscall"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	appstats "github.com/xtls/xray-core/app/stats"
	"github.com/xtls/xray-core/common"
	. "github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/transport/internet/stat"
	"github.com/xtls/xray-core/transport/pipe"
)

func TestWriter(t *testing.T) {
	lb := New()
	common.Must2(lb.ReadFrom(rand.Reader))

	expectedBytes := append([]byte(nil), lb.Bytes()...)

	writeBuffer := bytes.NewBuffer(make([]byte, 0, 1024*1024))

	writer := NewBufferedWriter(NewWriter(writeBuffer))
	writer.SetBuffered(false)
	common.Must(writer.WriteMultiBuffer(MultiBuffer{lb}))
	common.Must(writer.Flush())

	if r := cmp.Diff(expectedBytes, writeBuffer.Bytes()); r != "" {
		t.Error(r)
	}
}

func TestBytesWriterReadFrom(t *testing.T) {
	const size = 50000
	pReader, pWriter := pipe.New(pipe.WithSizeLimit(size))
	reader := bufio.NewReader(io.LimitReader(rand.Reader, size))
	writer := NewBufferedWriter(pWriter)
	writer.SetBuffered(false)
	nBytes, err := reader.WriteTo(writer)
	if nBytes != size {
		t.Fatal("unexpected size of bytes written: ", nBytes)
	}
	if err != nil {
		t.Fatal("expect success, but actually error: ", err.Error())
	}

	mb, err := pReader.ReadMultiBuffer()
	common.Must(err)
	if mb.Len() != size {
		t.Fatal("unexpected size read: ", mb.Len())
	}
}

func TestDiscardBytes(t *testing.T) {
	b := New()
	common.Must2(b.ReadFullFrom(rand.Reader, Size))

	nBytes, err := io.Copy(DiscardBytes, b)
	common.Must(err)
	if nBytes != Size {
		t.Error("copy size: ", nBytes)
	}
}

func TestDiscardBytesMultiBuffer(t *testing.T) {
	const size = 10240*1024 + 1
	buffer := bytes.NewBuffer(make([]byte, 0, size))
	common.Must2(buffer.ReadFrom(io.LimitReader(rand.Reader, size)))

	r := NewReader(buffer)
	nBytes, err := io.Copy(DiscardBytes, &BufferedReader{Reader: r})
	common.Must(err)
	if nBytes != size {
		t.Error("copy size: ", nBytes)
	}
}

type vectorStreamConnection struct {
	net.Conn
	write func([]byte) (int, error)
}

func (c *vectorStreamConnection) SyscallConn() (syscall.RawConn, error) {
	return c.Conn.(syscall.Conn).SyscallConn()
}

func (c *vectorStreamConnection) Write(p []byte) (int, error) {
	if c.write != nil {
		return c.write(p)
	}
	return c.Conn.Write(p)
}

func vectorTCPPair(t *testing.T) (*vectorStreamConnection, func() []byte) {
	t.Helper()
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	common.Must(err)
	t.Cleanup(func() { listener.Close() })
	client, err := net.DialTCP("tcp4", nil, listener.Addr().(*net.TCPAddr))
	common.Must(err)
	t.Cleanup(func() { client.Close() })
	peer, err := listener.AcceptTCP()
	common.Must(err)
	t.Cleanup(func() { peer.Close() })
	common.Must(client.SetDeadline(time.Now().Add(5 * time.Second)))
	common.Must(peer.SetDeadline(time.Now().Add(5 * time.Second)))
	done := make(chan []byte, 1)
	go func() { p, _ := io.ReadAll(peer); done <- p }()
	return &vectorStreamConnection{Conn: client}, func() []byte {
		client.CloseWrite()
		return <-done
	}
}

func managedVectorPayload(parts ...string) (MultiBuffer, []*Buffer) {
	mb := make(MultiBuffer, len(parts))
	originals := make([]*Buffer, len(parts))
	for i, s := range parts {
		b := New()
		common.Must2(b.WriteString(s))
		mb[i], originals[i] = b, b
	}
	return mb, originals
}

func requireVectorReleased(t *testing.T, originals []*Buffer) {
	t.Helper()
	for _, b := range originals {
		if b.Bytes() != nil {
			t.Fatal("owned input storage was not released")
		}
	}
}

func TestBufferToBytesWriterDelivery(t *testing.T) {
	for _, test := range []struct {
		name  string
		parts []string
		want  string
	}{
		{"singleton", []string{"single"}, "single"},
		{"multiple", []string{"head", "body", "tail"}, "headbodytail"},
		{"empty-entries", []string{"", "head", "", "tail", ""}, "headtail"},
	} {
		t.Run(test.name, func(t *testing.T) {
			conn, received := vectorTCPPair(t)
			var counter appstats.Counter
			writer := NewWriter(&stat.CounterConnection{Connection: conn.Conn, WriteCounter: &counter})
			mb, originals := managedVectorPayload(test.parts...)
			common.Must(writer.WriteMultiBuffer(mb))
			if got := received(); string(got) != test.want || counter.Value() != int64(len(test.want)) {
				t.Fatalf("bytes=%q counter=%d want=%q", got, counter.Value(), test.want)
			}
			requireVectorReleased(t, originals)
		})
	}
}

func TestBufferToBytesWriterEmpty(t *testing.T) {
	conn, received := vectorTCPPair(t)
	common.Must(conn.Close())
	var counter appstats.Counter
	writer := NewWriter(&stat.CounterConnection{Connection: conn.Conn, WriteCounter: &counter})
	empty, originals := managedVectorPayload("")
	common.Must(writer.WriteMultiBuffer(append(MultiBuffer{nil}, empty...)))
	if got := received(); len(got) != 0 || counter.Value() != 0 {
		t.Fatalf("bytes=%q counter=%d", got, counter.Value())
	}
	requireVectorReleased(t, originals)
}

func TestBufferToBytesWriterPartialError(t *testing.T) {
	for _, test := range []struct {
		name  string
		parts []string
		limit int
		want  string
	}{
		{"initial", []string{"head", "body", "tail"}, 0, ""},
		{"first-boundary", []string{"head", "body", "tail"}, 4, "head"},
		{"middle", []string{"head", "body", "tail"}, 5, "headb"},
		{"complete", []string{"head", "body", "tail"}, 12, "headbodytail"},
		{"singleton", []string{"headbodytail"}, 5, "headb"},
	} {
		t.Run(test.name, func(t *testing.T) {
			conn, received := vectorTCPPair(t)
			failure := errors.New("body write failed")
			remaining := test.limit
			conn.write = func(p []byte) (int, error) {
				if len(p) > remaining {
					p = p[:remaining]
				}
				n, err := conn.Conn.Write(p)
				remaining -= n
				if err == nil && remaining == 0 {
					err = failure
				}
				return n, err
			}
			var counter appstats.Counter
			writer := NewWriter(&stat.CounterConnection{Connection: conn, WriteCounter: &counter})
			mb, originals := managedVectorPayload(test.parts...)
			if err := writer.WriteMultiBuffer(mb); err != failure {
				t.Fatalf("error=%v", err)
			}
			if counter.Value() != int64(len(test.want)) {
				t.Fatalf("counter=%d", counter.Value())
			}
			requireVectorReleased(t, originals)
			conn.write = nil
			next, owned := managedVectorPayload("new", "", "data")
			common.Must(writer.WriteMultiBuffer(next))
			if got := received(); string(got) != test.want+"newdata" || counter.Value() != int64(len(test.want)+7) {
				t.Fatalf("bytes=%q counter=%d", got, counter.Value())
			}
			requireVectorReleased(t, owned)
		})
	}
}

func TestBufferToBytesWriterPipeError(t *testing.T) {
	client, peer := net.Pipe()
	defer client.Close()
	received := make(chan []byte, 1)
	go func() { p := make([]byte, 5); n, _ := io.ReadFull(peer, p); peer.Close(); received <- p[:n] }()
	writer := &BufferToBytesWriter{Writer: client}
	mb, originals := managedVectorPayload("head", "body", "tail")
	if err := writer.WriteMultiBuffer(mb); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("error=%v", err)
	}
	if got := <-received; string(got) != "headb" {
		t.Fatalf("bytes=%q", got)
	}
	requireVectorReleased(t, originals)
}

func TestBufferToBytesWriterLargeAggregate(t *testing.T) {
	payload := make([]byte, 1<<20)
	conn, received := vectorTCPPair(t)
	// Count logical delivery into the real io.Discard consumer without sending
	// gigabytes over the socket. SyscallConn still delegates to the real TCP fd.
	conn.write = io.Discard.Write
	var counter appstats.Counter
	writer := NewWriter(&stat.CounterConnection{Connection: conn, WriteCounter: &counter})
	for _, views := range []int{2047, 2048, 2049, 4096} {
		counter.Set(0)
		mb := make(MultiBuffer, views)
		for i := range mb {
			mb[i] = FromBytes(payload)
		}
		common.Must(writer.WriteMultiBuffer(mb))
		if want := int64(views) * int64(len(payload)); counter.Value() != want {
			t.Fatalf("views=%d counter=%d want=%d", views, counter.Value(), want)
		}
	}
	if got := received(); len(got) != 0 {
		t.Fatalf("unexpected physical transfer=%d", len(got))
	}
}

func TestWriterInterface(t *testing.T) {
	{
		var writer interface{} = (*BufferToBytesWriter)(nil)
		switch writer.(type) {
		case Writer, io.Writer, io.ReaderFrom:
		default:
			t.Error("BufferToBytesWriter is not Writer, io.Writer or io.ReaderFrom")
		}
	}

	{
		var writer interface{} = (*BufferedWriter)(nil)
		switch writer.(type) {
		case Writer, io.Writer, io.ReaderFrom, io.ByteWriter:
		default:
			t.Error("BufferedWriter is not Writer, io.Writer, io.ReaderFrom or io.ByteWriter")
		}
	}
}
