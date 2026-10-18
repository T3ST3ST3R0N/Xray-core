package mux_test

import (
	"context"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/mux"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/testing/mocks"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/pipe"
)

func TestIncrementalPickerFailure(t *testing.T) {
	mockCtl := gomock.NewController(t)
	defer mockCtl.Finish()

	mockWorkerFactory := mocks.NewMuxClientWorkerFactory(mockCtl)
	mockWorkerFactory.EXPECT().Create().Return(nil, errors.New("test"))

	picker := mux.IncrementalWorkerPicker{
		Factory: mockWorkerFactory,
	}

	_, err := picker.PickAvailable()
	if err == nil {
		t.Error("expected error, but nil")
	}
}

func TestClientWorkerEOF(t *testing.T) {
	reader, writer := pipe.New(pipe.WithoutSizeLimit())
	common.Must(writer.Close())

	worker, err := mux.NewClientWorker(transport.Link{Reader: reader, Writer: writer}, mux.ClientStrategy{})
	common.Must(err)

	time.Sleep(time.Millisecond * 500)

	f := worker.Dispatch(context.Background(), nil)
	if f {
		t.Error("expected failed dispatching, but actually not")
	}
}

func TestClientWorkerClose(t *testing.T) {
	mockCtl := gomock.NewController(t)
	defer mockCtl.Finish()

	r1, w1 := pipe.New(pipe.WithoutSizeLimit())
	worker1, err := mux.NewClientWorker(transport.Link{
		Reader: r1,
		Writer: w1,
	}, mux.ClientStrategy{
		MaxConcurrency: 4,
		MaxConnection:  4,
	})
	common.Must(err)

	r2, w2 := pipe.New(pipe.WithoutSizeLimit())
	worker2, err := mux.NewClientWorker(transport.Link{
		Reader: r2,
		Writer: w2,
	}, mux.ClientStrategy{
		MaxConcurrency: 4,
		MaxConnection:  4,
	})
	common.Must(err)

	factory := mocks.NewMuxClientWorkerFactory(mockCtl)
	gomock.InOrder(
		factory.EXPECT().Create().Return(worker1, nil),
		factory.EXPECT().Create().Return(worker2, nil),
	)

	picker := &mux.IncrementalWorkerPicker{
		Factory: factory,
	}
	manager := &mux.ClientManager{
		Picker: picker,
	}

	tr1, tw1 := pipe.New(pipe.WithoutSizeLimit())
	ctx1 := session.ContextWithOutbounds(context.Background(), []*session.Outbound{{
		Target: net.TCPDestination(net.DomainAddress("www.example.com"), 80),
	}})
	common.Must(manager.Dispatch(ctx1, &transport.Link{
		Reader: tr1,
		Writer: tw1,
	}))
	defer tw1.Close()

	common.Must(w1.Close())

	time.Sleep(time.Millisecond * 500)
	if !worker1.Closed() {
		t.Error("worker1 is not finished")
	}

	tr2, tw2 := pipe.New(pipe.WithoutSizeLimit())
	ctx2 := session.ContextWithOutbounds(context.Background(), []*session.Outbound{{
		Target: net.TCPDestination(net.DomainAddress("www.example.com"), 80),
	}})
	common.Must(manager.Dispatch(ctx2, &transport.Link{
		Reader: tr2,
		Writer: tw2,
	}))
	defer tw2.Close()

	common.Must(w2.Close())
}

func TestClientWorkerUDPSource(t *testing.T) {
	downR, downW := pipe.New(pipe.WithoutSizeLimit())
	upR, upW := pipe.New(pipe.WithoutSizeLimit())
	worker, err := mux.NewClientWorker(transport.Link{Reader: downR, Writer: upW}, mux.ClientStrategy{})
	common.Must(err)

	inR, inW := pipe.New(pipe.WithoutSizeLimit())
	outR, outW := pipe.New(pipe.WithoutSizeLimit())
	ctx := session.ContextWithOutbounds(context.Background(), []*session.Outbound{{
		Target: net.UDPDestination(net.ParseAddress("8.8.8.8"), 53),
	}})
	if !worker.Dispatch(ctx, &transport.Link{Reader: inR, Writer: outW}) {
		t.Fatal("failed to dispatch")
	}
	b := buf.New()
	b.WriteString("query")
	common.Must(inW.WriteMultiBuffer(buf.MultiBuffer{b}))
	mb, err := upR.ReadMultiBuffer() // New frame, the session is UDP from now on
	common.Must(err)
	buf.ReleaseMulti(mb)

	srcs := []net.Destination{
		net.UDPDestination(net.ParseAddress("1.1.1.1"), 1111),
		net.UDPDestination(net.DomainAddress("example.com"), 2222),
		net.UDPDestination(net.ParseAddress("3.3.3.3"), 3333),
	}
	w := mux.NewResponseWriter(1, downW, protocol.TransferTypePacket)
	var got buf.MultiBuffer
	for i := range srcs {
		b := buf.New()
		b.WriteString("reply")
		b.UDP = &srcs[i]
		common.Must(w.WriteMultiBuffer(buf.MultiBuffer{b}))
		// keep earlier replies around while the next frame is parsed
		mb, err := outR.ReadMultiBuffer()
		common.Must(err)
		got = append(got, mb...)
	}
	for i, b := range got {
		if b.UDP == nil || *b.UDP != srcs[i] {
			t.Errorf("reply %d: source = %v, want %v", i, b.UDP, srcs[i])
		}
	}
}

// Keep the nil-parent default and worker teardown contract covered independently
// of the transport writer optimizations in PR #4.
func TestDialingWorkerFactoryNilContext(t *testing.T) {
	mockCtl := gomock.NewController(t)
	defer mockCtl.Finish()

	processed := make(chan context.Context, 1)
	returned := make(chan struct{})
	outbound := mocks.NewProxyOutbound(mockCtl)
	outbound.EXPECT().Process(gomock.Any(), gomock.Any(), nil).DoAndReturn(
		func(ctx context.Context, link *transport.Link, _ internet.Dialer) error {
			defer close(returned)
			defer common.Close(link.Writer)
			processed <- ctx
			// Closing the real worker must unblock its proxy-side pipe reader.
			mb, err := link.Reader.ReadMultiBuffer()
			buf.ReleaseMulti(mb)
			return err
		})
	factory := mux.DialingWorkerFactory{Proxy: outbound}
	worker, err := factory.Create()
	if err != nil {
		t.Fatal(err)
	}
	defer worker.Close()

	var ctx context.Context
	select {
	case ctx = <-processed:
		if ctx == nil {
			t.Fatal("proxy received a nil context")
		}
		outbounds := session.OutboundsFromContext(ctx)
		if len(outbounds) != 1 || outbounds[0].Target != net.TCPDestination(net.DomainAddress("v1.mux.cool"), 9527) {
			t.Fatal("proxy did not receive the mux destination")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("factory did not start proxy processing")
	}
	if err := worker.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-returned:
	case <-time.After(5 * time.Second):
		t.Fatal("worker closure did not release proxy processing")
	}
	// Cancellation occurs after Process returns and the factory finishes cleanup.
	select {
	case <-ctx.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("factory goroutine did not finish cleanup")
	}
	if !worker.Closed() {
		t.Fatal("worker remained open")
	}
}
