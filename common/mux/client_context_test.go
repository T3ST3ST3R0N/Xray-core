package mux_test

import (
	"context"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/mux"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/testing/mocks"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet"
)

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
