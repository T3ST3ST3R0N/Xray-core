package shadowsocks_2022

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"maps"
	"sync"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/log"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/signal"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport"
)

const (
	uotV1Domain  = "sp.udp-over-tcp.arpa"
	uotV2Domain  = "sp.v2.udp-over-tcp.arpa"
	uotMaxRoutes = 256
)

// sing UoT uses SOCKS address families in its v2 request, but a different
// family mapping in packet frames. It is recognized only after SS2022
// authentication; it never opens a socket outside the normal UDP dispatcher.
var uotRequestAddress = protocol.NewAddressParser(
	protocol.AddressFamilyByte(1, net.AddressFamilyIPv4),
	protocol.AddressFamilyByte(3, net.AddressFamilyDomain),
	protocol.AddressFamilyByte(4, net.AddressFamilyIPv6),
)

var uotPacketAddress = protocol.NewAddressParser(
	protocol.AddressFamilyByte(0, net.AddressFamilyIPv4),
	protocol.AddressFamilyByte(1, net.AddressFamilyIPv6),
	protocol.AddressFamilyByte(2, net.AddressFamilyDomain),
)

type uotRequest struct {
	connect     bool
	destination net.Destination
}

func isSingUoT(dest net.Destination) bool {
	return dest.Network == net.Network_TCP && dest.Address != nil && dest.Address.Family().IsDomain() &&
		(dest.Address.Domain() == uotV1Domain || dest.Address.Domain() == uotV2Domain)
}

func readUoTRequest(reader io.Reader, legacy bool) (uotRequest, error) {
	if legacy {
		return uotRequest{}, nil
	}
	var flag [1]byte
	if _, err := io.ReadFull(reader, flag[:]); err != nil {
		return uotRequest{}, err
	}
	if flag[0] > 1 {
		return uotRequest{}, errors.New("invalid UoT connect flag")
	}
	address, port, err := uotRequestAddress.ReadAddressPort(nil, reader)
	if err != nil {
		return uotRequest{}, err
	}
	dest := net.UDPDestination(address, port)
	if address == nil || (address.Family().IsDomain() && address.Domain() == "") || (flag[0] == 1 && port == 0) {
		return uotRequest{}, errors.New("invalid UoT request destination")
	}
	return uotRequest{connect: flag[0] == 1, destination: dest}, nil
}

func readUoTPacket(reader io.Reader, request uotRequest) (*buf.Buffer, net.Destination, error) {
	dest := request.destination
	if !request.connect {
		address, port, err := uotPacketAddress.ReadAddressPort(nil, reader)
		if err != nil {
			return nil, net.Destination{}, err
		}
		dest = net.UDPDestination(address, port)
	}
	if dest.Address == nil || dest.Port == 0 || (dest.Address.Family().IsDomain() && dest.Address.Domain() == "") {
		return nil, net.Destination{}, errors.New("invalid UoT packet destination")
	}
	var length [2]byte
	if _, err := io.ReadFull(reader, length[:]); err != nil {
		return nil, net.Destination{}, err
	}
	size := int32(binary.BigEndian.Uint16(length[:]))
	packet := buf.NewWithSize(max(size, 1))
	if _, err := packet.ReadFullFrom(reader, size); err != nil {
		packet.Release()
		return nil, net.Destination{}, err
	}
	packet.UDP = &dest
	return packet, dest, nil
}

func writeUoTPacket(writer io.Writer, request uotRequest, dest net.Destination, payload []byte) error {
	if len(payload) > 65535 {
		return errors.New("UoT packet exceeds 16-bit length")
	}
	var frame bytes.Buffer
	if !request.connect {
		if err := uotPacketAddress.WriteAddressPort(&frame, dest.Address, dest.Port); err != nil {
			return err
		}
	}
	var length [2]byte
	binary.BigEndian.PutUint16(length[:], uint16(len(payload)))
	frame.Write(length[:])
	frame.Write(payload)
	if n, err := writer.Write(frame.Bytes()); err != nil {
		return err
	} else if n != frame.Len() {
		return io.ErrShortWrite
	}
	return nil
}

func processSingUoT(ctx context.Context, conn net.Conn, magic net.Destination, early []byte, reader io.Reader, writer io.Writer, dispatcher routing.Dispatcher, sessionPolicy policy.Session) error {
	ctx, cancel := context.WithCancel(ctx)
	ctx = policy.ContextWithBufferPolicy(ctx, sessionPolicy.Buffer)
	timer := signal.CancelAfterInactivity(ctx, cancel, sessionPolicy.Timeouts.ConnectionIdle)
	defer timer.SetTimeout(0)
	var mu, writeMu sync.Mutex
	var workers sync.WaitGroup
	routes := make(map[string]*transport.Link)
	closeRoutes := func() {
		mu.Lock()
		links := make([]*transport.Link, 0, len(routes))
		for _, link := range routes {
			links = append(links, link)
		}
		mu.Unlock()
		for _, link := range links {
			common.Interrupt(link.Reader)
			common.Interrupt(link.Writer)
		}
	}
	stop := context.AfterFunc(ctx, func() {
		conn.Close() // Unblock both encrypted stream reads and writes.
		closeRoutes()
	})
	defer func() {
		cancel()
		conn.Close()
		closeRoutes()
		workers.Wait()
		stop()
	}()

	input := io.MultiReader(bytes.NewReader(early), reader)
	request, err := readUoTRequest(input, magic.Address.Domain() == uotV1Domain)
	if err != nil {
		return err
	}
	for {
		packet, dest, err := readUoTPacket(input, request)
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}
		timer.Update()
		key := dest.String()
		mu.Lock()
		link := routes[key]
		full := len(routes) >= uotMaxRoutes
		mu.Unlock()
		if link == nil {
			if full {
				packet.Release()
				return errors.New("too many UoT destinations")
			}
			routeCtx, routeCancel := context.WithCancel(ctx)
			// Each UDP destination is an independent routing/sniffing session.
			// The TCP worker's Outbounds and Content are mutable; sharing them
			// lets concurrently active routes overwrite each other's target.
			routeCtx = session.ContextWithOutbounds(routeCtx, []*session.Outbound{{}})
			content := new(session.Content)
			if parent := session.ContentFromContext(ctx); parent != nil {
				*content = *parent
				content.Attributes = maps.Clone(parent.Attributes)
			}
			routeCtx = session.ContextWithContent(routeCtx, content)
			var email string
			if inbound := session.InboundFromContext(ctx); inbound != nil {
				// Dispatchers may attach per-link state to Inbound. Do not share
				// that mutable state between independently routed destinations.
				copy := *inbound
				routeCtx = session.ContextWithInbound(routeCtx, &copy)
				if copy.User != nil {
					email = copy.User.Email
				}
			}
			routeCtx = log.ContextWithAccessMessage(routeCtx, &log.AccessMessage{
				From: conn.RemoteAddr(), To: dest, Status: log.AccessAccepted, Email: email,
			})
			link, err = dispatcher.Dispatch(routeCtx, dest)
			if err != nil {
				routeCancel()
				packet.Release()
				return err
			}
			mu.Lock()
			if ctx.Err() != nil {
				mu.Unlock()
				routeCancel()
				common.Interrupt(link.Reader)
				common.Interrupt(link.Writer)
				packet.Release()
				return ctx.Err()
			}
			routes[key] = link
			mu.Unlock()
			workers.Add(1)
			go func(link *transport.Link, dest net.Destination, key string) {
				defer workers.Done()
				defer routeCancel()
				defer func() {
					mu.Lock()
					if routes[key] == link {
						delete(routes, key)
					}
					mu.Unlock()
					common.Interrupt(link.Reader)
					common.Interrupt(link.Writer)
				}()
				for {
					mb, readErr := link.Reader.ReadMultiBuffer()
					for index, b := range mb {
						source := dest
						if b.UDP != nil {
							source = *b.UDP
						}
						writeMu.Lock()
						err := writeUoTPacket(writer, request, source, b.Bytes())
						writeMu.Unlock()
						b.Release()
						if err != nil {
							buf.ReleaseMulti(mb[index+1:])
							cancel()
							return
						}
						timer.Update()
					}
					if readErr != nil {
						return
					}
				}
			}(link, dest, key)
		}
		if err := link.Writer.WriteMultiBuffer(buf.MultiBuffer{packet}); err != nil {
			// A destination can expire after lookup while other destinations keep
			// this stream active. Retire only that route. The writer owns packet
			// and may already have consumed it: never replay an ambiguous write.
			mu.Lock()
			if routes[key] == link {
				delete(routes, key)
			}
			mu.Unlock()
			common.Interrupt(link.Reader)
			common.Interrupt(link.Writer)
			if ctx.Err() != nil {
				return ctx.Err()
			}
			errors.LogDebug(ctx, "UoT destination route ended: ", err)
		}
	}
}
