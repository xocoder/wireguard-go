/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2020 WireGuard LLC. All Rights Reserved.
 */

package tuntest

import (
	"encoding/binary"
	"io"
	"net"
	"os"

	"github.com/tailscale/wireguard-go/tun"
)

func Ping(dst, src net.IP) []byte {
	localPort := uint16(1337)
	seq := uint16(0)

	payload := make([]byte, 4)
	binary.BigEndian.PutUint16(payload[0:], localPort)
	binary.BigEndian.PutUint16(payload[2:], seq)

	return genICMPv4(payload, dst, src)
}

// Checksum is the "internet checksum" from https://tools.ietf.org/html/rfc1071.
func checksum(buf []byte, initial uint16) uint16 {
	v := uint32(initial)
	for i := 0; i < len(buf)-1; i += 2 {
		v += uint32(binary.BigEndian.Uint16(buf[i:]))
	}
	if len(buf)%2 == 1 {
		v += uint32(buf[len(buf)-1]) << 8
	}
	for v > 0xffff {
		v = (v >> 16) + (v & 0xffff)
	}
	return ^uint16(v)
}

func genICMPv4(payload []byte, dst, src net.IP) []byte {
	const (
		icmpv4ProtocolNumber = 1
		icmpv4Echo           = 8
		icmpv4ChecksumOffset = 2
		icmpv4Size           = 8
		ipv4Size             = 20
		ipv4TotalLenOffset   = 2
		ipv4ChecksumOffset   = 10
		ttl                  = 65
	)

	hdr := make([]byte, ipv4Size+icmpv4Size)

	ip := hdr[0:ipv4Size]
	icmpv4 := hdr[ipv4Size : ipv4Size+icmpv4Size]

	// https://tools.ietf.org/html/rfc792
	icmpv4[0] = icmpv4Echo // type
	icmpv4[1] = 0          // code
	chksum := ^checksum(icmpv4, checksum(payload, 0))
	binary.BigEndian.PutUint16(icmpv4[icmpv4ChecksumOffset:], chksum)

	// https://tools.ietf.org/html/rfc760 section 3.1
	length := uint16(len(hdr) + len(payload))
	ip[0] = (4 << 4) | (ipv4Size / 4)
	binary.BigEndian.PutUint16(ip[ipv4TotalLenOffset:], length)
	ip[8] = ttl
	ip[9] = icmpv4ProtocolNumber
	copy(ip[12:], src.To4())
	copy(ip[16:], dst.To4())
	chksum = ^checksum(ip[:], 0)
	binary.BigEndian.PutUint16(ip[ipv4ChecksumOffset:], chksum)

	var v []byte
	v = append(v, hdr...)
	v = append(v, payload...)
	return []byte(v)
}

// TODO(crawshaw): find a reusable home for this. package devicetest?
type ChannelTUN struct {
	Inbound  chan []byte // incoming packets, closed on TUN close
	Outbound chan []byte // outbound packets, blocks forever on TUN close

	closed chan struct{}
	events chan tun.Event
	tun    chTun
}

func NewChannelTUN() *ChannelTUN {
	c := &ChannelTUN{
		Inbound:  make(chan []byte),
		Outbound: make(chan []byte),
		closed:   make(chan struct{}),
		events:   make(chan tun.Event, 1),
	}
	c.tun.c = c
	c.events <- tun.EventUp
	return c
}

func (c *ChannelTUN) TUN() tun.Device {
	return &c.tun
}

type chTun struct {
	c *ChannelTUN
}

func (t *chTun) File() *os.File { return nil }

func (t *chTun) Read(data []byte, offset int) (int, error) {
	select {
	case <-t.c.closed:
		return 0, io.EOF // TODO(crawshaw): what is the correct error value?
	case msg := <-t.c.Outbound:
		return copy(data[offset:], msg), nil
	}
}

// Write is called by the wireguard device to deliver a packet for routing.
func (t *chTun) Write(data []byte, offset int) (int, error) {
	if offset == -1 {
		close(t.c.closed)
		close(t.c.events)
		return 0, io.EOF
	}
	msg := make([]byte, len(data)-offset)
	copy(msg, data[offset:])
	select {
	case <-t.c.closed:
		return 0, io.EOF // TODO(crawshaw): what is the correct error value?
	case t.c.Inbound <- msg:
		return len(data) - offset, nil
	}
}

const DefaultMTU = 1420

func (t *chTun) Flush() error           { return nil }
func (t *chTun) MTU() (int, error)      { return DefaultMTU, nil }
func (t *chTun) Name() (string, error)  { return "loopbackTun1", nil }
func (t *chTun) Events() chan tun.Event { return t.c.events }
func (t *chTun) Close() error {
	t.Write(nil, -1)
	return nil
}
