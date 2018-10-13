package main

import (
	hdialer "github.com/mwitkow/go-http-dialer"
	"log"
	"net"
	"net/http"
	"net/url"
	"sync"
)

// A mux of in ports and out ports. One out port may have multiple in ports.
type mux struct {
	outs *sync.Map
	ins  *sync.Map
}

func NewOutPort(u *url.URL) *outport {
	dialer := hdialer.New(u)

	outboundTransport := &http.Transport{
		Dial: func(network, host string) (c net.Conn, e error) {
			c, e = dialer.Dial(network, host)
			if e != nil {
				log.Printf("exception while attempting connection to %s: %v\n", host, e)
				return
			}

			return c, e
		},
	}

	return &outport{
		o: nil,
		t: outboundTransport,
	}
}

// One outport. This port can be the outbound of many inports. Supports
// authentication
type outport struct {
	o http.RoundTripper
	t *http.Transport
}

func (o *outport) O() http.RoundTripper {
	return o.o
}

func (o *outport) T() *http.Transport {
	return o.t
}

type OP interface {
	O() http.RoundTripper
	T() *http.Transport
}
