package main

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"github.com/elazarl/goproxy"
	"log"
	"net"
	"net/http"
	"strings"
)

type AuthHandler func(*http.Request) bool

func NoAuth(h *http.Request) bool {
	return true
}

func parseBasicAuth(auth string) (username, password string, ok bool) {
	const prefix = "Basic "
	if !strings.HasPrefix(auth, prefix) {
		return
	}
	c, err := base64.StdEncoding.DecodeString(auth[len(prefix):])
	if err != nil {
		return
	}
	cs := string(c)
	s := strings.IndexByte(cs, ':')
	if s < 0 {
		return
	}
	return cs[:s], cs[s+1:], true
}

func UPwAuth(auth map[string][sha256.Size]byte) AuthHandler {
	return func(h *http.Request) bool {
		a := h.Header.Get("Proxy-Authorization")
		if a == "" {
			return false
		}

		user, pass, ok := parseBasicAuth(a)
		if !ok {
			return false
		}

		sha, ok := auth[user]
		if !ok {
			return false
		}
		passhash := sha256.Sum256([]byte(pass))
		return subtle.ConstantTimeCompare(sha[:], passhash[:]) == 1
	}
}

// One inport. This must be bound to exactly one outport. Supports
// authentication and useragent rewriting
type inport struct {
	target OP
	auth   AuthHandler
	doMitm bool
	uaMitm *string

	s *http.Server
}

func (i *inport) CreateHandler() http.Handler {
	proxy := goproxy.NewProxyHttpServer()
	proxy.Tr = i.target.T()

	// Handle HTTPS MITM
	proxy.OnRequest().HandleConnectFunc(func(host string, ctx *goproxy.ProxyCtx) (*goproxy.ConnectAction, string) {
		if i.doMitm {
			return goproxy.HTTPMitmConnect, host
		} else {
			return goproxy.OkConnect, host
		}
	})

	// Handle authentication
	proxy.OnRequest().DoFunc(func(r *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
		if !i.auth(r) {
			resp := goproxy.NewResponse(r, "text/plain", 403, "Forbidden")
			return r, resp
		}

		if i.doMitm {
			r.Header.Set("User-Agent", *i.uaMitm)
		}

		if i.target.O() != nil {
			resp, err := i.target.O().RoundTrip(r)
			if err != nil {
				return r, nil
			}
			return r, resp
		}

		return r, nil
	})

	return proxy
}

func (i *inport) Start(addr string) (bind net.Addr, e error) {
	l, e := net.Listen("tcp", addr)
	if e != nil {
		return
	}

	if i.s == nil {
		i.s = &http.Server{
			Handler: i.CreateHandler(),
		}
	}

	go func() {
		defer l.Close()
		err := i.s.Serve(l)
		if err != http.ErrServerClosed {
			log.Printf("Proxy %s server closed with unusual error: %v\n", addr, err)
		}
	}()

	return l.Addr(), nil
}

func (i *inport) Close() error {
	if i.s != nil {
		return i.s.Close()
	}
	return nil
}
