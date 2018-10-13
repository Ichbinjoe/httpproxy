package main

import (
	"crypto/sha256"
	"github.com/labstack/echo"
	"github.com/labstack/echo/middleware"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync"
)

var M *mux = &mux{
	outs: &sync.Map{},
	ins:  &sync.Map{},
}

func RunEcho(listen string) {
	E := echo.New()

	E.Use(middleware.Logger())
	E.Use(middleware.Recover())

	E.PUT("/inport", AddInPort)
	E.DELETE("/inport", DelInPort)

	E.PUT("/outport", AddOutPort)
	E.DELETE("/outport", DelOutPort)

	E.POST("/reset", ResetServer)

	E.Logger.Fatal(E.Start(listen))
}

type Resp struct {
	Status string `json:"status"`
}

type Error struct {
	Resp
	Error string `json:"error"`
}

type InportCreate struct {
	Resp
	Bind string `json:"bind"`
}

func SendOk(c echo.Context) error {
	return c.JSON(http.StatusOK, Resp{Status: "ok"})
}

func SendError(c echo.Context, err string) error {
	return c.JSON(http.StatusInternalServerError, &Error{
		Resp: Resp{
			Status: "error",
		},
		Error: err,
	})
}

func SendInportCreate(c echo.Context, bind string) error {
	return c.JSON(http.StatusOK, &InportCreate{
		Resp: Resp{
			Status: "ok",
		},
		Bind: bind,
	})
}

func SendBadReq(c echo.Context, msg string) error {
	return c.JSON(http.StatusBadRequest, &Error{
		Resp: Resp{
			Status: "badreq",
		},
		Error: msg,
	})
}

func DelInPort(c echo.Context) error {
	ipn := c.QueryParam("port")
	if ipn == "" {
		return SendBadReq(c, "missing port param")
	}

	p, ok := M.ins.Load(ipn)
	if !ok {
		return SendBadReq(c, "port does not exist")
	}

	M.ins.Delete(ipn)
	err := p.(io.Closer).Close()
	if err != nil {
		c.Logger().Errorf("Error logged when closing port %s: %v\n", ipn, err)
	}

	return SendOk(c)
}

func AddInPort(c echo.Context) error {
	outport := c.QueryParam("outport")     // required
	name := c.QueryParam("name")           // required
	bindscope := c.QueryParam("bindscope") // required
	uamitm := c.QueryParam("useragent")    // optional
	auth := c.QueryParam("auth")           // optional - user:pass;user:pass

	if name == "" {
		return SendBadReq(c, "missing name")
	}

	if outport == "" {
		return SendBadReq(c, "missing port param")
	}

	if bindscope == "" {
		return SendBadReq(c, "missing bindscope")
	}

	op, ok := M.outs.Load(outport)
	if !ok {
		return SendBadReq(c, "outport does not exist")
	}

	_, exist := M.ins.Load(name)
	if exist {
		return SendBadReq(c, "inport already exists")
	}

	var ah AuthHandler
	if auth == "" {
		ah = NoAuth
	} else {
		at := make(map[string][sha256.Size]byte)
		accts := strings.Split(auth, ";")
		for _, a := range accts {
			up := strings.Split(a, ":")
			if len(up) != 2 {
				return SendBadReq(c, "Bad acct format")
			}
			at[up[0]] = sha256.Sum256([]byte(up[1]))
		}
		ah = UPwAuth(at)
	}

	i := &inport{
		target: op.(OP),
		auth:   ah,
		doMitm: uamitm != "",
		uaMitm: &uamitm,
	}

	bind, err := i.Start(bindscope)
	if err != nil {
		defer i.Close()
		log.Printf("Inport '%s' failed to start with error: %v\n", name, err)
		return SendError(c, "failed to start inport!")
	}
	M.ins.Store(name, i)

	return SendInportCreate(c, bind.String())
}

func AddOutPort(c echo.Context) error {
	name := c.QueryParam("name")
	tgt := c.QueryParam("url")

	if name == "" {
		return SendBadReq(c, "name missing")
	}

	if tgt == "" {
		return SendBadReq(c, "url missing")
	}

	_, ok := M.outs.Load(name)
	if ok {
		return SendBadReq(c, "out port already exists with name")
	}

	u, e := url.Parse(tgt)

	if e != nil {
		return SendBadReq(c, "error parsing url: "+e.Error())
	}

	op := NewOutPort(u)
	M.outs.Store(name, op)

	return SendOk(c)
}

func DelOutPort(c echo.Context) error {
	name := c.QueryParam("name")

	if name == "" {
		return SendBadReq(c, "name missing")
	}

	_, ok := M.outs.Load(name)
	if !ok {
		return SendBadReq(c, "outport doesn't exist")
	}

	M.outs.Delete(name)
	return SendOk(c)
}

func ResetServer(c echo.Context) error {
	M.ins.Range(func(_, v interface{}) bool {
		e := v.(io.Closer).Close()
		if e != nil {
			c.Logger().Errorf("Error occurred when closing inport: %v\n", e)
		}
		return true
	})

	M.ins = &sync.Map{}
	M.outs = &sync.Map{}
	return SendOk(c)
}
