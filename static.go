package main

import (
	"crypto/tls"
	"github.com/elazarl/goproxy"
	"io/ioutil"
	"os"
)

func SetMITMKeys(cert, private string) (err error) {
	cf, err := os.Open(cert)
	if err != nil {
		return
	}

	pf, err := os.Open(private)
	if err != nil {
		return
	}

	goproxy.CA_CERT, err = ioutil.ReadAll(cf)
	if err != nil {
		return
	}

	goproxy.CA_KEY, err = ioutil.ReadAll(pf)
	if err != nil {
		return
	}

	goproxy.GoproxyCa, err = tls.X509KeyPair(goproxy.CA_CERT, goproxy.CA_KEY)
	return
}
