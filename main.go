package main

import (
	"flag"
)

func main() {
	bind := flag.String("bind", "localhost:http", "bind address")
	cert := flag.String("cert", "cert.pem", "cert file")
	key := flag.String("key", "key.pem", "key file")

	flag.Parse()

	e := SetMITMKeys(*cert, *key)
	if e != nil {
		panic(e)
	}

	RunEcho(*bind)
}
