package main

import (
	"fmt"
	"github.com/libp2p/go-libp2p-tls-ca/cmd/tlsdiag_ca/client"
	"github.com/libp2p/go-libp2p-tls-ca/cmd/tlsdiag_ca/server"
	"os"
)

func main() {
	if len(os.Args) <= 1 {
		fmt.Println("missing argument: client / server")
		return
	}

	role := os.Args[1]
	// remove the role argument from os.Args
	os.Args = append([]string{os.Args[0]}, os.Args[2:]...)

	var err error
	switch role {
	case "client":
		//err = tlsdiag.StartClient()
		err = client.StartClient()
	case "server":
		//err = tlsdiag.StartServer()
		err = server.StartServer()
	default:
		fmt.Println("invalid argument. Expected client / server")
		return
	}
	if err != nil {
		panic(err)
	}
}
