package server

import (
	"context"
	"encoding/pem"
	"flag"
	"fmt"
	"github.com/libp2p/go-libp2p-core/crypto"
	"io/ioutil"
	"log"
	"net"
	"time"

	"github.com/libp2p/go-libp2p-core/peer"
	libp2ptls "github.com/libp2p/go-libp2p-tls"
)

const (
	//keyFile = "./cmd/tlsdiag_ca/server/kubeedge/server.key"
	//certFile = "./cmd/tlsdiag_ca/server/kubeedge/server.crt"
	//caFile = "./cmd/tlsdiag_ca/ca-kubeedge.crt"
	keyFile  = "./cmd/tlsdiag_ca/server/server.key"
	certFile = "./cmd/tlsdiag_ca/server/server.crt"
	caFile   = "./cmd/tlsdiag_ca/ca.crt"
)

func StartServer() error {
	port := flag.Int("p", 5533, "port")
	//keyType := flag.String("key", "ecdsa", "rsa, ecdsa, ed25519 or secp256k1")
	flag.Parse()

	certBytes, err := ioutil.ReadFile(keyFile)
	if err != nil {
		log.Println("unable to read client.pem, error: ", err)
		return err
	}
	block, _ := pem.Decode(certBytes)

	//priv, err := crypto.UnmarshalECDSAPrivateKey(block.Bytes)
	priv, err := crypto.UnmarshalRsaPrivateKey(block.Bytes)
	if err != nil {
		panic(err)
	}

	id, err := peer.IDFromPrivateKey(priv)
	if err != nil {
		return err
	}
	fmt.Printf(" Peer ID: %s\n", id.Pretty())
	tp, err := libp2ptls.CANew(priv, certFile, keyFile, caFile)
	if err != nil {
		return err
	}

	ln, err := net.Listen("tcp", fmt.Sprintf("localhost:%d", *port))
	if err != nil {
		return err
	}
	fmt.Printf("Listening for new connections on %s\n", ln.Addr())
	fmt.Printf("Now run the following command in a separate terminal:\n")
	fmt.Printf("\tgo run cmd/tlsdiag.go client -p %d -id %s\n", *port, id.Pretty())

	for {
		conn, err := ln.Accept()
		if err != nil {
			return err
		}
		fmt.Printf("Accepted raw connection from %s\n", conn.RemoteAddr())
		go func() {
			if err := handleConn(tp, conn); err != nil {
				fmt.Printf("Error handling connection from %s: %s\n", conn.RemoteAddr(), err)
			}
		}()
	}
}

func handleConn(tp *libp2ptls.CATransport, conn net.Conn) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	sconn, err := tp.SecureInbound(ctx, conn)
	if err != nil {
		return err
	}
	fmt.Printf("Authenticated client: %s\n", sconn.RemotePeer().Pretty())
	fmt.Fprintf(sconn, "Hello client!")
	fmt.Printf("Closing connection to %s\n", conn.RemoteAddr())
	return sconn.Close()
}
