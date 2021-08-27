package client

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
	//keyFile = "./cmd/tlsdiag_ca/client/kubeedge/client.key"
	//certFile = "./cmd/tlsdiag_ca/client/kubeedge/client.crt"
	//caFile = "./cmd/tlsdiag_ca/ca-kubeedge.crt"
	keyFile  = "./cmd/tlsdiag_ca/client/client.key"
	certFile = "./cmd/tlsdiag_ca/client/client.crt"
	caFile   = "./cmd/tlsdiag_ca/ca.crt"
)

func StartClient() error {
	port := flag.Int("p", 5533, "port")
	peerIDString := flag.String("id", "Qmd8NEpx1vtmtDvG36GhbiVhX4CRiNC5y6EzDLNfMRuxNb", "peer ID")
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

	peerID, err := peer.Decode(*peerIDString)
	if err != nil {
		return err
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

	remoteAddr := fmt.Sprintf("localhost:%d", *port)
	fmt.Printf("Dialing %s\n", remoteAddr)
	conn, err := net.Dial("tcp", remoteAddr)
	if err != nil {
		fmt.Printf("net.Dial error")
		return err
	}
	fmt.Printf("Dialed raw connection to %s\n", conn.RemoteAddr())

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	sconn, err := tp.SecureOutbound(ctx, conn, peerID)

	fmt.Println("tlsdia ca client")
	if err != nil {
		return err
	}
	fmt.Println("tlsdia ca client")
	fmt.Printf("Authenticated server: %s\n", sconn.RemotePeer().Pretty())
	data, err := ioutil.ReadAll(sconn)
	if err != nil {
		fmt.Println("read all error")
		return err
	}
	fmt.Printf("Received message from server: %s\n", string(data))
	return nil
}
