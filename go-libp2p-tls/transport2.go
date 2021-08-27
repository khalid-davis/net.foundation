package libp2ptls

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	ci "github.com/libp2p/go-libp2p-core/crypto"
	"github.com/libp2p/go-libp2p-core/peer"
	"github.com/libp2p/go-libp2p-core/sec"
	"io/ioutil"
	"log"
	"net"
	"strings"
	"sync"
)

const CAID = "/tls/1.0.1"

type CATransport struct {
	caIdentity *CAIdentity

	localPeer peer.ID
	privKey ci.PrivKey
}

func CANew(key ci.PrivKey, certFile, keyFile, caFile string) (*CATransport, error) {
	id, err := peer.IDFromPrivateKey(key)
	if err != nil {
		return nil, err
	}
	t := &CATransport{
		localPeer: id,
		privKey:   key,
	}

	var cert tls.Certificate
	cert, err = tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		log.Println(err)
		return nil, err
	}

	var clientCertPool *x509.CertPool
	caCertBytes, err := ioutil.ReadFile(caFile)
	if err != nil {
		panic("unable to read client.pem")
	}
	clientCertPool = x509.NewCertPool()
	ok := clientCertPool.AppendCertsFromPEM(caCertBytes)
	if !ok {
		panic("failed to parse root certificate")
	}

	identity, err := NewCAIdentity(cert, clientCertPool)
	if err != nil {
		return nil, err
	}
	t.caIdentity = identity
	return t, nil
}

// SecureInbound runs the TLS handshake as a server.
func (t *CATransport) SecureInbound(ctx context.Context, insecure net.Conn) (sec.SecureConn, error) {
	config, _ := t.caIdentity.ConfigForAny()
	cs, err := t.handshake(ctx, tls.Server(insecure, config))
	if err != nil {
		insecure.Close()
	}
	return cs, err
}


func (t *CATransport) SecureOutbound(ctx context.Context, insecure net.Conn, p peer.ID) (sec.SecureConn, error) {
	// 这里需要设置下config.ServerName
	addr := insecure.RemoteAddr().String()
	config, _:= t.caIdentity.ConfigForPeer(p, addr)
	cs, err := t.handshake(ctx, tls.Client(insecure, config))
	if err != nil {
		insecure.Close()
	}
	return cs, err
}


func (t *CATransport) handshake(
	ctx context.Context,
	tlsConn *tls.Conn,
) (sec.SecureConn, error) {
	// There's no way to pass a context to tls.Conn.Handshake().
	// See https://github.com/golang/go/issues/18482.
	// Close the connection instead.
	select {
	case <-ctx.Done():
		tlsConn.Close()
	default:
	}

	done := make(chan struct{})
	var wg sync.WaitGroup

	// Ensure that we do not return before
	// either being done or having a context
	// cancellation.
	defer wg.Wait()
	defer close(done)

	wg.Add(1)
	go func() {
		defer wg.Done()
		select {
		case <-done:
		case <-ctx.Done():
			tlsConn.Close()
		}
	}()

	if err := tlsConn.Handshake(); err != nil {
		// if the context was canceled, return the context error
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, ctxErr
		}
		return nil, err
	}

	// Should be ready by this point, don't block.
	//var remotePubKey ci.PubKey
	//select {
	//case remotePubKey = <-keyCh:
	//default:
	//}
	//if remotePubKey == nil {
	//	return nil, errors.New("go-libp2p-tls BUG: expected remote pub key to be set")
	//}

	conn, err := t.setupConn(tlsConn, nil)
	if err != nil {
		// if the context was canceled, return the context error
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, ctxErr
		}
		return nil, err
	}
	return conn, nil
}

func (t *CATransport) setupConn(tlsConn *tls.Conn, remotePubKey ci.PubKey) (sec.SecureConn, error) {
	//remotePeerID, err := peer.IDFromPublicKey(remotePubKey)
	//if err != nil {
	//	return nil, err
	//}
	return &conn{
		Conn:         tlsConn,
		localPeer:    t.localPeer,
		privKey:      t.privKey,
		//remotePeer:   remotePeerID,
		remotePubKey: remotePubKey,
	}, nil
}


// CAIdentity ---------------
type CAIdentity struct {
	config tls.Config
}

func NewCAIdentity(cert tls.Certificate, certPoll *x509.CertPool) (*CAIdentity, error) {
	return &CAIdentity{
		config: tls.Config{
			Certificates: []tls.Certificate{cert},
			//ServerName: "127.0.0.1", // 原本的tls里面是判断为空会去填充
			//InsecureSkipVerify: true,
			// for server
			ClientAuth: tls.RequireAndVerifyClientCert,
			ClientCAs: certPoll,
			// for client
			RootCAs: certPoll,
		},
	}, nil
}

func (i *CAIdentity) ConfigForAny() (*tls.Config, <-chan ci.PubKey) {
	return i.ConfigForPeer("", "")
}

func (i *CAIdentity) ConfigForPeer(remote peer.ID, addr string) (*tls.Config, <-chan ci.PubKey) {


	keyCh := make(chan ci.PubKey, 1)
	// We need to check the peer ID in the VerifyPeerCertificate callback.
	// The tls.Config it is also used for listening, and we might also have concurrent dials.
	// Clone it so we can check for the specific peer ID we're dialing here.
	conf := i.config.Clone()

	fmt.Println("addr: ", addr)

	// set the server name
	if addr != "" {
		colonPos := strings.LastIndex(addr, ":")
		if colonPos == -1 {
			colonPos = len(addr)
		}
		hostname := addr[:colonPos]

		// If no ServerName is set, infer the ServerName
		// from the hostname we're connecting to.
		if conf.ServerName == "" {
			conf.ServerName = hostname
		}
	}

	// We're using InsecureSkipVerify, so the verifiedChains parameter will always be empty.
	// We need to parse the certificates ourselves from the raw certs.
	//conf.VerifyPeerCertificate = func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
	//	defer close(keyCh)
	//
	//	chain := make([]*x509.Certificate, len(rawCerts))
	//	for i := 0; i < len(rawCerts); i++ {
	//		cert, err := x509.ParseCertificate(rawCerts[i])
	//		if err != nil {
	//			return err
	//		}
	//		chain[i] = cert
	//	}
	//
	//	pubKey, err := PubKeyFromCertChain(chain)
	//	if err != nil {
	//		return err
	//	}
	//	if remote != "" && !remote.MatchesPublicKey(pubKey) {
	//		peerID, err := peer.IDFromPublicKey(pubKey)
	//		if err != nil {
	//			peerID = peer.ID(fmt.Sprintf("(not determined: %s)", err.Error()))
	//		}
	//		return fmt.Errorf("peer IDs don't match: expected %s, got %s", remote, peerID)
	//	}
	//	keyCh <- pubKey
	//	return nil
	//}
	return conf, keyCh
}
