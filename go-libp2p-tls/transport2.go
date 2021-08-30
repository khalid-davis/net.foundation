package libp2ptls

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"github.com/gogo/protobuf/proto"
	ci "github.com/libp2p/go-libp2p-core/crypto"
	pb "github.com/libp2p/go-libp2p-core/crypto/pb"
	"github.com/libp2p/go-libp2p-core/peer"

	"github.com/libp2p/go-libp2p-core/sec"
	"github.com/minio/sha256-simd"
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
	privKey   ci.PrivKey
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
	config, keyCh := t.caIdentity.ConfigForAny()
	cs, err := t.handshake(ctx, tls.Server(insecure, config), keyCh)
	if err != nil {
		insecure.Close()
	}
	return cs, err
}

func (t *CATransport) SecureOutbound(ctx context.Context, insecure net.Conn, p peer.ID) (sec.SecureConn, error) {
	// 这里需要设置下config.ServerName
	addr := insecure.RemoteAddr().String()
	config, keyCh := t.caIdentity.ConfigForPeer(p, addr)
	cs, err := t.handshake(ctx, tls.Client(insecure, config), keyCh)
	if err != nil {
		insecure.Close()
	}
	return cs, err
}

func (t *CATransport) handshake(
	ctx context.Context,
	tlsConn *tls.Conn,
	keyCh <-chan ci.PubKey,
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

	//Should be ready by this point, don't block.
	var remotePubKey ci.PubKey
	select {
	case remotePubKey = <-keyCh:
	default:
	}
	if remotePubKey == nil {
		return nil, errors.New("go-libp2p-tls BUG: expected remote pub key to be set")
	}

	conn, err := t.setupConn(tlsConn, remotePubKey)
	if err != nil {
		// if the context was canceled, return the context error
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, ctxErr
		}
		return nil, err
	}
	fmt.Println("remoteAddr: ", conn.RemoteAddr())
	return conn, nil
}

func (t *CATransport) setupConn(tlsConn *tls.Conn, remotePubKey ci.PubKey) (sec.SecureConn, error) {
	remotePeerID, err := peer.IDFromPublicKey(remotePubKey)
	if err != nil {
		return nil, err
	}
	fmt.Println("remotePeer: ", remotePeerID)
	return &conn{
		Conn:      tlsConn,
		localPeer: t.localPeer,
		privKey:   t.privKey,
		remotePeer:   remotePeerID,
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
			ClientCAs:  certPoll,
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
	conf.VerifyPeerCertificate = func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		defer close(keyCh)

		chain := make([]*x509.Certificate, len(rawCerts))
		for i := 0; i < len(rawCerts); i++ {
			cert, err := x509.ParseCertificate(rawCerts[i])
			if err != nil {
				return err
			}
			chain[i] = cert
		}

		//pubKey, err := PubKeyFromCertChain(chain)
		// todo kubeedge里面是ecdsapublic
		//rsaPublicKey := chain[0].PublicKey.(*ecdsa.PublicKey)
		tmp := chain[0].PublicKey.(*rsa.PublicKey)
		pubKey := &RsaPublicKey{
			k: *tmp,
		}
		//if err != nil {
		//	return err
		//}
		if remote != "" && !remote.MatchesPublicKey(pubKey) {
			peerID, err := peer.IDFromPublicKey(pubKey)
			if err != nil {
				peerID = peer.ID(fmt.Sprintf("(not determined: %s)", err.Error()))
			}
			return fmt.Errorf("peer IDs don't match: expected %s, got %s", remote, peerID)
		}
		keyCh <- pubKey
		return nil
	}
	return conf, keyCh
}

// RsaPublicKey is an rsa public key
type RsaPublicKey struct {
	k rsa.PublicKey
}

// Verify compares a signature against input data
func (pk *RsaPublicKey) Verify(data, sig []byte) (bool, error) {
	hashed := sha256.Sum256(data)
	err := rsa.VerifyPKCS1v15(&pk.k, crypto.SHA256, hashed[:], sig)
	if err != nil {
		return false, err
	}
	return true, nil
}

func (pk *RsaPublicKey) Type() pb.KeyType {
	return pb.KeyType_RSA
}

// Bytes returns protobuf bytes of a public key
func (pk *RsaPublicKey) Bytes() ([]byte, error) {
	return MarshalPublicKey(pk)
}

func (pk *RsaPublicKey) Raw() ([]byte, error) {
	return x509.MarshalPKIXPublicKey(&pk.k)
}

// Equals checks whether this key is equal to another
func (pk *RsaPublicKey) Equals(k ci.Key) bool {
	// make sure this is an rsa public key
	other, ok := (k).(*RsaPublicKey)
	if !ok {
		return basicEquals(pk, k)
	}

	return pk.k.N.Cmp(other.k.N) == 0 && pk.k.E == other.k.E
}

func basicEquals(k1, k2 ci.Key) bool {
	if k1.Type() != k2.Type() {
		return false
	}

	a, err := k1.Raw()
	if err != nil {
		return false
	}
	b, err := k2.Raw()
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare(a, b) == 1
}

// MarshalPublicKey converts a public key object into a protobuf serialized
// public key
func MarshalPublicKey(k ci.PubKey) ([]byte, error) {
	pbmes, err := PublicKeyToProto(k)
	if err != nil {
		return nil, err
	}

	return proto.Marshal(pbmes)
}

// PublicKeyToProto converts a public key object into an unserialized
// protobuf PublicKey message.
func PublicKeyToProto(k ci.PubKey) (*pb.PublicKey, error) {
	pbmes := new(pb.PublicKey)
	pbmes.Type = k.Type()
	data, err := k.Raw()
	if err != nil {
		return nil, err
	}
	pbmes.Data = data
	return pbmes, nil
}
