package libp2ptls

import (
	"crypto/tls"
	"fmt"

	ci "github.com/libp2p/go-libp2p-core/crypto"
	"github.com/libp2p/go-libp2p-core/peer"
	"github.com/libp2p/go-libp2p-core/sec"
)

type conn struct {
	*tls.Conn

	localPeer peer.ID
	privKey   ci.PrivKey

	remotePeer   peer.ID
	remotePubKey ci.PubKey
}

var _ sec.SecureConn = &conn{}

func (c *conn) LocalPeer() peer.ID {
	return c.localPeer
}

func (c *conn) LocalPrivateKey() ci.PrivKey {
	return c.privKey
}

//
func (c *conn) RemotePeer() peer.ID {
	return c.remotePeer
}

// RemotePublicKey 这个东西暂时拿不到, ci.PubKey不具备中途构造的能力，所以就自己实现一个
func (c *conn) RemotePublicKey() ci.PubKey {
	return c.remotePubKey
}

func (c *conn) String() string {
	out := fmt.Sprintf("Remote Peer ID: %s \n", c.RemotePeer())
	out += fmt.Sprintf("Remote Peer Addr: %s \n", c.RemoteAddr())
	return out
}