package authorizer

import (
	"context"

	"github.com/anyproto/any-sync/app"
	"github.com/anyproto/any-sync/net/peer"
	"github.com/anyproto/any-sync/net/secureservice/handshake"
	"github.com/anyproto/any-sync/nodeconf"
	"storj.io/drpc"
)

const CName = "common.rpc.authorizer"

type RpcAuthorizer interface {
	app.Component
	// WrapDRPCHandler wraps the given drpc.Handler with additional functionality
	WrapDRPCHandler(handler drpc.Handler) drpc.Handler
}

func New() RpcAuthorizer {
	return &authorizer{}
}

type authorizer struct {
	drpc.Handler

	cfg Config
}

func (a authorizer) Name() string {
	return CName
}

func (a *authorizer) Init(app *app.App) error {
	a.cfg = app.MustComponent("config").(ConfigGetter).GetAuthorizerConf()

	nodeConf := app.MustComponent(nodeconf.CName).(nodeconf.NodeConf)
	for _, node := range nodeConf.Configuration().Nodes {
		a.cfg.AllowedNodePeerIds[node.PeerId] = struct{}{}
	}

	return nil
}

func (a authorizer) WrapDRPCHandler(h drpc.Handler) drpc.Handler {
	a.Handler = h
	return a
}

func (a authorizer) HandleRPC(stream drpc.Stream, rpc string) (err error) {
	ctx := stream.Context()
	if err = a.validateAllowList(ctx); err != nil {
		return
	}

	return a.Handler.HandleRPC(stream, rpc)
}

func (a authorizer) validateAllowList(ctx context.Context) (err error) {
	err = nil

	if a.cfg.AllowedNodePeerIds == nil || a.cfg.AllowedAccountpubKeys == nil {
		return
	}

	pubKey, err := peer.CtxPubKey(ctx)
	if err != nil {
		return
	}
	peerId, err := peer.CtxPeerId(ctx)
	if err != nil {
		return
	}

	_, ok := a.cfg.AllowedNodePeerIds[peerId]
	if !ok {
		err = handshake.ErrInvalidCredentials
		return
	}

	var raw []byte
	raw, err = pubKey.Raw()
	_, ok = a.cfg.AllowedAccountpubKeys[[32]byte(raw)]
	if !ok {
		err = handshake.ErrInvalidCredentials
		return
	}

	return
}
