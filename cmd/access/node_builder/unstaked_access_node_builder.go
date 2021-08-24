package node_builder

import (
	"context"
	"errors"

	"github.com/libp2p/go-libp2p-core/peer"

	"github.com/onflow/flow-go/cmd"
	"github.com/onflow/flow-go/engine"
	"github.com/onflow/flow-go/model/flow"
	"github.com/onflow/flow-go/module"
	"github.com/onflow/flow-go/module/id"
	"github.com/onflow/flow-go/module/local"
	"github.com/onflow/flow-go/module/metrics"
	"github.com/onflow/flow-go/network/converter"
	"github.com/onflow/flow-go/network/p2p"
	"github.com/onflow/flow-go/state/protocol/events/gadgets"
)

type UnstakedAccessNodeBuilder struct {
	*FlowAccessNodeBuilder
}

func NewUnstakedAccessNodeBuilder(anb *FlowAccessNodeBuilder) *UnstakedAccessNodeBuilder {
	return &UnstakedAccessNodeBuilder{
		FlowAccessNodeBuilder: anb,
	}
}

func (anb *UnstakedAccessNodeBuilder) initNodeInfo() {
	// use the networking key that has been passed in the config
	networkingKey := anb.AccessNodeConfig.NetworkKey
	pubKey, err := p2p.LibP2PPublicKeyFromFlow(networkingKey.PublicKey())
	anb.MustNot(err)
	peerID, err := peer.IDFromPublicKey(pubKey)
	anb.MustNot(err)
	anb.NodeID, err = p2p.NewUnstakedNetworkIDTranslator().GetFlowID(peerID)
	anb.MustNot(err)
	anb.NodeConfig.NetworkKey = networkingKey // copy the key to NodeConfig
	anb.NodeConfig.StakingKey = nil           // no staking key for the unstaked node
}

func (anb *UnstakedAccessNodeBuilder) InitIDProviders() {
	anb.Module("id providers", func(builder cmd.NodeBuilder, node *cmd.NodeConfig) error {
		idCache, err := p2p.NewProtocolStateIDCache(node.Logger, node.State, anb.ProtocolEvents)
		if err != nil {
			return err
		}

		anb.IdentityProvider = idCache

		anb.IDTranslator = p2p.NewHierarchicalIDTranslator(idCache, p2p.NewUnstakedNetworkIDTranslator())

		return nil
	})
}

func (anb *UnstakedAccessNodeBuilder) Initialize() cmd.NodeBuilder {

	ctx, cancel := context.WithCancel(context.Background())
	anb.Cancel = cancel

	anb.validateParams()

	// if a network key has been passed in the init node info here
	if anb.AccessNodeConfig.NetworkKey != nil {
		anb.initNodeInfo()
	}

	anb.InitIDProviders()

	anb.enqueueMiddleware(ctx)

	anb.enqueueUnstakedNetworkInit(ctx)

	anb.enqueueConnectWithStakedAN()

	anb.PreInit(anb.initUnstakedLocal())

	return anb
}

func (anb *UnstakedAccessNodeBuilder) validateParams() {
	if len(anb.bootstrapNodeAddresses) != len(anb.bootstrapNodePublicKeys) {
		anb.Logger.Fatal().Msg("number of bootstrap node addresses and public keys should match")
	}
}

// initUnstakedLocal initializes the unstaked node ID, network key and network address
// Currently, it reads a node-info.priv.json like any other node.
// TODO: read the node ID from the special bootstrap files
func (anb *UnstakedAccessNodeBuilder) initUnstakedLocal() func(builder cmd.NodeBuilder, node *cmd.NodeConfig) {
	return func(_ cmd.NodeBuilder, node *cmd.NodeConfig) {
		// for an unstaked node, set the identity here explicitly since it will not be found in the protocol state
		self := &flow.Identity{
			NodeID:        node.NodeID,
			NetworkPubKey: node.NetworkKey.PublicKey(),
			StakingPubKey: nil,             // no staking key needed for the unstaked node
			Role:          flow.RoleAccess, // unstaked node can only run as an access node
			Address:       anb.BindAddr,
		}

		me, err := local.New(self, nil)
		anb.MustNot(err).Msg("could not initialize local")
		node.Me = me
	}
}

// enqueueMiddleware enqueues the creation of the network middleware
// this needs to be done before sync engine participants module
func (anb *UnstakedAccessNodeBuilder) enqueueMiddleware(ctx context.Context) {
	anb.
		Module("network middleware", func(_ cmd.NodeBuilder, node *cmd.NodeConfig) error {

			// NodeID for the unstaked node on the unstaked network
			unstakedNodeID := node.NodeID

			// Networking key
			unstakedNetworkKey := node.NetworkKey

			// Network Metrics
			// for now we use the empty metrics NoopCollector till we have defined the new unstaked network metrics
			unstakedNetworkMetrics := metrics.NewNoopCollector()

			libP2PFactory, err := anb.initLibP2PFactory(ctx, unstakedNodeID, unstakedNetworkKey)
			anb.MustNot(err)

			msgValidators := unstakedNetworkMsgValidators(node.Logger, node.IdentityProvider, unstakedNodeID)

			anb.initMiddleware(unstakedNodeID, unstakedNetworkMetrics, libP2PFactory, msgValidators...)

			return nil
		})
}

// Build enqueues the sync engine and the follower engine for the unstaked access node.
// Currently, the unstaked AN only runs the follower engine.
func (anb *UnstakedAccessNodeBuilder) Build() AccessNodeBuilder {
	anb.
		Module("sync engine participants provider", func(_ cmd.NodeBuilder, node *cmd.NodeConfig) error {
			middleware, ok := anb.Middleware.(*p2p.Middleware)
			if !ok {
				return errors.New("middleware was of unexpected type")
			}
			// use the default identifier provider
			anb.SyncEngineParticipantsProviderFactory = func() id.IdentifierProvider { return middleware.IdentifierProvider() }
			return nil
		})

	anb.FlowAccessNodeBuilder.BuildConsensusFollower()
	return anb
}

// enqueueUnstakedNetworkInit enqueues the unstaked network component initialized for the unstaked node
func (anb *UnstakedAccessNodeBuilder) enqueueUnstakedNetworkInit(ctx context.Context) {

	anb.Component("unstaked network", func(_ cmd.NodeBuilder, node *cmd.NodeConfig) (module.ReadyDoneAware, error) {

		// Network Metrics
		// for now we use the empty metrics NoopCollector till we have defined the new unstaked network metrics
		unstakedNetworkMetrics := metrics.NewNoopCollector()


		subscriptionManager := converter.NewSubscriptionManager(p2p.NewChannelSubscriptionManager(middleware), engine.SyncCommittee, engine.UnstakedSyncCommittee)

		// topology is nil since its automatically managed by libp2p
		network, err := anb.initNetwork(builder.Me, unstakedNetworkMetrics, middleware, nil, subscriptionManager)
		anb.MustNot(err)

		anb.Logger.Info().Msgf("network will run on address: %s", anb.BindAddr)

		idEvents := gadgets.NewIdentityDeltas(anb.Middleware.UpdateNodeAddresses)
		anb.ProtocolEvents.AddConsumer(idEvents)

		return anb.Network, err
	})
}

// enqueueConnectWithStakedAN enqueues the upstream connector component which connects the libp2p host of the unstaked
// AN with the staked AN.
// Currently, there is an issue with LibP2P stopping advertisements of subscribed topics if no peers are connected
// (https://github.com/libp2p/go-libp2p-pubsub/issues/442). This means that an unstaked AN could end up not being
// discovered by other unstaked ANs if it subscribes to a topic before connecting to the staked AN. Hence, the need
// of an explicit connect to the staked AN before the node attempts to subscribe to topics.
func (anb *UnstakedAccessNodeBuilder) enqueueConnectWithStakedAN() {
	anb.Component("upstream connector", func(_ cmd.NodeBuilder, _ *cmd.NodeConfig) (module.ReadyDoneAware, error) {
		return newUpstreamConnector(anb.bootstrapIdentities, anb.LibP2PNode, anb.Logger), nil
	})
}
