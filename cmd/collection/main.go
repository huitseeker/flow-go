package main

import (
	"time"

	"github.com/spf13/pflag"

	"github.com/dapperlabs/flow-go/cmd"
	"github.com/dapperlabs/flow-go/engine/collection/ingest"
	"github.com/dapperlabs/flow-go/engine/collection/proposal"
	"github.com/dapperlabs/flow-go/engine/collection/provider"
	"github.com/dapperlabs/flow-go/module"
	"github.com/dapperlabs/flow-go/module/mempool"
	"github.com/dapperlabs/flow-go/storage"
	badgerstorage "github.com/dapperlabs/flow-go/storage/badger"
)

func main() {

	var (
		pool         module.TransactionPool
		collections  storage.Collections
		guarantees   storage.Guarantees
		proposalConf proposal.Config
		providerEng  *provider.Engine
		err          error
	)

	cmd.FlowNode("collection").
		Create(func(node *cmd.FlowNodeBuilder) {
			pool, err = mempool.NewTransactionPool()
			node.MustNot(err).Msg("could not initialize transaction pool")

			collections = badgerstorage.NewCollections(node.DB)
			guarantees = badgerstorage.NewGuarantees(node.DB)
		}).
		ExtraFlags(func(flags *pflag.FlagSet) {
			flags.DurationVarP(&proposalConf.ProposalPeriod, "proposal-period", "p", time.Second*5, "period at which collections are proposed")
		}).
		Component("ingestion engine", func(node *cmd.FlowNodeBuilder) module.ReadyDoneAware {
			node.Logger.Info().Msg("initializing ingestion engine")

			eng, err := ingest.New(node.Logger, node.Network, node.State, node.Me, pool)
			node.MustNot(err).Msg("could not initialize ingestion engine")
			return eng
		}).
		Component("provider engine", func(node *cmd.FlowNodeBuilder) module.ReadyDoneAware {
			node.Logger.Info().Msg("initializing provider engine")

			providerEng, err = provider.New(node.Logger, node.Network, node.State, node.Me, collections)
			node.MustNot(err).Msg("could not initialize proposal engine")
			return providerEng
		}).
		Component("proposal engine", func(node *cmd.FlowNodeBuilder) module.ReadyDoneAware {
			node.Logger.Info().Msg("initializing proposal engine")

			eng, err := proposal.New(node.Logger, proposalConf, node.Network, node.Me, node.State, providerEng, pool, collections, guarantees)
			node.MustNot(err).Msg("could not initialize proposal engine")
			return eng
		}).
		Run()
}
