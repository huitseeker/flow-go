package p2p

import (
	"context"
	"strings"
	"sync"

	"github.com/libp2p/go-libp2p-core/peer"
	pubsub "github.com/libp2p/go-libp2p-pubsub"

	"github.com/rs/zerolog"

	"github.com/onflow/flow-go/crypto"
	"github.com/onflow/flow-go/module"
	"github.com/onflow/flow-go/network/message"
	_ "github.com/onflow/flow-go/utils/binstat"
)

// readSubscription reads the messages coming in on the subscription and calls the given callback until
// the context of the subscription is cancelled. Additionally, it reports metrics
type readSubscription struct {
	ctx      context.Context
	log      zerolog.Logger
	sub      *pubsub.Subscription
	metrics  module.NetworkMetrics
	callback func(msg *message.Message, pubKey crypto.PublicKey)
}

// newReadSubscription reads the messages coming in on the subscription
func newReadSubscription(ctx context.Context,
	sub *pubsub.Subscription,
	callback func(msg *message.Message, pubKey crypto.PublicKey),
	log zerolog.Logger,
	metrics module.NetworkMetrics) *readSubscription {

	log = log.With().
		Str("channel", sub.Topic()).
		Logger()

	r := readSubscription{
		ctx:      ctx,
		log:      log,
		sub:      sub,
		callback: callback,
		metrics:  metrics,
	}

	return &r
}

// receiveLoop must be run in a goroutine. It continuously receives
// messages for the topic and calls the callback synchronously
func (r *readSubscription) receiveLoop(wg *sync.WaitGroup) {

	defer wg.Done()
	defer r.log.Debug().Msg("exiting receive routine")

	for {

		// read the next message from libp2p's subscription (blocking call)
		rawMsg, err := r.sub.Next(r.ctx)

		if err != nil {

			// middleware may have cancelled the context
			if err == context.Canceled {
				return
			}

			// subscription may have just been cancelled if node is being stopped or the topic has been unsubscribed,
			// don't log error in that case
			// (https://github.com/ipsn/go-ipfs/blob/master/gxlibs/github.com/libp2p/go-libp2p-pubsub/pubsub.go#L435)
			if strings.Contains(err.Error(), "subscription cancelled") {
				return
			}

			// log any other error
			r.log.Err(err).Msg("failed to read subscription message")

			return
		}

		var msg message.Message
		// convert the incoming raw message payload to Message type
		//bs := binstat.EnterTimeVal(binstat.BinNet+":wire>1protobuf2message", int64(len(rawMsg.Data)))
		err = msg.Unmarshal(rawMsg.Data)
		//binstat.Leave(bs)
		if err != nil {
			r.log.Err(err).Str("topic_message", msg.String()).Msg("failed to unmarshal message")
			return
		}

		// if pubsub.WithMessageSigning(true) and pubsub.WithStrictSignatureVerification(true),
		// the emitter is authenticated
		emitter, err := peer.IDFromBytes(rawMsg.From)
		if err != nil {
			r.log.Err(err).Msgf("failed to unmarshal peerID %v of a message", rawMsg.From)
			return
		}
		// we use ECDSA, so the PeerID should be an identity mutlihash and this should succeed
		pk, err := emitter.ExtractPublicKey()
		if err != nil {
			r.log.Err(err).Msgf("failed to extract public key of peerID %v", emitter.String())
			return
		}
		flowKey, err := PublicKeyFromNetwork(pk)
		if err != nil {
			r.log.Err(err).Msgf("failed to extract flow public key of libp2p key %v", err)
			return
		}

		// log metrics
		r.metrics.NetworkMessageReceived(msg.Size(), msg.ChannelID, msg.Type)

		// call the callback
		r.callback(&msg, flowKey)
	}
}
