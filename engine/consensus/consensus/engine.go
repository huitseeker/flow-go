// (c) 2019 Dapper Labs - ALL RIGHTS RESERVED

package consensus

import (
	"errors"
	"fmt"
	"math/rand"

	"github.com/hashicorp/go-multierror"
	"github.com/rs/zerolog"

	"github.com/dapperlabs/flow-go/crypto"
	"github.com/dapperlabs/flow-go/engine"
	model "github.com/dapperlabs/flow-go/model/coldstuff"
	"github.com/dapperlabs/flow-go/model/flow"
	"github.com/dapperlabs/flow-go/model/flow/filter"
	"github.com/dapperlabs/flow-go/model/messages"
	"github.com/dapperlabs/flow-go/module"
	"github.com/dapperlabs/flow-go/network"
	"github.com/dapperlabs/flow-go/protocol"
	"github.com/dapperlabs/flow-go/storage"
)

// Engine is the consensus engine, responsible for handling communication for
// the embedded consensus algorithm.
type Engine struct {
	unit     *engine.Unit   // used to control startup/shutdown
	log      zerolog.Logger // used to log relevant actions with context
	me       module.Local
	state    protocol.State
	headers  storage.Headers
	payloads storage.Payloads
	con      network.Conduit

	cache module.PendingBlockBuffer

	coldstuff module.ColdStuff
}

// New creates a new consensus propagation engine.
func New(
	log zerolog.Logger,
	net module.Network,
	me module.Local,
	state protocol.State,
	headers storage.Headers,
	payloads storage.Payloads,
	cache module.PendingBlockBuffer,
) (*Engine, error) {

	// initialize the propagation engine with its dependencies
	e := &Engine{
		unit:     engine.NewUnit(),
		log:      log.With().Str("engine", "consensus").Logger(),
		me:       me,
		state:    state,
		headers:  headers,
		payloads: payloads,
		cache:    cache,
	}

	// register the engine with the network layer and store the conduit
	con, err := net.Register(engine.ProtocolConsensus, e)
	if err != nil {
		return nil, fmt.Errorf("could not register engine: %w", err)
	}
	e.con = con

	return e, nil
}

// WithConsensus adds the consensus algorithm to the engine. This must be
// called before the engine can start.
func (e *Engine) WithConsensus(cold module.ColdStuff) *Engine {
	e.coldstuff = cold
	return e
}

// Ready returns a ready channel that is closed once the engine has fully
// started. For consensus engine, this is true once the underlying consensus
// algorithm has started.
func (e *Engine) Ready() <-chan struct{} {
	if e.coldstuff == nil {
		panic("cannot start consensus engine without consensus algorithm")
	}

	return e.unit.Ready(func() {
		<-e.coldstuff.Ready()
	})
}

// Done returns a done channel that is closed once the engine has fully stopped.
// For the consensus engine, we wait for hotstuff to finish.
func (e *Engine) Done() <-chan struct{} {
	return e.unit.Done(func() {
		<-e.coldstuff.Done()
	})
}

// SubmitLocal submits an event originating on the local node.
func (e *Engine) SubmitLocal(event interface{}) {
	e.Submit(e.me.NodeID(), event)
}

// Submit submits the given event from the node with the given origin ID
// for processing in a non-blocking manner. It returns instantly and logs
// a potential processing error internally when done.
func (e *Engine) Submit(originID flow.Identifier, event interface{}) {
	e.unit.Launch(func() {
		err := e.Process(originID, event)
		if err != nil {
			e.log.Error().Err(err).Msg("could not process submitted event")
		}
	})
}

// ProcessLocal processes an event originating on the local node.
func (e *Engine) ProcessLocal(event interface{}) error {
	return e.Process(e.me.NodeID(), event)
}

// Process processes the given event from the node with the given origin ID in
// a blocking manner. It returns the potential processing error when done.
func (e *Engine) Process(originID flow.Identifier, event interface{}) error {
	return e.unit.Do(func() error {
		return e.process(originID, event)
	})
}

// SendVote will send a vote to the desired node.
func (e *Engine) SendVote(blockID flow.Identifier, view uint64, stakingSig crypto.Signature, randomBeaconSig crypto.Signature, recipientID flow.Identifier) error {

	// build the vote message
	vote := &messages.BlockVote{
		BlockID:               blockID,
		View:                  view,
		StakingSignature:      stakingSig,
		RandomBeaconSignature: randomBeaconSig,
	}

	// send the vote the desired recipient
	err := e.con.Submit(vote, recipientID)
	if err != nil {
		return fmt.Errorf("could not send vote: %w", err)
	}

	return nil
}

// BroadcastProposal will propagate a block proposal to all non-local consensus nodes.
// Note the header has incomplete fields, because it was converted from a hotstuff.Proposal type
func (e *Engine) BroadcastProposal(header *flow.Header) error {

	// first, check that we are the proposer of the block
	if header.ProposerID != e.me.NodeID() {
		return fmt.Errorf("cannot broadcast proposal with non-local proposer (%x)", header.ProposerID)
	}

	// get the parent of the block
	parent, err := e.headers.ByBlockID(header.ParentID)
	if err != nil {
		return fmt.Errorf("could not retrieve proposal parent: %w", err)
	}

	// fill in the fields that can't be populated by HotStuff
	header.ChainID = parent.ChainID
	header.Height = parent.Height + 1

	// retrieve the payload for the block
	blockID := header.ID()
	payload, err := e.payloads.ByBlockID(blockID)
	if err != nil {
		return fmt.Errorf("could not retrieve payload for proposal: %w", err)
	}

	// retrieve all consensus nodes without our ID
	recipients, err := e.state.AtBlockID(header.ParentID).Identities(
		filter.HasRole(flow.RoleConsensus),
		filter.Not(filter.HasNodeID(e.me.NodeID())),
	)
	if err != nil {
		return fmt.Errorf("could not get consensus recipients: %w", err)
	}

	// NOTE: some fields are not needed for the message
	// - proposer ID is conveyed over the network message
	// - the payload hash is deduced from the payload
	msg := &messages.BlockProposal{
		Header:  header,
		Payload: payload,
	}

	// broadcast the proposal to consensus nodes
	err = e.con.Submit(msg, recipients.NodeIDs()...)
	if err != nil {
		return fmt.Errorf("could not send proposal message: %w", err)
	}

	return nil
}

func (e *Engine) BroadcastCommit(commit *model.Commit) error {

	// retrieve all consensus nodes without our ID
	recipients, err := e.state.Final().Identities(
		filter.HasRole(flow.RoleConsensus),
		filter.Not(filter.HasNodeID(e.me.NodeID())),
	)
	if err != nil {
		return fmt.Errorf("could not get consensus recipients: %w", err)
	}

	err = e.con.Submit(commit, recipients.NodeIDs()...)
	if err != nil {
		return fmt.Errorf("could not send commit message: %w", err)
	}

	return err
}

// process processes events for the propagation engine on the consensus node.
func (e *Engine) process(originID flow.Identifier, event interface{}) error {
	switch ev := event.(type) {
	case *messages.BlockProposal:
		return e.onBlockProposal(originID, ev)
	case *messages.BlockVote:
		return e.onBlockVote(originID, ev)
	case *messages.BlockRequest:
		return e.onBlockRequest(originID, ev)
	case *messages.BlockResponse:
		return e.onBlockResponse(originID, ev)
	case *model.Commit:
		return e.onBlockCommit(originID, ev)
	default:
		return fmt.Errorf("invalid event type (%T)", event)
	}
}

// onBlockProposal handles incoming block proposals.
func (e *Engine) onBlockProposal(originID flow.Identifier, proposal *messages.BlockProposal) error {

	// retrieve the parent for the block for parent view; if not found, cache for later
	parent, err := e.headers.ByBlockID(proposal.Header.ParentID)
	if errors.Is(err, storage.ErrNotFound) {
		return e.processPendingProposal(originID, proposal)
	}
	if err != nil {
		return fmt.Errorf("could not retrieve proposal parent: %w", err)
	}

	// store all of the block contents
	err = e.payloads.Store(proposal.Header, proposal.Payload)
	if err != nil {
		return fmt.Errorf("could not store block payload: %w", err)
	}

	// insert the header into the database
	err = e.headers.Store(proposal.Header)
	if err != nil {
		return fmt.Errorf("could not store header: %w", err)
	}

	// see if the block is a valid extension of the protocol state
	blockID := proposal.Header.ID()
	err = e.state.Mutate().Extend(blockID)
	if err != nil {
		return fmt.Errorf("could not extend protocol state: %w", err)
	}

	// submit the model to hotstuff for processing
	e.coldstuff.SubmitProposal(proposal.Header, parent.View)

	// check for any descendants of the block to process
	children, ok := e.cache.ByParentID(blockID)
	if !ok {
		return nil
	}

	// then try to process children only this once
	var result *multierror.Error
	for _, child := range children {
		proposal := &messages.BlockProposal{
			Header:  child.Header,
			Payload: child.Payload,
		}
		err := e.onBlockProposal(child.OriginID, proposal)
		if err != nil {
			result = multierror.Append(result, err)
		}
	}

	// remove the children from cache
	e.cache.DropForParent(blockID)

	return result.ErrorOrNil()
}

// onBlockVote handles incoming block votes.
func (e *Engine) onBlockVote(originID flow.Identifier, vote *messages.BlockVote) error {

	// forward the vote to coldstuff for processing
	e.coldstuff.SubmitVote(originID, vote.BlockID, vote.View, vote.StakingSignature, vote.RandomBeaconSignature)

	return nil
}

// onBlockRequest is how we handle when blocks are requested from us.
func (e *Engine) onBlockRequest(originID flow.Identifier, request *messages.BlockRequest) error {

	// try to retrieve the block header from storage
	header, err := e.headers.ByBlockID(request.BlockID)
	if err != nil {
		return fmt.Errorf("could not find requested block: %w", err)
	}

	// try to retrieve the block payload from storage
	payload, err := e.payloads.ByBlockID(request.BlockID)
	if err != nil {
		return fmt.Errorf("could not find requested payload: %w", err)
	}

	// NOTE: there is a bunch of redundant block proposal construction code here;
	// this is already refactored in another PR and can be replaced once that is
	// merged and I rebase this PR

	// construct the block proposal
	proposal := messages.BlockProposal{
		Header:  header,
		Payload: payload,
	}

	// construct the block response
	response := messages.BlockResponse{
		OriginID: header.ProposerID,
		Proposal: &proposal,
		Nonce:    request.Nonce,
	}
	err = e.con.Submit(&response, originID)
	if err != nil {
		return fmt.Errorf("could not send block response: %w", err)
	}

	return nil
}

// onBlockResponse is how we process responses to our block requests; we could simply use
// the same function as new proposals (onBlockProposal), but separating it allows us more
// flexibility; for one, we can explicitly convey the original origin ID. We could also do
// additional robustness stuff by matching requests & responses.
func (e *Engine) onBlockResponse(originID flow.Identifier, response *messages.BlockResponse) error {

	// for now, we simply process the block response like a normal proposal
	err := e.onBlockProposal(response.OriginID, response.Proposal)
	if err != nil {
		return fmt.Errorf("could not process block response: %w", err)
	}

	return nil
}

// onBlockCommit handles incoming block commits by passing them to the core
// consensus algorithm.
//
// NOTE: This is only necessary for ColdStuff and can be removed when we switch
// to HotStuff.
func (e *Engine) onBlockCommit(originID flow.Identifier, commit *model.Commit) error {
	e.coldstuff.SubmitCommit(commit)
	return nil
}

// processPendingProposal will deal with proposals where the parent is missing.
func (e *Engine) processPendingProposal(originID flow.Identifier, proposal *messages.BlockProposal) error {

	parentID := proposal.Header.ParentID

	pendingBlock := &flow.PendingBlock{
		OriginID: originID,
		Header:   proposal.Header,
		Payload:  proposal.Payload,
	}

	// add the block to the buffer, exit early if it already exists
	added := e.cache.Add(pendingBlock)
	if !added {
		return nil
	}

	// if the block hasn't yet been cached, send the block request
	request := messages.BlockRequest{
		BlockID: parentID,
		Nonce:   rand.Uint64(),
	}
	err := e.con.Submit(&request, originID)
	if err != nil {
		return fmt.Errorf("could not send block request: %w", err)
	}

	// NOTE: at this point, if he doesn't send us the parent, we should probably think about a way
	// to blacklist him, as this can be exploited by sending us lots of children without parent;
	// a second mitigation strategy is to put a strict limit on children we cache, and possibly a
	// limit on children we cache coming from a single other node

	return nil
}
