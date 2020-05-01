package testutil

import (
	"encoding/hex"
	"fmt"

	"github.com/dapperlabs/flow-go/crypto/hash"
	"github.com/dapperlabs/flow-go/model/flow"
)

func DeployCounterContractTransaction() flow.TransactionBody {
	encoded := hex.EncodeToString([]byte(`
			access(all) contract Container {
				access(all) resource Counter {
					pub var count: Int

					init(_ v: Int) {
						self.count = v
					}
					pub fun add(_ count: Int) {
						self.count = self.count + count
					}
				}
				pub fun createCounter(_ v: Int): @Counter {
					return <-create Counter(v)
				}
			}`))

	return flow.TransactionBody{
		Script: []byte(fmt.Sprintf(`transaction {
              prepare(signer: AuthAccount) {
                signer.setCode("%s".decodeHex())
              }
            }`, encoded)),
		Authorizers: []flow.Address{flow.RootAddress},
	}
}

func CreateCounterTransaction() flow.TransactionBody {
	return flow.TransactionBody{
		Script: []byte(`
			import 0x01
			
			transaction {
				prepare(acc: AuthAccount) {
					var maybeCounter <- acc.load<@Container.Counter>(from: /storage/counter)
			
					if maybeCounter == nil {
						maybeCounter <-! Container.createCounter(3)		
					}
			
					acc.save(<-maybeCounter!, to: /storage/counter)
				}   	
			}`),
		Authorizers: []flow.Address{flow.RootAddress},
	}
}

// CreateCounterPanicTransaction returns a transaction that will manipulate state by writing a new counter into storage
// and then panic. It can be used to test whether execution state stays untouched/will revert
func CreateCounterPanicTransaction() flow.TransactionBody {
	return flow.TransactionBody{
		Script: []byte(`

			import 0x01

			transaction {
				prepare(acc: AuthAccount) {
					let existing <- acc.storage[Container.Counter] <- Container.createCounter(42)
					destroy existing

					panic("fail for testing purposes")
              	}
            }`),
		Authorizers: []flow.Address{flow.RootAddress},
	}
}

func AddToCounterTransaction() flow.TransactionBody {
	return flow.TransactionBody{
		Script: []byte(`
			import 0x01
			
			transaction {
				prepare(acc: AuthAccount) {
					let counter <- acc.load<@Container.Counter>(from: /storage/counter)
			
					counter?.add(2)
			
					acc.save(<-counter, to: /storage/counter)
				}
			}`),
		Authorizers: []flow.Address{flow.RootAddress},
	}
}

func SignTransactionbyRoot(tx *flow.TransactionBody, seqNum uint64) error {

	privateKeyBytes, err := hex.DecodeString(flow.RootAccountPrivateKeyHex)
	if err != nil {
		return fmt.Errorf("cannot hex decode hardcoded key: %w", err)
	}

	privateKey, err := flow.DecodeAccountPrivateKey(privateKeyBytes)
	if err != nil {
		return fmt.Errorf("cannot decode hardcoded private key: %w", err)
	}

	hasher, err := hash.NewHasher(privateKey.HashAlgo)
	if err != nil {
		return fmt.Errorf("cannot create hasher: %w", err)
	}

	err = tx.SetPayer(flow.RootAddress).
		SetProposalKey(flow.RootAddress, 0, seqNum).
		SignEnvelope(flow.RootAddress, 0, privateKey.PrivateKey, hasher)

	if err != nil {
		return fmt.Errorf("cannot sign tx: %w", err)
	}

	return nil
}
