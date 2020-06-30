package testutil

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/onflow/cadence"
	jsoncdc "github.com/onflow/cadence/encoding/json"
	"github.com/onflow/cadence/runtime"
	"github.com/stretchr/testify/require"

	"github.com/dapperlabs/flow-go/crypto"
	"github.com/dapperlabs/flow-go/crypto/hash"
	"github.com/dapperlabs/flow-go/engine/execution/utils"
	"github.com/dapperlabs/flow-go/fvm"
	"github.com/dapperlabs/flow-go/model/flow"
	"github.com/dapperlabs/flow-go/utils/unittest"
)

func CreateContractDeploymentTransaction(contract string, authorizer flow.Address, chain flow.Chain) *flow.TransactionBody {
	encoded := hex.EncodeToString([]byte(contract))

	return flow.NewTransactionBody().
		SetScript([]byte(fmt.Sprintf(`transaction {
              prepare(signer: AuthAccount, service: AuthAccount) {
                signer.setCode("%s".decodeHex())
              }
            }`, encoded)),
		).
		AddAuthorizer(authorizer).
		AddAuthorizer(chain.ServiceAddress())
}

func CreateUnauthorizedContractDeploymentTransaction(contract string, authorizer flow.Address) *flow.TransactionBody {
	encoded := hex.EncodeToString([]byte(contract))

	return flow.NewTransactionBody().
		SetScript([]byte(fmt.Sprintf(`transaction {
              prepare(signer: AuthAccount) {
                signer.setCode("%s".decodeHex())
              }
            }`, encoded)),
		).
		AddAuthorizer(authorizer)
}

func SignPayload(
	tx *flow.TransactionBody,
	account flow.Address,
	privateKey flow.AccountPrivateKey,
) error {
	hasher, err := utils.NewHasher(privateKey.HashAlgo)
	if err != nil {
		return fmt.Errorf("failed to create hasher: %w", err)
	}

	err = tx.SignPayload(account, 0, privateKey.PrivateKey, hasher)

	if err != nil {
		return fmt.Errorf("failed to sign transaction: %w", err)
	}

	return nil
}

func SignEnvelope(tx *flow.TransactionBody, account flow.Address, privateKey flow.AccountPrivateKey) error {
	hasher, err := utils.NewHasher(privateKey.HashAlgo)
	if err != nil {
		return fmt.Errorf("failed to create hasher: %w", err)
	}

	err = tx.SignEnvelope(account, 0, privateKey.PrivateKey, hasher)

	if err != nil {
		return fmt.Errorf("failed to sign transaction: %w", err)
	}

	return nil
}

func SignTransaction(
	tx *flow.TransactionBody,
	address flow.Address,
	privateKey flow.AccountPrivateKey,
	seqNum uint64,
) error {
	tx.SetProposalKey(address, 0, seqNum)
	tx.SetPayer(address)
	return SignEnvelope(tx, address, privateKey)
}

func SignTransactionAsServiceAccount(tx *flow.TransactionBody, seqNum uint64, chain flow.Chain) error {
	return SignTransaction(tx, chain.ServiceAddress(), unittest.ServiceAccountPrivateKey, seqNum)
}

// GenerateAccountPrivateKeys generates a number of private keys.
func GenerateAccountPrivateKeys(numberOfPrivateKeys int) ([]flow.AccountPrivateKey, error) {
	var privateKeys []flow.AccountPrivateKey
	for i := 0; i < numberOfPrivateKeys; i++ {
		pk, err := GenerateAccountPrivateKey()
		if err != nil {
			return nil, err
		}
		privateKeys = append(privateKeys, pk)
	}

	return privateKeys, nil
}

// GenerateAccountPrivateKey generates a private key.
func GenerateAccountPrivateKey() (flow.AccountPrivateKey, error) {
	seed := make([]byte, crypto.KeyGenSeedMinLenECDSAP256)
	_, err := rand.Read(seed)
	if err != nil {
		return flow.AccountPrivateKey{}, err
	}
	privateKey, err := crypto.GeneratePrivateKey(crypto.ECDSAP256, seed)
	if err != nil {
		return flow.AccountPrivateKey{}, err
	}
	pk := flow.AccountPrivateKey{
		PrivateKey: privateKey,
		SignAlgo:   crypto.ECDSAP256,
		HashAlgo:   hash.SHA2_256,
	}
	return pk, nil
}

// CreateAccounts inserts accounts into the ledger using the provided private keys.
func CreateAccounts(
	vm *fvm.VirtualMachine,
	ledger fvm.Ledger,
	privateKeys []flow.AccountPrivateKey,
	chain flow.Chain,
) ([]flow.Address, error) {
	return CreateAccountsWithSimpleAddresses(vm, ledger, privateKeys, chain)
}

func CreateAccountsWithSimpleAddresses(
	vm *fvm.VirtualMachine,
	ledger fvm.Ledger,
	privateKeys []flow.AccountPrivateKey,
	chain flow.Chain,
) ([]flow.Address, error) {
	ctx := fvm.NewContext(fvm.WithSignatureVerification(false))

	var accounts []flow.Address

	script := []byte(`
	  transaction(publicKey: [Int]) {
	    prepare(signer: AuthAccount) {
	  	  let acct = AuthAccount(payer: signer)
	  	  acct.addPublicKey(publicKey)
	    }
	  }
	`)

	serviceAddress := chain.ServiceAddress()

	for _, privateKey := range privateKeys {
		accountKey := privateKey.PublicKey(fvm.AccountKeyWeightThreshold)
		encAccountKey, _ := flow.EncodeRuntimeAccountPublicKey(accountKey)
		cadAccountKey := BytesToCadenceArray(encAccountKey)
		encCadAccountKey, _ := jsoncdc.Encode(cadAccountKey)

		tx := flow.NewTransactionBody().
			SetScript(script).
			AddArgument(encCadAccountKey).
			AddAuthorizer(serviceAddress)

		result, err := vm.Invoke(ctx, fvm.Transaction(tx), ledger)
		if err != nil {
			return nil, err
		}

		if result.Error != nil {
			return nil, fmt.Errorf("failed to create account: %w", result.Error)
		}

		var addr flow.Address

		for _, event := range result.Events {
			if event.EventType.ID() == string(flow.EventAccountCreated) {
				addr = event.Fields[0].ToGoValue().([8]byte)
				break
			}

			return nil, errors.New("no account creation event emitted")
		}

		accounts = append(accounts, addr)
	}

	return accounts, nil
}

func RootBootstrappedLedger(chain flow.Chain) fvm.Ledger {
	ledger := make(fvm.MapLedger)

	vm := fvm.New(runtime.NewInterpreterRuntime(), chain)

	_, _ = vm.Invoke(
		fvm.NewContext(),
		fvm.Bootstrap(unittest.ServiceAccountPublicKey, unittest.GenesisTokenSupply),
		ledger,
	)

	return ledger
}

func BytesToCadenceArray(l []byte) cadence.Array {
	values := make([]cadence.Value, len(l))
	for i, b := range l {
		values[i] = cadence.NewInt(int(b))
	}

	return cadence.NewArray(values)
}

// CreateAccountCreationTransaction creates a transaction which will create a new account.
//
// This function returns a randomly generated private key and the transaction.
func CreateAccountCreationTransaction(t *testing.T, chain flow.Chain) (flow.AccountPrivateKey, *flow.TransactionBody) {
	accountKey, err := GenerateAccountPrivateKey()
	require.NoError(t, err)

	keyBytes, err := flow.EncodeRuntimeAccountPublicKey(accountKey.PublicKey(1000))
	require.NoError(t, err)

	// define the cadence script
	script := fmt.Sprintf(`
		transaction {
		  prepare(signer: AuthAccount) {
			let acct = AuthAccount(payer: signer)
			acct.addPublicKey("%s".decodeHex())
		  }
		}
	`, hex.EncodeToString(keyBytes))

	// create the transaction to create the account
	tx := flow.NewTransactionBody().
		SetScript([]byte(script)).
		AddAuthorizer(chain.ServiceAddress())

	return accountKey, tx
}

// CreateAddAccountKeyTransaction generates a tx that adds a key to an account.
func CreateAddAccountKeyTransaction(t *testing.T, accountKey *flow.AccountPrivateKey) *flow.TransactionBody {
	keyBytes, err := flow.EncodeRuntimeAccountPublicKey(accountKey.PublicKey(1000))
	require.NoError(t, err)

	// encode the bytes to cadence string
	encodedKey := languageEncodeBytes(keyBytes)

	script := fmt.Sprintf(`
        transaction {
          prepare(signer: AuthAccount) {
            signer.addPublicKey(%s)
          }
        }
   	`, encodedKey)

	return &flow.TransactionBody{
		Script: []byte(script),
	}
}

// CreateRemoveAccountKeyTransaction generates a tx that removes a key from an account.
func CreateRemoveAccountKeyTransaction(index int) *flow.TransactionBody {
	script := fmt.Sprintf(`
		transaction {
		  prepare(signer: AuthAccount) {
	    	signer.removePublicKey(%d)
		  }
		}
	`, index)

	return &flow.TransactionBody{
		Script: []byte(script),
	}
}

func languageEncodeBytes(b []byte) string {
	if len(b) == 0 {
		return "[]"
	}
	return strings.Join(strings.Fields(fmt.Sprintf("%d", b)), ",")
}
