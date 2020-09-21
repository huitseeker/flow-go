package wal

import (
	"fmt"

	"github.com/dapperlabs/flow-go/ledger"
	"github.com/dapperlabs/flow-go/ledger/common/encoding"
	"github.com/dapperlabs/flow-go/ledger/common/utils"
)

type WALOperation uint8

const WALUpdate WALOperation = 1
const WALDelete WALOperation = 2
const WALUpdateAck WALOperation = 3

/*
The LedgerWAL update record uses two operations so far - an update which must include all keys and values, and deletion
which only needs a root tree state commitment.
Updates need to be atomic, hence we prepare binary representation of whole changeset.
Since keys, values and state commitments date types are variable length, we have to store it as well.
Every record has:

1 byte Operation Type | 2 bytes Big Endian uint16 length of state commitment | state commitment data

If OP = WALUpdate, then it follow with:

4 bytes Big Endian uint32 - total number of key/value pairs | 2 bytes Big Endian uint16 - length of key (keys are the same length)

and for every pair after
bytes for key | 4 bytes Big Endian uint32 - length of value | value bytes

The code here is deliberately simple, for performance.

*/

func EncodeUpdate(update *ledger.TrieUpdate) []byte {
	encUpdate := encoding.EncodeTrieUpdate(update)
	buf := make([]byte, 0, len(encUpdate)+1)
	// set WAL type
	buf = append(buf, byte(WALUpdate))
	// TODO use 2 bytes for encoding length
	// the rest is encoded update
	buf = append(buf, encUpdate...)
	return buf
}

func EncodeDelete(rootHash ledger.RootHash) []byte {
	buf := make([]byte, 0)
	buf = append(buf, byte(WALDelete))
	buf = utils.AppendShortData(buf, rootHash)
	return buf
}

func EncodeUpdateAck(uuid ledger.OperationUUID, newRootHash ledger.RootHash) []byte {
	buf := make([]byte, 0)
	buf = append(buf, byte(WALUpdateAck))
	buf = utils.AppendShortData(buf, uuid)
	buf = utils.AppendShortData(buf, newRootHash)
	return buf
}

func Decode(data []byte) (operation WALOperation, rootHash ledger.RootHash, update *ledger.TrieUpdate, err error) {
	if len(data) < 4 { // 1 byte op + 2 size + actual data = 4 minimum
		err = fmt.Errorf("data corrupted, too short to represent operation - hexencoded data: %x", data)
		return
	}

	operation = WALOperation(data[0])
	switch operation {
	case WALUpdate:
		update, err = encoding.DecodeTrieUpdate(data[1:])
		return
	case WALDelete:
		rootHash, _, err = utils.ReadShortData(data[1:])
		if err != nil {
			err = fmt.Errorf("cannot read state commitment: %w", err)
		}
		return
	case WALUpdateAck:
		// TODO(return operation ack)
		var rest []byte
		_, rest, err = utils.ReadShortData(data[1:])
		if err != nil {
			err = fmt.Errorf("cannot read opeartion uuid: %w", err)
			return
		}
		rootHash, _, err = utils.ReadShortData(rest)
		if err != nil {
			err = fmt.Errorf("cannot read state commitment: %w", err)
		}
		return
	default:
		err = fmt.Errorf("unknown operation type, given: %x", operation)
	}
	return
}
