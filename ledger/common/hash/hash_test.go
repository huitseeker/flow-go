package hash_test

import (
	"math/rand"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	cryhash "github.com/onflow/flow-go/crypto/hash"
	"github.com/onflow/flow-go/ledger/common/hash"
)

// Test_GetDefaultHashForHeight tests getting default hash for given heights
func Test_GetDefaultHashForHeight(t *testing.T) {
	hasher := cryhash.NewSHA3_256()
	defaultLeafHash := hasher.ComputeHash([]byte("default:"))
	expected := hash.GetDefaultHashForHeight(0)
	assert.Equal(t, []byte(expected[:]), []byte(defaultLeafHash))

	l1 := hash.HashInterNode(hash.GetDefaultHashForHeight(0), hash.GetDefaultHashForHeight(0))
	assert.Equal(t, l1, hash.GetDefaultHashForHeight(1))

	l2 := hash.HashInterNode(l1, l1)
	assert.Equal(t, l2, hash.GetDefaultHashForHeight(2))
}

func Test_ComputeCompactValue(t *testing.T) {
	v := []byte{'A'}

	// 00000101...00000000
	var path hash.Hash
	path[0] = 5
	nodeHeight := 251
	h := hash.HashLeaf(path, v)
	l := 0
	// exclude last 3 level
	for ; l < nodeHeight-3; l++ {
		h = hash.HashInterNode(h, hash.GetDefaultHashForHeight(l))
	}
	l1 := hash.HashInterNode(hash.GetDefaultHashForHeight(l), h)
	l2 := hash.HashInterNode(l1, hash.GetDefaultHashForHeight(l+1))
	l3 := hash.HashInterNode(hash.GetDefaultHashForHeight(l+2), l2)
	result := hash.ComputeCompactValue(path, v, nodeHeight)
	assert.Equal(t, l3, result)
}

func TestHash(t *testing.T) {
	r := time.Now().UnixNano()
	rand.Seed(r)
	t.Logf("math rand seed is %d", r)

	t.Run("HashLeaf", func(t *testing.T) {
		var path hash.Hash

		for i := 0; i < 5000; i++ {
			value := make([]byte, i)
			rand.Read(path[:])
			rand.Read(value)
			h := hash.HashLeaf(path, value)

			hasher := cryhash.NewSHA3_256()
			_, _ = hasher.Write(path[:])
			_, _ = hasher.Write(value)
			expected := hasher.SumHash()
			assert.Equal(t, []byte(expected), []byte(h[:]))
		}
	})

	t.Run("HashInterNode", func(t *testing.T) {
		var h1, h2 hash.Hash

		for i := 0; i < 5000; i++ {
			rand.Read(h1[:])
			rand.Read(h2[:])
			h := hash.HashInterNode(h1, h2)

			hasher := cryhash.NewSHA3_256()
			_, _ = hasher.Write(h1[:])
			_, _ = hasher.Write(h2[:])
			expected := hasher.SumHash()
			assert.Equal(t, []byte(expected), []byte(h[:]))
		}
	})
}

func BenchmarkHash(b *testing.B) {

	var h1, h2 hash.Hash
	rand.Read(h1[:])
	rand.Read(h2[:])

	// customized sha3 for ledger
	b.Run("LedgerSha3", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_ = hash.HashInterNode(h1, h2)
		}
		b.StopTimer()
	})

	// flow crypto generic sha3
	b.Run("GenericSha3", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			hasher := cryhash.NewSHA3_256()
			_, _ = hasher.Write(h1[:])
			_, _ = hasher.Write(h2[:])
			_ = hasher.SumHash()
		}
		b.StopTimer()
	})
}