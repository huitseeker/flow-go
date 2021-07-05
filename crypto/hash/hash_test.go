package hash

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func checkBytes(t *testing.T, input, expected, result []byte) {
	if !bytes.Equal(expected, result) {
		t.Errorf("hash mismatch: expect: \n%x have:\n%x, input is %x", expected, result, input)
	} else {
		t.Logf("hash test ok: expect: %x, input: %x", expected, input)
	}
}

// Sanity checks of SHA3_256
func TestSha3_256(t *testing.T) {
	input := []byte("test")
	expected, _ := hex.DecodeString("36f028580bb02cc8272a9a020f4200e346e276ae664e45ee80745574e2f5ab80")

	alg := NewSHA3_256()
	hash := alg.ComputeHash(input)
	checkBytes(t, input, expected, hash)

	alg.Reset()
	_, _ = alg.Write([]byte("te"))
	_, _ = alg.Write([]byte("s"))
	_, _ = alg.Write([]byte("t"))
	hash = alg.SumHash()
	checkBytes(t, input, expected, hash)
}

// Sanity checks of SHA3_384
func TestSha3_384(t *testing.T) {
	input := []byte("test")
	expected, _ := hex.DecodeString("e516dabb23b6e30026863543282780a3ae0dccf05551cf0295178d7ff0f1b41eecb9db3ff219007c4e097260d58621bd")

	alg := NewSHA3_384()
	hash := alg.ComputeHash(input)
	checkBytes(t, input, expected, hash)

	alg.Reset()
	_, _ = alg.Write([]byte("te"))
	_, _ = alg.Write([]byte("s"))
	_, _ = alg.Write([]byte("t"))
	hash = alg.SumHash()
	checkBytes(t, input, expected, hash)
}

// Sanity checks of SHA2_256
func TestSha2_256(t *testing.T) {
	input := []byte("test")
	expected, _ := hex.DecodeString("9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08")

	alg := NewSHA2_256()
	hash := alg.ComputeHash(input)
	checkBytes(t, input, expected, hash)

	alg.Reset()
	_, _ = alg.Write([]byte("te"))
	_, _ = alg.Write([]byte("s"))
	_, _ = alg.Write([]byte("t"))
	hash = alg.SumHash()
	checkBytes(t, input, expected, hash)
}

// Sanity checks of SHA2_256
func TestSha2_384(t *testing.T) {
	input := []byte("test")
	expected, _ := hex.DecodeString("768412320f7b0aa5812fce428dc4706b3cae50e02a64caa16a782249bfe8efc4b7ef1ccb126255d196047dfedf17a0a9")

	alg := NewSHA2_384()
	hash := alg.ComputeHash(input)
	checkBytes(t, input, expected, hash)

	alg.Reset()
	_, _ = alg.Write([]byte("te"))
	_, _ = alg.Write([]byte("s"))
	_, _ = alg.Write([]byte("t"))
	hash = alg.SumHash()
	checkBytes(t, input, expected, hash)
}

// Sanity checks of XMD_SHA2_256
// See https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hash-to-curve-10#appendix-K.1
func TestXmd_Sha2_256(t *testing.T) {
	dst := []byte("QUUX-V01-CS02-with-expander")

	input := []byte("")
	expected, _ := hex.DecodeString("8bcffd1a3cae24cf9cd7ab85628fd111bb17e3739d3b53f89580d217aa79526f1708354a76a402d3569d6a9d19ef3de4d0b991e4f54b9f20dcde9b95a66824cbdf6c1a963a1913d43fd7ac443a02fc5d9d8d77e2071b86ab114a9f34150954a7531da568a1ea8c760861c0cde2005afc2c114042ee7b5848f5303f0611cf297f")

	alg := NewXMD_SHA2_256(dst)
	hash := alg.ComputeHash(input)
	checkBytes(t, input, expected, hash)

	alg.Reset()
	input = []byte("abc")
	expected, _ = hex.DecodeString("fe994ec51bdaa821598047b3121c149b364b178606d5e72bfbb713933acc29c186f316baecf7ea22212f2496ef3f785a27e84a40d8b299cec56032763eceeff4c61bd1fe65ed81decafff4a31d0198619c0aa0c6c51fca15520789925e813dcfd318b542f8799441271f4db9ee3b8092a7a2e8d5b75b73e28fb1ab6b4573c192")
	hash = alg.ComputeHash(input)
	checkBytes(t, input, expected, hash)

	alg.Reset()
	input = []byte("abcdef0123456789")
	expected, _ = hex.DecodeString("c9ec7941811b1e19ce98e21db28d22259354d4d0643e301175e2f474e030d32694e9dd5520dde93f3600d8edad94e5c364903088a7228cc9eff685d7eaac50d5a5a8229d083b51de4ccc3733917f4b9535a819b445814890b7029b5de805bf62b33a4dc7e24acdf2c924e9fe50d55a6b832c8c84c7f82474b34e48c6d43867be")
	hash = alg.ComputeHash(input)
	checkBytes(t, input, expected, hash)
}

// Sanity checks of XMD_SHA2_256
// See https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hash-to-curve-10#appendix-K.2
func TestXmd_Sha2_512(t *testing.T) {
	dst := []byte("QUUX-V01-CS02-with-expander")

	input := []byte("")
	expected, _ := hex.DecodeString("0687ce02eba5eb3faf1c3c539d1f04babd3c0f420edae244eeb2253b6c6d6865145c31458e824b4e87ca61c3442dc7c8c9872b0b7250aa33e0668ccebbd2b386de658ca11a1dcceb51368721ae6dcd2d4bc86eaebc4e0d11fa02ad053289c9b28a03da6c942b2e12c14e88dbde3b0ba619d6214f47212b628f3e1b537b66efcf")

	alg := NewXMD_SHA2_512(dst)
	hash := alg.ComputeHash(input)
	checkBytes(t, input, expected, hash)

	alg.Reset()
	input = []byte("abc")
	expected, _ = hex.DecodeString("779ae4fd8a92f365e4df96b9fde97b40486bb005c1a2096c86f55f3d92875d89045fbdbc4a0e9f2d3e1e6bcd870b2d7131d868225b6fe72881a81cc5166b5285393f71d2e68bb0ac603479959370d06bdbe5f0d8bfd9af9494d1e4029bd68ab35a561341dd3f866b3ef0c95c1fdfaab384ce24a23427803dda1db0c7d8d5344a")
	hash = alg.ComputeHash(input)
	checkBytes(t, input, expected, hash)

	alg.Reset()
	input = []byte("abcdef0123456789")
	expected, _ = hex.DecodeString("f0953d28846a50e9f88b7ae35b643fc43733c9618751b569a73960c655c068db7b9f044ad5a40d49d91c62302eaa26163c12abfa982e2b5d753049e000adf7630ae117aeb1fb9b61fc724431ac68b369e12a9481b4294384c3c890d576a79264787bc8076e7cdabe50c044130e480501046920ff090c1a091c88391502f0fbac")
	hash = alg.ComputeHash(input)
	checkBytes(t, input, expected, hash)
}

// SHA3_256 bench
func BenchmarkSha3_256(b *testing.B) {
	a := []byte("Bench me!")
	alg := NewSHA3_256()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		alg.ComputeHash(a)
	}
	return
}

// SHA3_384 bench
func BenchmarkSha3_384(b *testing.B) {
	a := []byte("Bench me!")
	alg := NewSHA3_384()
	for i := 0; i < b.N; i++ {
		alg.ComputeHash(a)
	}
	return
}

// SHA2_256 bench
func BenchmarkSha2_256(b *testing.B) {
	a := []byte("Bench me!")
	alg := NewSHA2_256()
	for i := 0; i < b.N; i++ {
		alg.ComputeHash(a)
	}
	return
}

// SHA2_256 bench
func BenchmarkSha2_384(b *testing.B) {
	a := []byte("Bench me!")
	alg := NewSHA2_384()
	for i := 0; i < b.N; i++ {
		alg.ComputeHash(a)
	}
	return
}

// Sanity checks of cSHAKE-128
// the test vector is taken from the NIST document
// https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/Kmac_samples.pdf
func TestKmac128(t *testing.T) {

	input := []byte{0x00, 0x01, 0x02, 0x03}
	expected := [][]byte{
		{0xE5, 0x78, 0x0B, 0x0D, 0x3E, 0xA6, 0xF7, 0xD3, 0xA4, 0x29, 0xC5, 0x70, 0x6A, 0xA4, 0x3A, 0x00,
			0xFA, 0xDB, 0xD7, 0xD4, 0x96, 0x28, 0x83, 0x9E, 0x31, 0x87, 0x24, 0x3F, 0x45, 0x6E, 0xE1, 0x4E},
		{0x3B, 0x1F, 0xBA, 0x96, 0x3C, 0xD8, 0xB0, 0xB5, 0x9E, 0x8C, 0x1A, 0x6D, 0x71, 0x88, 0x8B, 0x71,
			0x43, 0x65, 0x1A, 0xF8, 0xBA, 0x0A, 0x70, 0x70, 0xC0, 0x97, 0x9E, 0x28, 0x11, 0x32, 0x4A, 0xA5},
	}
	key := []byte{0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F,
		0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F}
	customizers := [][]byte{
		[]byte(""),
		[]byte("My Tagged Application"),
	}
	outputSize := 32

	alg, err := NewKMAC_128(key, customizers[0], outputSize)
	require.Nil(t, err)
	_, _ = alg.Write(input[0:2])
	_, _ = alg.Write(input[2:])
	hash := alg.SumHash()
	checkBytes(t, input, expected[0], hash)

	for i := 0; i < len(customizers); i++ {
		alg, err = NewKMAC_128(key, customizers[i], outputSize)
		require.Nil(t, err)
		hash = alg.ComputeHash(input)
		checkBytes(t, input, expected[i], hash)
	}

	// test short key length
	_, err = NewKMAC_128(key[:15], customizers[0], outputSize)
	assert.Error(t, err)
}

// TestHashersAPI tests the expected definition of the hashers APIs
func TestHashersAPI(t *testing.T) {
	kmac128, err := NewKMAC_128([]byte("test_key________"), []byte("test_custommizer"), 32)
	require.Nil(t, err)

	hashers := []Hasher{
		NewSHA2_256(),
		NewSHA2_384(),
		NewSHA3_256(),
		NewSHA3_384(),
		kmac128,
	}
	for _, h := range hashers {
		// Reset should empty the state
		expectedEmptyHash := h.SumHash()
		h.Write([]byte("data"))
		h.Reset()
		emptyHash := h.SumHash()
		assert.Equal(t, expectedEmptyHash, emptyHash)

		// ComputeHash output does not depend on the hasher state
		h.Write([]byte("data"))
		emptyHash = h.ComputeHash([]byte(""))
		assert.Equal(t, expectedEmptyHash, emptyHash)

		// ComputeHash does not update the state (only for KMAC128)
		hash := h.SumHash()
		expectedHash := h.ComputeHash([]byte("data"))
		if h.Algorithm() == KMAC128 {
			assert.Equal(t, expectedHash, hash)
		}

		// SumHash does not reset the hasher state and allows writing more data
		h.Reset()
		h.Write([]byte("da"))
		_ = h.SumHash()
		h.Write([]byte("ta"))
		hash = h.SumHash()
		assert.Equal(t, expectedHash, hash)
	}
}
