// +build relic

package crypto

import (
	"encoding/hex"
	"fmt"

	"github.com/onflow/flow-go/crypto/hash"
)

func ExampleGeneratePrivateKey() {
	// select input key material, usually from a backup seed, or initially generated at random
	ikmString := "cafecafecafecafecafecafecafecafecafecafecafecafecafecafecafecafecafecafecafecafecafecafecafecafe"
	ikm, _ := hex.DecodeString(ikmString)
	sk, err := GeneratePrivateKey(BLSBLS12381, ikm)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Generated BLS12-381 Private Key: %v \n", sk.String())
	// Output:
	// Generated BLS12-381 Private Key: 0x5ad8056931182dc50be602c1ac060048da8b639b9156e5fc0ea61025cafecaff
}

func ExampleDecodePrivateKey() {
	skString := "708309a7449e156b0db70e5b52e606c7e094ed676ce8953bf6c14757c826f590"
	skBytes, _ := hex.DecodeString(skString)
	sk, err := DecodePrivateKey(BLSBLS12381, skBytes)
	if err != nil {
		panic(err)
	}
	fmt.Printf("BLS12-381 Private Key: %v\n", sk.String())
	// Output:
	// BLS12-381 Private Key: 0x708309a7449e156b0db70e5b52e606c7e094ed676ce8953bf6c14757c826f590
}

// Test vector from https://github.com/algorand/bls_sigs_ref/blob/master/test-vectors/hash_g1/fips_186_3_P256
func ExampleHashToG1() {
	msgString := "ff624d0ba02c7b6370c1622eec3fa2186ea681d1659e0a845448e777b75a8e77a77bb26e5733179d58ef9bc8a4e8b6971aef2539f77ab0963a3415bbd6258339bd1bf55de65db520c63f5b8eab3d55debd05e9494212170f5d65b3286b8b668705b1e2b2b5568610617abb51d2dd0cb450ef59df4b907da90cfa7b268de8c4c2"
	msg, _ := hex.DecodeString(msgString)

	hasher := hash.NewXMD_SHA2_256([]byte{01})

	fieldHash := hasher.ComputeHash(msg)
	point := hashToG1(fieldHash)
	dest := make([]byte, signatureLengthBLSBLS12381)
	writePointG1(dest, point)
	fmt.Printf("G1 point: %v\n", hex.EncodeToString(dest))
	// Output: G1 point: 934b3a537d5e092e8a0a6f9193fa2112fa178b1bd416adb6e6f3b95aeda3752f9297ddecc87920ec0c25b31bb748cc9b
}

// Test vector from https://github.com/algorand/bls_sigs_ref/blob/master/test-vectors/hash_g1/fips_186_3_P256
func ExampleMapToG1Relic() {
	msgString := "ff624d0ba02c7b6370c1622eec3fa2186ea681d1659e0a845448e777b75a8e77a77bb26e5733179d58ef9bc8a4e8b6971aef2539f77ab0963a3415bbd6258339bd1bf55de65db520c63f5b8eab3d55debd05e9494212170f5d65b3286b8b668705b1e2b2b5568610617abb51d2dd0cb450ef59df4b907da90cfa7b268de8c4c2"
	msg, _ := hex.DecodeString(msgString)

	var point pointG1
	mapToG1Relic(&point, msg, []byte{01})
	dest := make([]byte, signatureLengthBLSBLS12381)
	writePointG1(dest, &point)
	fmt.Printf("G1 point: %v\n", hex.EncodeToString(dest))
	// Output: G1 point: 934b3a537d5e092e8a0a6f9193fa2112fa178b1bd416adb6e6f3b95aeda3752f9297ddecc87920ec0c25b31bb748cc9b
}

// Test vector from https://github.com/kwantam/bls_sigs_ref/blob/master/test-vectors/sig_g1_basic/fips_186_3_P256
func ExampleSignatureWithXMD() {
	skString := "708309a7449e156b0db70e5b52e606c7e094ed676ce8953bf6c14757c826f590"
	skBytes, _ := hex.DecodeString(skString)
	sk, _ := DecodePrivateKey(BLSBLS12381, skBytes)

	msgString := "ff624d0ba02c7b6370c1622eec3fa2186ea681d1659e0a845448e777b75a8e77a77bb26e5733179d58ef9bc8a4e8b6971aef2539f77ab0963a3415bbd6258339bd1bf55de65db520c63f5b8eab3d55debd05e9494212170f5d65b3286b8b668705b1e2b2b5568610617abb51d2dd0cb450ef59df4b907da90cfa7b268de8c4c2"
	msg, _ := hex.DecodeString(msgString)

	// standard BLS DST for basic signature
	hasher := hash.NewXMD_SHA2_256([]byte("BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_"))

	// Sanity-check
	// fmt.Printf("ciphersuite: %v \n", hex.EncodeToString([]byte("BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_")))

	sig, err := sk.Sign(msg, hasher)
	if err != nil {
		panic(err)
	}

	sigHex := hex.EncodeToString(sig)
	fmt.Printf("BLS12-381 signature: %v\n", sigHex)
	// Output:
	// BLS12-381 signature: 8376eaaae4275ee59263ba2a94c3e664c031bc3177eea3333ba893ab33c8df3f2e8825be3ada8ed6184b2e38367113ab
}
