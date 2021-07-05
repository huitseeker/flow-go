package hash

import (
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"hash"
)

// ExpandMsgXmd expands msg to a slice of lenInBytes bytes.
// https://tools.ietf.org/html/draft-irtf-cfrg-hash-to-curve-10#section-5.4
// https://tools.ietf.org/html/rfc8017#section-4.1 (I2OSP/O2ISP)
func expandMsgXmd(h hash.Hash, msg, dst []byte, lenInBytes int) ([]byte, error) {

	ell := (lenInBytes + h.Size() - 1) / h.Size() // ceil(len_in_bytes / b_in_bytes)
	if ell > 255 {
		return nil, errors.New("invalid lenInBytes")
	}
	if len(dst) > 255 {
		return nil, errors.New("invalid domain size (>255 bytes)")
	}
	sizeDomain := uint8(len(dst))

	// Z_pad = I2OSP(0, r_in_bytes)
	// l_i_b_str = I2OSP(len_in_bytes, 2)
	// DST_prime = I2OSP(len(DST), 1) || DST
	// b_0 = H(Z_pad || msg || l_i_b_str || I2OSP(0, 1) || DST_prime)
	h.Reset()
	if _, err := h.Write(make([]byte, h.BlockSize())); err != nil {
		return nil, err
	}
	if _, err := h.Write(msg); err != nil {
		return nil, err
	}
	if _, err := h.Write([]byte{uint8(lenInBytes >> 8), uint8(lenInBytes), uint8(0)}); err != nil {
		return nil, err
	}
	if _, err := h.Write(dst); err != nil {
		return nil, err
	}
	if _, err := h.Write([]byte{sizeDomain}); err != nil {
		return nil, err
	}
	b0 := h.Sum(nil)

	// b_1 = H(b_0 || I2OSP(1, 1) || DST_prime)
	h.Reset()
	if _, err := h.Write(b0); err != nil {
		return nil, err
	}
	if _, err := h.Write([]byte{uint8(1)}); err != nil {
		return nil, err
	}
	if _, err := h.Write(dst); err != nil {
		return nil, err
	}
	if _, err := h.Write([]byte{sizeDomain}); err != nil {
		return nil, err
	}
	b1 := h.Sum(nil)

	res := make([]byte, lenInBytes)
	copy(res[:h.Size()], b1)

	for i := 2; i <= ell; i++ {
		// b_i = H(strxor(b_0, b_(i - 1)) || I2OSP(i, 1) || DST_prime)
		h.Reset()
		strxor := make([]byte, h.Size())
		for j := 0; j < h.Size(); j++ {
			strxor[j] = b0[j] ^ b1[j]
		}
		if _, err := h.Write(strxor); err != nil {
			return nil, err
		}
		if _, err := h.Write([]byte{uint8(i)}); err != nil {
			return nil, err
		}
		if _, err := h.Write(dst); err != nil {
			return nil, err
		}
		if _, err := h.Write([]byte{sizeDomain}); err != nil {
			return nil, err
		}
		b1 = h.Sum(nil)
		copy(res[h.Size()*(i-1):h.Size()*i], b1)
	}
	return res, nil
}

// xmd_sha2_256Algo, embeds commonHasher
// Used for tests of the BLS library
type xmd_sha2_256Algo struct {
	*commonHasher
	hash.Hash
	dst []byte
}

// NewXMD_SHA2_256 returns a new instance of XMD-SHA2-256 hasher
func NewXMD_SHA2_256(dst []byte) Hasher {
	return &xmd_sha2_256Algo{
		commonHasher: &commonHasher{
			algo:       XMD_SHA2_256,
			outputSize: 128,
		},
		dst:  dst,
		Hash: sha256.New()}
}

// ComputeHash calculates and returns the XMD-SHA2-256 output of the input byte array.
// It does reset the state
func (s *xmd_sha2_256Algo) ComputeHash(data []byte) Hash {
	h, err := expandMsgXmd(s.Hash, data, s.dst, s.outputSize)
	// failure cases are in hasher construction, not in hasing
	if err != nil {
		panic(err)
	}
	return h
}

// SumHash returns the XMD-SHA2-256 output.
func (s *xmd_sha2_256Algo) SumHash() Hash {
	panic("SumHash not implemented for xmd_sha2_256")
}

// xmd_sha2_512Algo, embeds commonHasher
// Used for tests of the BLS library
type xmd_sha2_512Algo struct {
	*commonHasher
	hash.Hash
	dst []byte
}

// Size returns the XMD-SHA2-256 output
func (s *xmd_sha2_256Algo) Size() int {
	return s.outputSize
}

// New XMD_SHA2_512 returns a new instance of XMD-SHA2-512 hasher
func NewXMD_SHA2_512(dst []byte) Hasher {
	return &xmd_sha2_256Algo{
		commonHasher: &commonHasher{
			algo:       XMD_SHA2_256,
			outputSize: 128,
		},
		dst:  dst,
		Hash: sha512.New()}
}

// ComputeHash calculates and returns the XMD-SHA2-512 output of the input byte array.
// It does reset the state
func (s *xmd_sha2_512Algo) ComputeHash(data []byte) Hash {
	h, err := expandMsgXmd(s.Hash, data, s.dst, s.outputSize)
	// failure cases are in hasher construction, not in hasing
	if err != nil {
		panic(err)
	}
	return h
}

// SumHash returns the XMD-SHA2-512 output.
func (s *xmd_sha2_512Algo) SumHash() Hash {
	panic("SumHash not implemented for xmd_sha2_512")
}

// Size returns the XMD-SHA2-512 output
func (s *xmd_sha2_512Algo) Size() int {
	return s.outputSize
}
