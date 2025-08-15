package poseidon2

import (
	"encoding/binary"
	"math/bits"
)

// Fr represents a field element in Montgomery form for bn256-r field
// Elements are stored as 4×64-bit limbs in little-endian order
type Fr [4]uint64

// Field modulus r for bn256 scalar field  
// r = 21888242871839275222246405745257275088548364400416034343698204186575808495617
var rModulus = Fr{
	0x43e1f593f0000001, // limbs[0] - least significant
	0x2833e84879b97091,
	0xb85045b68181585d,
	0x30644e72e131a029, // limbs[3] - most significant
}

// Montgomery constant -(r^-1) mod 2^64 for CIOS reduction
const nPrime = 0xc2e1f593efffffff

// Montgomery constants
var (
	// R = 2^256 mod r (Montgomery radix)
	montgomeryR = Fr{
		0xac96341c4ffffffb,
		0x36fc76959f60cd29,
		0x666ea36f7879462e,
		0x0e0a77c19a07df2f,
	}

	// R2 = R^2 mod r = 2^512 mod r (for conversion to Montgomery form)
	montgomeryR2 = Fr{
		0x1bb8e645ae216da7,
		0x53fe3ab1e35c59e3,
		0x8c49833d53bb8085,
		0x0216d0b17f4e44a5,
	}
)

// Zero returns the additive identity (0) in Montgomery form
func Zero() Fr {
	return Fr{0, 0, 0, 0}
}

// One returns the multiplicative identity (1) in Montgomery form  
func One() Fr {
	return montgomeryR // 1*R mod r = R
}

// FromUint64 converts a uint64 to Montgomery form
func FromUint64(x uint64) Fr {
	if x == 0 {
		return Zero()
	}
	if x == 1 {
		return One()
	}
	
	// Convert x to Montgomery form by using the Montgomery multiplication
	// To get x*R, we compute Mul(x, R^2) = x * R^2 * R^(-1) = x * R
	xFr := Fr{x, 0, 0, 0} // Regular form of x
	var result Fr
	result.Mul(&xFr, &montgomeryR2) // Use R^2 constant for conversion
	return result
}


// FromBytes converts a 32-byte big-endian representation to Montgomery form
func FromBytes(data [32]byte) Fr {
	// Convert big-endian bytes to limbs (little-endian)
	limbs := Fr{
		binary.BigEndian.Uint64(data[24:32]), // least significant
		binary.BigEndian.Uint64(data[16:24]),
		binary.BigEndian.Uint64(data[8:16]),
		binary.BigEndian.Uint64(data[0:8]),   // most significant
	}
	
	// Reduce modulo r if necessary
	limbs.reduce()
	
	// Convert to Montgomery form
	var result Fr
	result.Mul(&limbs, &montgomeryR2)
	return result
}

// ToBytes32 converts from Montgomery form to 32-byte big-endian representation
func (f Fr) ToBytes32() [32]byte {
	// Convert from Montgomery form to regular form
	one := Fr{1, 0, 0, 0}
	var regular Fr
	regular.Mul(&f, &one) // f * 1 * R^(-1) = f * R^(-1) = regular form
	
	var result [32]byte
	binary.BigEndian.PutUint64(result[24:32], regular[0]) // least significant
	binary.BigEndian.PutUint64(result[16:24], regular[1])
	binary.BigEndian.PutUint64(result[8:16], regular[2])
	binary.BigEndian.PutUint64(result[0:8], regular[3])   // most significant
	
	return result
}

// Mul performs Montgomery multiplication: (a * b * R^(-1)) mod r
// Uses simple bit-by-bit Montgomery reduction algorithm (reference implementation)
func (z *Fr) Mul(x, y *Fr) *Fr {
	// First compute the regular multiplication x * y
	var t [8]uint64 // Need 8 limbs for 256-bit * 256-bit multiplication
	
	// Multi-precision multiplication: t = x * y
	for i := 0; i < 4; i++ {
		var carry uint64
		for j := 0; j < 4; j++ {
			hi, lo := bits.Mul64(x[i], y[j])
			sum, c1 := bits.Add64(t[i+j], lo, 0)
			sum, c2 := bits.Add64(sum, carry, 0)
			t[i+j] = sum
			carry = hi + c1 + c2
		}
		t[i+4] = carry
	}
	
	// Montgomery reduction: for each bit position, if lowest bit is 1, add modulus
	for i := 0; i < 256; i++ { // 256 bits to reduce
		if t[0]&1 == 1 {
			// Add modulus: t += r
			var carry uint64
			for j := 0; j < 4; j++ {
				sum, c := bits.Add64(t[j], rModulus[j], carry)
				t[j] = sum
				carry = c
			}
			// Propagate carry through upper limbs
			for j := 4; j < 8 && carry > 0; j++ {
				sum, c := bits.Add64(t[j], 0, carry)
				t[j] = sum
				carry = c
			}
		}
		// Right shift by 1 bit: t >>= 1
		for j := 0; j < 7; j++ {
			t[j] = (t[j] >> 1) | (t[j+1] << 63)
		}
		t[7] >>= 1
	}
	
	// Final conditional subtraction: if t >= r, subtract r
	// Result is now in t[0..3]
	z[0], z[1], z[2], z[3] = t[0], t[1], t[2], t[3]
	
	var diff Fr
	borrow := diff.sub(z, &rModulus)
	
	// If no borrow (t >= r), use the subtracted result
	z.cmov(z, &diff, 1-borrow)
	
	return z
}

// Add performs field addition: (a + b) mod r
func (z *Fr) Add(x, y *Fr) *Fr {
	var carry uint64
	z[0], carry = bits.Add64(x[0], y[0], 0)
	z[1], carry = bits.Add64(x[1], y[1], carry)
	z[2], carry = bits.Add64(x[2], y[2], carry)
	z[3], carry = bits.Add64(x[3], y[3], carry)
	
	// If there's overflow or result >= r, subtract r
	var temp Fr
	borrow := temp.sub(z, &rModulus)
	// Subtract if there was overflow (carry=1) OR if z >= r (borrow=0)
	// borrow=1 means z < r, borrow=0 means z >= r
	shouldSubtract := carry | (1 - borrow)
	z.cmov(z, &temp, shouldSubtract)
	return z
}

// Sub performs field subtraction: (a - b) mod r
func (z *Fr) Sub(x, y *Fr) *Fr {
	borrow := z.sub(x, y)
	
	// If there was a borrow, add r to get positive result
	var temp Fr
	temp.add(z, &rModulus)
	z.cmov(z, &temp, borrow)
	return z
}

// Neg performs field negation: (-a) mod r
func (z *Fr) Neg(x *Fr) *Fr {
	if x.IsZero() {
		*z = Zero()
		return z
	}
	z.sub(&rModulus, x)
	return z
}

// Square performs field squaring: (a^2) mod r
func (z *Fr) Square(x *Fr) *Fr {
	return z.Mul(x, x)
}

// Equal checks if two field elements are equal
func (f *Fr) Equal(other *Fr) bool {
	return f[0] == other[0] && f[1] == other[1] && f[2] == other[2] && f[3] == other[3]
}

// IsZero checks if the field element is zero
func (f *Fr) IsZero() bool {
	return f[0] == 0 && f[1] == 0 && f[2] == 0 && f[3] == 0
}

// Set copies another field element
func (z *Fr) Set(x *Fr) *Fr {
	z[0], z[1], z[2], z[3] = x[0], x[1], x[2], x[3]
	return z
}

// Helper functions for constant-time operations

// sub performs z = x - y and returns the final borrow
func (z *Fr) sub(x, y *Fr) uint64 {
	var borrow uint64
	z[0], borrow = bits.Sub64(x[0], y[0], 0)
	z[1], borrow = bits.Sub64(x[1], y[1], borrow)
	z[2], borrow = bits.Sub64(x[2], y[2], borrow)
	z[3], borrow = bits.Sub64(x[3], y[3], borrow)
	return borrow
}

// add performs z = x + y (without reduction)
func (z *Fr) add(x, y *Fr) uint64 {
	var carry uint64
	z[0], carry = bits.Add64(x[0], y[0], 0)
	z[1], carry = bits.Add64(x[1], y[1], carry)
	z[2], carry = bits.Add64(x[2], y[2], carry)
	z[3], carry = bits.Add64(x[3], y[3], carry)
	return carry
}

// cmov sets z = y if cond == 0, z = x if cond == 1 (constant-time)
func (z *Fr) cmov(y, x *Fr, cond uint64) {
	mask := -cond // 0xFFFFFFFFFFFFFFFF if cond == 1, 0 if cond == 0
	z[0] = y[0] ^ ((y[0] ^ x[0]) & mask)
	z[1] = y[1] ^ ((y[1] ^ x[1]) & mask)
	z[2] = y[2] ^ ((y[2] ^ x[2]) & mask)
	z[3] = y[3] ^ ((y[3] ^ x[3]) & mask)
}

// reduce ensures the result is < r (for internal use)
func (z *Fr) reduce() {
	var temp Fr
	borrow := temp.sub(z, &rModulus)
	z.cmov(z, &temp, 1-borrow)
}