package poseidon2

import (
	"errors"
)

// Hash computes Poseidon2 hash of multiple field elements
// Uses sponge construction with domain separation
func Hash(elements ...Fr) Fr {
	if len(elements) == 0 {
		// Return hash of empty input (zero)
		hasher := NewHasher()
		return hasher.Finalize()
	}
	
	hasher := NewHasher()
	hasher.AbsorbMany(elements)
	return hasher.Finalize()
}

// Compress2 performs two-to-one hash compression for Merkle trees
// Optimized for tree construction: Hash(a, b)
func Compress2(a, b Fr) Fr {
	hasher := NewHasher()
	hasher.Absorb(a)
	hasher.Absorb(b)
	return hasher.Finalize()
}

// HashBytes hashes arbitrary byte data with domain separation
// Domain tag is absorbed first, then data is parsed as field elements
func HashBytes(tag Domain, data ...[]byte) ([32]byte, error) {
	hasher := NewHasher()
	
	// Absorb domain tag first
	domainFr := FromUint64(uint64(tag))
	hasher.Absorb(domainFr)
	
	// Process each data chunk
	for _, chunk := range data {
		if len(chunk) == 0 {
			continue
		}
		
		// Convert bytes to field elements
		// Process in 31-byte chunks to stay under field modulus
		for i := 0; i < len(chunk); i += 31 {
			end := i + 31
			if end > len(chunk) {
				end = len(chunk)
			}
			
			// Pad to 32 bytes and convert to field element
			var padded [32]byte
			copy(padded[32-(end-i):], chunk[i:end]) // Right-align in 32-byte array
			
			element := FromBytes(padded)
			hasher.Absorb(element)
		}
	}
	
	// Get hash result and convert to bytes
	result := hasher.Finalize()
	return result.ToBytes32(), nil
}

// HashBytesSimple is a simplified version for single byte slice
func HashBytesSimple(tag Domain, data []byte) ([32]byte, error) {
	return HashBytes(tag, data)
}

// Utility functions for common operations

// HashPair hashes two 32-byte values (useful for Merkle tree operations)
func HashPair(left, right [32]byte) [32]byte {
	leftFr := FromBytes(left)
	rightFr := FromBytes(right)
	result := Compress2(leftFr, rightFr)
	return result.ToBytes32()
}

// HashMany hashes multiple field elements with domain separation
func HashMany(tag Domain, elements ...Fr) Fr {
	hasher := NewHasher()
	
	// Absorb domain tag first
	domainFr := FromUint64(uint64(tag))
	hasher.Absorb(domainFr)
	
	// Absorb all elements
	hasher.AbsorbMany(elements)
	
	return hasher.Finalize()
}

// ValidateInput performs basic input validation
func ValidateInput(data []byte) error {
	if len(data) > 1024*1024 { // 1MB limit
		return errors.New("input data too large (max 1MB)")
	}
	return nil
}