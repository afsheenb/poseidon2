package poseidon2

import (
	"errors"
	"fmt"
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

// Input validation constants
const (
	MaxInputSize       = 64 * 1024 // 64KB limit for DoS protection
	MaxComplexityScore = 1000      // Algorithmic complexity threshold
)

// ValidateInput performs comprehensive input validation with DoS protection
func ValidateInput(data []byte) error {
	if len(data) > MaxInputSize {
		return errors.New("input data too large (max 64KB for DoS protection)")
	}
	
	if len(data) == 0 {
		return errors.New("input data cannot be empty")
	}
	
	// Estimate algorithmic complexity to prevent DoS attacks
	complexity := estimateComplexity(data)
	if complexity > MaxComplexityScore {
		return fmt.Errorf("input complexity too high (%d > %d) - potential DoS attack", complexity, MaxComplexityScore)
	}
	
	return nil
}

// estimateComplexity analyzes input data to detect potential DoS attack vectors
// Returns a complexity score based on various factors
func estimateComplexity(data []byte) int {
	if len(data) == 0 {
		return 0
	}
	
	complexity := 0
	
	// Base complexity: linear in data size
	complexity += len(data) / 100 // 1 point per 100 bytes
	
	// Pattern analysis for potential DoS vectors
	
	// 1. Repetitive patterns (could cause algorithmic issues)
	patternComplexity := analyzePatterns(data)
	complexity += patternComplexity
	
	// 2. High entropy sequences (could indicate crafted input)
	entropyComplexity := analyzeEntropy(data)
	complexity += entropyComplexity
	
	// 3. Edge case byte values (null bytes, max values)
	edgeComplexity := analyzeEdgeCases(data)
	complexity += edgeComplexity
	
	return complexity
}

// analyzePatterns detects repetitive patterns that could cause performance issues
func analyzePatterns(data []byte) int {
	if len(data) < 4 {
		return 0
	}
	
	complexity := 0
	patternCounts := make(map[string]int)
	
	// Check for 4-byte patterns
	for i := 0; i <= len(data)-4; i++ {
		pattern := string(data[i : i+4])
		patternCounts[pattern]++
	}
	
	// High repetition of patterns increases complexity score
	for _, count := range patternCounts {
		if count > 10 { // Pattern repeats more than 10 times
			complexity += count - 10 // Penalty for excessive repetition
		}
	}
	
	return complexity
}

// analyzeEntropy checks for unusual entropy characteristics
func analyzeEntropy(data []byte) int {
	if len(data) < 16 {
		return 0
	}
	
	// Count byte frequency
	frequency := make([]int, 256)
	for _, b := range data {
		frequency[b]++
	}
	
	// Check for unusual distributions
	complexity := 0
	nonZeroBytes := 0
	maxFreq := 0
	
	for _, freq := range frequency {
		if freq > 0 {
			nonZeroBytes++
			if freq > maxFreq {
				maxFreq = freq
			}
		}
	}
	
	// Very low diversity (few unique bytes) could indicate crafted input
	if nonZeroBytes < 4 && len(data) > 32 {
		complexity += 50
	}
	
	// Very high frequency of single byte could indicate crafted input
	if maxFreq > len(data)/2 && len(data) > 16 {
		complexity += 30
	}
	
	return complexity
}

// analyzeEdgeCases detects potentially problematic byte sequences
func analyzeEdgeCases(data []byte) int {
	complexity := 0
	nullBytes := 0
	maxBytes := 0
	
	for _, b := range data {
		if b == 0x00 {
			nullBytes++
		} else if b == 0xFF {
			maxBytes++
		}
	}
	
	// High concentration of null or max bytes could indicate crafted input
	if nullBytes > len(data)/3 {
		complexity += 20
	}
	if maxBytes > len(data)/3 {
		complexity += 20
	}
	
	return complexity
}