package poseidon2

import (
	"fmt"
	"math/big"
	"testing"
)

// nonRecursiveFromUint64 converts a uint64 to Montgomery form without using Mul
func nonRecursiveFromUint64(x uint64) Fr {
	if x == 0 {
		return Zero()
	}
	if x == 1 {
		return One()
	}
	
	// Use big.Int arithmetic to compute (x * R) mod r correctly
	bigX := big.NewInt(int64(x))
	bigR := new(big.Int)
	bigMod := new(big.Int)
	
	// Convert montgomeryR to big.Int
	bigR.SetBytes([]byte{
		byte(montgomeryR[3] >> 56), byte(montgomeryR[3] >> 48), byte(montgomeryR[3] >> 40), byte(montgomeryR[3] >> 32),
		byte(montgomeryR[3] >> 24), byte(montgomeryR[3] >> 16), byte(montgomeryR[3] >> 8), byte(montgomeryR[3]),
		byte(montgomeryR[2] >> 56), byte(montgomeryR[2] >> 48), byte(montgomeryR[2] >> 40), byte(montgomeryR[2] >> 32),
		byte(montgomeryR[2] >> 24), byte(montgomeryR[2] >> 16), byte(montgomeryR[2] >> 8), byte(montgomeryR[2]),
		byte(montgomeryR[1] >> 56), byte(montgomeryR[1] >> 48), byte(montgomeryR[1] >> 40), byte(montgomeryR[1] >> 32),
		byte(montgomeryR[1] >> 24), byte(montgomeryR[1] >> 16), byte(montgomeryR[1] >> 8), byte(montgomeryR[1]),
		byte(montgomeryR[0] >> 56), byte(montgomeryR[0] >> 48), byte(montgomeryR[0] >> 40), byte(montgomeryR[0] >> 32),
		byte(montgomeryR[0] >> 24), byte(montgomeryR[0] >> 16), byte(montgomeryR[0] >> 8), byte(montgomeryR[0]),
	})
	
	// Convert rModulus to big.Int
	bigMod.SetBytes([]byte{
		byte(rModulus[3] >> 56), byte(rModulus[3] >> 48), byte(rModulus[3] >> 40), byte(rModulus[3] >> 32),
		byte(rModulus[3] >> 24), byte(rModulus[3] >> 16), byte(rModulus[3] >> 8), byte(rModulus[3]),
		byte(rModulus[2] >> 56), byte(rModulus[2] >> 48), byte(rModulus[2] >> 40), byte(rModulus[2] >> 32),
		byte(rModulus[2] >> 24), byte(rModulus[2] >> 16), byte(rModulus[2] >> 8), byte(rModulus[2]),
		byte(rModulus[1] >> 56), byte(rModulus[1] >> 48), byte(rModulus[1] >> 40), byte(rModulus[1] >> 32),
		byte(rModulus[1] >> 24), byte(rModulus[1] >> 16), byte(rModulus[1] >> 8), byte(rModulus[1]),
		byte(rModulus[0] >> 56), byte(rModulus[0] >> 48), byte(rModulus[0] >> 40), byte(rModulus[0] >> 32),
		byte(rModulus[0] >> 24), byte(rModulus[0] >> 16), byte(rModulus[0] >> 8), byte(rModulus[0]),
	})
	
	// Compute (x * R) mod r  
	result := new(big.Int)
	result.Mul(bigX, bigR)
	result.Mod(result, bigMod)
	
	// Convert back to Fr
	resultBytes := result.FillBytes(make([]byte, 32))
	return FromBytes([32]byte(resultBytes))
}

// TestFixedConversion tests our fixed conversion function
func TestFixedConversion(t *testing.T) {
	fmt.Printf("Testing fixed conversion functions\n")
	
	// Test that our non-recursive conversion works for small numbers
	two := nonRecursiveFromUint64(2)
	three := nonRecursiveFromUint64(3)
	
	fmt.Printf("nonRecursive 2: %x %x %x %x\n", two[3], two[2], two[1], two[0])
	fmt.Printf("nonRecursive 3: %x %x %x %x\n", three[3], three[2], three[1], three[0])
	
	// Try addition with the corrected conversion
	var sum Fr
	sum.Add(&two, &three)
	five := nonRecursiveFromUint64(5)
	
	fmt.Printf("2 + 3 = %x %x %x %x\n", sum[3], sum[2], sum[1], sum[0])
	fmt.Printf("Expected 5: %x %x %x %x\n", five[3], five[2], five[1], five[0])
	fmt.Printf("Addition works: %t\n", sum.Equal(&five))
}