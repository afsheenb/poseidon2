package poseidon2

import (
	"fmt"
	"math/big"
	"testing"
)

// Reference Montgomery implementation using big.Int for verification
type refMont struct {
	n  uint     // m.BitLen()
	m  *big.Int // modulus, must be odd
	r2 *big.Int // (1<<2n) mod m
}

func newRefMont(m *big.Int) *refMont {
	if m.Bit(0) != 1 {
		return nil
	}
	n := uint(m.BitLen())
	x := big.NewInt(1)
	x.Sub(x.Lsh(x, n), m)
	return &refMont{n, new(big.Int).Set(m), x.Mod(x.Mul(x, x), m)}
}

func (m refMont) reduce(t *big.Int) *big.Int {
	a := new(big.Int).Set(t)
	for i := uint(0); i < m.n; i++ {
		if a.Bit(0) == 1 {
			a.Add(a, m.m)
		}
		a.Rsh(a, 1)
	}
	if a.Cmp(m.m) >= 0 {
		a.Sub(a, m.m)
	}
	return a
}

// TestReferenceImplementation tests our constants against the reference
func TestReferenceImplementation(t *testing.T) {
	// bn256 scalar field modulus
	rBig := new(big.Int)
	rBig.SetString("21888242871839275222246405745257275088548364400416034343698204186575808495617", 10)
	
	fmt.Printf("Testing reference Montgomery implementation\n")
	fmt.Printf("Modulus r: %s\n", rBig.String())
	
	// Create reference Montgomery
	mr := newRefMont(rBig)
	
	// Test 1 * 1 = 1
	one := big.NewInt(1)
	montOne := mr.reduce(new(big.Int).Mul(one, mr.r2))
	result11 := mr.reduce(new(big.Int).Mul(montOne, montOne))
	final11 := mr.reduce(result11)
	
	fmt.Printf("\nReference: 1 * 1 in Montgomery form:\n")
	fmt.Printf("  montOne = %s\n", montOne.String())
	fmt.Printf("  montOne * montOne (reduced) = %s\n", result11.String())
	fmt.Printf("  final result = %s\n", final11.String())
	fmt.Printf("  Should equal 1: %t\n", final11.Cmp(one) == 0)
	
	// Test 2 * 3 = 6
	two := big.NewInt(2)
	three := big.NewInt(3)
	six := big.NewInt(6)
	
	montTwo := mr.reduce(new(big.Int).Mul(two, mr.r2))
	montThree := mr.reduce(new(big.Int).Mul(three, mr.r2))
	result23 := mr.reduce(new(big.Int).Mul(montTwo, montThree))
	final23 := mr.reduce(result23)
	
	fmt.Printf("\nReference: 2 * 3 in Montgomery form:\n")
	fmt.Printf("  montTwo = %s\n", montTwo.String())
	fmt.Printf("  montThree = %s\n", montThree.String())
	fmt.Printf("  montTwo * montThree (reduced) = %s\n", result23.String())
	fmt.Printf("  final result = %s\n", final23.String())
	fmt.Printf("  Should equal 6: %t\n", final23.Cmp(six) == 0)
	
	// Compare our constants with reference
	fmt.Printf("\nComparing our constants with reference:\n")
	fmt.Printf("Reference R^2 mod r: %s\n", mr.r2.String())
	
	// Convert our R2 to big.Int
	ourR2Big := new(big.Int)
	ourR2Bytes := make([]byte, 32)
	for i := 0; i < 4; i++ {
		for j := 0; j < 8; j++ {
			ourR2Bytes[31-i*8-j] = byte(montgomeryR2[i] >> (j * 8))
		}
	}
	ourR2Big.SetBytes(ourR2Bytes)
	fmt.Printf("Our R2 constant:    %s\n", ourR2Big.String())
	fmt.Printf("R2 constants match:  %t\n", ourR2Big.Cmp(mr.r2) == 0)
}