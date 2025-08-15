package poseidon2

import (
	"fmt" 
	"testing"
)

// TestZeroAddition tests adding zero to itself
func TestZeroAddition(t *testing.T) {
	zero1 := Zero()
	zero2 := Zero()
	
	var result Fr
	result.Add(&zero1, &zero2)
	
	fmt.Printf("0 + 0 = %x %x %x %x\n", result[3], result[2], result[1], result[0])
	fmt.Printf("Expected:  %x %x %x %x\n", zero1[3], zero1[2], zero1[1], zero1[0])
	fmt.Printf("Zero addition works: %t\n", result.Equal(&zero1))
}

// TestOneAddition tests adding one to zero
func TestOneAddition(t *testing.T) {
	zero := Zero()
	one := One()
	
	var result Fr
	result.Add(&one, &zero)
	
	fmt.Printf("1 + 0 = %x %x %x %x\n", result[3], result[2], result[1], result[0])
	fmt.Printf("Expected: %x %x %x %x\n", one[3], one[2], one[1], one[0])
	fmt.Printf("One + zero works: %t\n", result.Equal(&one))
}

// TestDirectAddition tests addition without conversion
func TestDirectAddition(t *testing.T) {
	// Create two simple values directly in Montgomery form
	a := Fr{100, 0, 0, 0}  // Small value
	b := Fr{200, 0, 0, 0}  // Small value
	
	var result Fr
	result.Add(&a, &b)
	expected := Fr{300, 0, 0, 0}
	
	fmt.Printf("Direct 100 + 200 = %x %x %x %x\n", result[3], result[2], result[1], result[0])
	fmt.Printf("Expected:           %x %x %x %x\n", expected[3], expected[2], expected[1], expected[0])
	fmt.Printf("Direct addition works: %t\n", result.Equal(&expected))
}