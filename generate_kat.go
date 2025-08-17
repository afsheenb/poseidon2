package poseidon2

import (
	"encoding/json"
	"fmt"
)

// TestVector represents a single KAT test case
type TestVector struct {
	Description string   `json:"description"`
	Input       []string `json:"input"`
	Expected    []string `json:"expected"`
}

// HashTestVector represents a hash function test case
type HashTestVector struct {
	Description string   `json:"description"`
	Input       []string `json:"input"`
	Expected    string   `json:"expected"`
}

// Compress2TestVector represents a two-element compression test case
type Compress2TestVector struct {
	Description string `json:"description"`
	A           string `json:"a"`
	B           string `json:"b"`
	Expected    string `json:"expected"`
}

// BytesHashTestVector represents a bytes hash test case
type BytesHashTestVector struct {
	Description string `json:"description"`
	Domain      string `json:"domain"`
	Data        string `json:"data"`
	Expected    string `json:"expected"`
}

// GeneratedKAT represents the complete set of generated KAT vectors
type GeneratedKAT struct {
	FieldModulus     string                `json:"field_modulus"`
	Parameters       map[string]int        `json:"parameters"`
	PermutationTests []TestVector          `json:"permutation_tests"`
	HashTests        []HashTestVector      `json:"hash_tests"`
	Compress2Tests   []Compress2TestVector `json:"compress2_tests"`
	BytesHashTests   []BytesHashTestVector `json:"bytes_hash_tests"`
}

// GenerateKATVectors generates Known Answer Test vectors using the actual implementation
func GenerateKATVectors() (*GeneratedKAT, error) {
	kat := &GeneratedKAT{
		FieldModulus: "0x30644e72e131a029b85045b68181585d2833e84879b97091b85045b68181585d",
		Parameters: map[string]int{
			"t":          T,
			"d":          5, // S-box degree
			"F":          FULL_ROUNDS,
			"P":          PARTIAL_ROUNDS,
			"rate":       2,
			"capacity":   1,
		},
	}
	
	// Generate permutation test vectors
	permTests, err := generatePermutationVectors()
	if err != nil {
		return nil, fmt.Errorf("failed to generate permutation vectors: %w", err)
	}
	kat.PermutationTests = permTests
	
	// Generate hash test vectors
	hashTests, err := generateHashVectors()
	if err != nil {
		return nil, fmt.Errorf("failed to generate hash vectors: %w", err)
	}
	kat.HashTests = hashTests
	
	// Generate Compress2 test vectors
	compress2Tests, err := generateCompress2Vectors()
	if err != nil {
		return nil, fmt.Errorf("failed to generate compress2 vectors: %w", err)
	}
	kat.Compress2Tests = compress2Tests
	
	// Generate bytes hash test vectors
	bytesHashTests, err := generateBytesHashVectors()
	if err != nil {
		return nil, fmt.Errorf("failed to generate bytes hash vectors: %w", err)
	}
	kat.BytesHashTests = bytesHashTests
	
	return kat, nil
}

func generatePermutationVectors() ([]TestVector, error) {
	var vectors []TestVector
	
	// Test 1: Zero state permutation
	zeroState := [T]Fr{Zero(), Zero(), Zero()}
	ProductionPermutation(&zeroState)
	vectors = append(vectors, TestVector{
		Description: "Zero state permutation",
		Input:       []string{"0x0", "0x0", "0x0"},
		Expected:    frSliceToHexSlice(zeroState[:]),
	})
	
	// Test 2: Unit elements permutation
	oneState := [T]Fr{One(), One(), One()}
	ProductionPermutation(&oneState)
	vectors = append(vectors, TestVector{
		Description: "All ones permutation",
		Input:       []string{"0x1", "0x1", "0x1"},
		Expected:    frSliceToHexSlice(oneState[:]),
	})
	
	// Test 3: Sequential elements
	seqState := [T]Fr{FromUint64(1), FromUint64(2), FromUint64(3)}
	ProductionPermutation(&seqState)
	vectors = append(vectors, TestVector{
		Description: "Sequential elements [1, 2, 3]",
		Input:       []string{"0x1", "0x2", "0x3"},
		Expected:    frSliceToHexSlice(seqState[:]),
	})
	
	// Test 4: Large values
	largeState := [T]Fr{
		FromUint64(0xFFFFFFFFFFFFFFFF),
		FromUint64(0x123456789ABCDEF0),
		FromUint64(0xFEDCBA0987654321),
	}
	ProductionPermutation(&largeState)
	vectors = append(vectors, TestVector{
		Description: "Large values permutation",
		Input: []string{
			"0xFFFFFFFFFFFFFFFF",
			"0x123456789ABCDEF0",
			"0xFEDCBA0987654321",
		},
		Expected: frSliceToHexSlice(largeState[:]),
	})
	
	return vectors, nil
}

func generateHashVectors() ([]HashTestVector, error) {
	var vectors []HashTestVector
	
	// Test 1: Hash empty input
	emptyResult := Hash()
	vectors = append(vectors, HashTestVector{
		Description: "Hash empty input",
		Input:       []string{},
		Expected:    frToHex(emptyResult),
	})
	
	// Test 2: Hash single element
	one := One()
	singleResult := Hash(one)
	vectors = append(vectors, HashTestVector{
		Description: "Hash single element [1]",
		Input:       []string{"0x1"},
		Expected:    frToHex(singleResult),
	})
	
	// Test 3: Hash two elements
	two := FromUint64(2)
	doubleResult := Hash(one, two)
	vectors = append(vectors, HashTestVector{
		Description: "Hash two elements [1, 2]",
		Input:       []string{"0x1", "0x2"},
		Expected:    frToHex(doubleResult),
	})
	
	// Test 4: Hash multiple elements
	multiResult := Hash(one, two, FromUint64(3), FromUint64(4), FromUint64(5))
	vectors = append(vectors, HashTestVector{
		Description: "Hash multiple elements [1, 2, 3, 4, 5]",
		Input:       []string{"0x1", "0x2", "0x3", "0x4", "0x5"},
		Expected:    frToHex(multiResult),
	})
	
	return vectors, nil
}

func generateCompress2Vectors() ([]Compress2TestVector, error) {
	var vectors []Compress2TestVector
	
	// Test 1: Compress two zeros
	zero := Zero()
	zeroResult := Compress2(zero, zero)
	vectors = append(vectors, Compress2TestVector{
		Description: "Compress2 zero inputs",
		A:           "0x0",
		B:           "0x0",
		Expected:    frToHex(zeroResult),
	})
	
	// Test 2: Compress one and two
	one := One()
	two := FromUint64(2)
	oneTwo := Compress2(one, two)
	vectors = append(vectors, Compress2TestVector{
		Description: "Compress2 one and two",
		A:           "0x1",
		B:           "0x2",
		Expected:    frToHex(oneTwo),
	})
	
	// Test 3: Compress large values
	large1 := FromUint64(0x123456789ABCDEF0)
	large2 := FromUint64(0xFEDCBA0987654321)
	largeResult := Compress2(large1, large2)
	vectors = append(vectors, Compress2TestVector{
		Description: "Compress2 large values",
		A:           "0x123456789ABCDEF0",
		B:           "0xFEDCBA0987654321",
		Expected:    frToHex(largeResult),
	})
	
	return vectors, nil
}

func generateBytesHashVectors() ([]BytesHashTestVector, error) {
	var vectors []BytesHashTestVector
	
	// Test 1: Hash empty bytes with generic domain
	emptyResult, err := HashBytes(DomainGeneric)
	if err != nil {
		return nil, err
	}
	vectors = append(vectors, BytesHashTestVector{
		Description: "Hash empty bytes with generic domain",
		Domain:      fmt.Sprintf("0x%08x", uint32(DomainGeneric)),
		Data:        "",
		Expected:    fmt.Sprintf("0x%x", emptyResult),
	})
	
	// Test 2: Hash "hello" with generic domain
	hello := []byte("hello")
	helloResult, err := HashBytes(DomainGeneric, hello)
	if err != nil {
		return nil, err
	}
	vectors = append(vectors, BytesHashTestVector{
		Description: "Hash 'hello' with generic domain",
		Domain:      fmt.Sprintf("0x%08x", uint32(DomainGeneric)),
		Data:        fmt.Sprintf("%x", hello),
		Expected:    fmt.Sprintf("0x%x", helloResult),
	})
	
	// Test 3: Hash with POET domain
	poetResult, err := HashBytes(DomainPOETNode, hello)
	if err != nil {
		return nil, err
	}
	vectors = append(vectors, BytesHashTestVector{
		Description: "Hash 'hello' with POET domain",
		Domain:      fmt.Sprintf("0x%08x", uint32(DomainPOETNode)),
		Data:        fmt.Sprintf("%x", hello),
		Expected:    fmt.Sprintf("0x%x", poetResult),
	})
	
	return vectors, nil
}

// GenerateKATJSON generates KAT vectors and returns them as JSON string
func GenerateKATJSON() (string, error) {
	kat, err := GenerateKATVectors()
	if err != nil {
		return "", err
	}
	
	jsonData, err := json.MarshalIndent(kat, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to marshal KAT to JSON: %w", err)
	}
	
	return string(jsonData), nil
}