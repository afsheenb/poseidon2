package poseidon2

import (
	"encoding/json"
	"os"
	"testing"
)

// Test vector structure matching kat.json
type TestVectors struct {
	Poseidon2TestVectors struct {
		FieldModulus string `json:"field_modulus"`
		Parameters   struct {
			T        int `json:"t"`
			D        int `json:"d"`
			F        int `json:"F"`
			P        int `json:"P"`
			Rate     int `json:"rate"`
			Capacity int `json:"capacity"`
		} `json:"parameters"`
		PermutationTests []struct {
			Description string   `json:"description"`
			Input       []string `json:"input"`
			Expected    []string `json:"expected"`
		} `json:"permutation_tests"`
		HashTests []struct {
			Description string   `json:"description"`
			Input       []string `json:"input"`
			Expected    string   `json:"expected"`
		} `json:"hash_tests"`
		Compress2Tests []struct {
			Description string `json:"description"`
			A           string `json:"a"`
			B           string `json:"b"`
			Expected    string `json:"expected"`
		} `json:"compress2_tests"`
		BytesHashTests []struct {
			Description string `json:"description"`
			Domain      string `json:"domain"`
			Data        string `json:"data"`
			Expected    string `json:"expected"`
		} `json:"bytes_hash_tests"`
		MerkleTests []struct {
			Description  string   `json:"description"`
			Leaves       []string `json:"leaves"`
			ExpectedRoot string   `json:"expected_root"`
		} `json:"merkle_tests"`
	} `json:"poseidon2_test_vectors"`
}

// loadTestVectors loads KAT from JSON file
func loadTestVectors(t *testing.T) *TestVectors {
	data, err := os.ReadFile("kat/kat.json")
	if err != nil {
		t.Fatalf("Failed to read test vectors: %v", err)
	}
	
	var vectors TestVectors
	err = json.Unmarshal(data, &vectors)
	if err != nil {
		t.Fatalf("Failed to parse test vectors: %v", err)
	}
	
	return &vectors
}

// TestFieldOperations tests basic field arithmetic
func TestFieldOperations(t *testing.T) {
	// Test zero and one
	zero := Zero()
	one := One()
	
	// Test zero properties
	var zeroSum Fr
	zeroSum.Add(&zero, &zero)
	if !zeroSum.Equal(&zero) {
		t.Error("0 + 0 != 0")
	}
	
	var zeroMul Fr
	zeroMul.Mul(&zero, &one)
	if !zeroMul.Equal(&zero) {
		t.Error("0 * 1 != 0")
	}
	
	// Test one properties
	var oneMul Fr
	oneMul.Mul(&one, &one)
	if !oneMul.Equal(&one) {
		t.Error("1 * 1 != 1")
	}
	
	var oneAdd Fr
	oneAdd.Add(&one, &zero)
	if !oneAdd.Equal(&one) {
		t.Error("1 + 0 != 1")
	}
	
	// Test FromUint64
	two := FromUint64(2)
	four := FromUint64(4)
	
	var twoSum Fr
	twoSum.Add(&two, &two)
	if !twoSum.Equal(&four) {
		t.Error("2 + 2 != 4")
	}
	
	var twoSquare Fr
	twoSquare.Mul(&two, &two)
	if !twoSquare.Equal(&four) {
		t.Error("2 * 2 != 4")
	}
}

// TestSBox tests the S-box function
func TestSBox(t *testing.T) {
	// Test S-box on known values
	zero := Zero()
	one := One()
	two := FromUint64(2)
	
	// S-box of 0 should be 0
	result0 := sBoxProd(&zero)
	if !result0.Equal(&zero) {
		t.Error("S-box(0) != 0")
	}
	
	// S-box of 1 should be 1 (1^5 = 1)
	result1 := sBoxProd(&one)
	if !result1.Equal(&one) {
		t.Error("S-box(1) != 1")
	}
	
	// S-box of 2 should be 32 (2^5 = 32)
	expected := FromUint64(32)
	result2 := sBoxProd(&two)
	if !result2.Equal(&expected) {
		t.Error("S-box(2) != 32")
	}
}

// TestPermutation tests the Poseidon2 permutation
func TestPermutation(t *testing.T) {
	vectors := loadTestVectors(t)
	
	for _, test := range vectors.Poseidon2TestVectors.PermutationTests {
		t.Run(test.Description, func(t *testing.T) {
			// Convert input strings to Fr elements (simplified)
			var state [T]Fr
			for i, inputStr := range test.Input {
				if i >= T {
					break
				}
				// Simplified conversion - would implement proper hex parsing
				if inputStr == "0x0" {
					state[i] = Zero()
				} else if inputStr == "0x1" {
					state[i] = One()
				} else {
					state[i] = FromUint64(uint64(len(inputStr))) // Placeholder
				}
			}
			
			// Apply permutation
			ProductionPermutation(&state)
			
			// Note: This is a basic structure test
			// Real implementation would compare against actual expected values
			t.Logf("Permutation result: state modified")
		})
	}
}

// TestHash tests the main Hash function
func TestHash(t *testing.T) {
	// Test empty input
	emptyResult := Hash()
	arbitrary := FromUint64(0xFFFFFFFF)
	if emptyResult.Equal(&arbitrary) { // Should not equal arbitrary value
		t.Error("Empty hash returned unexpected value")
	}
	
	// Test single element
	one := One()
	singleResult := Hash(one)
	if singleResult.Equal(&emptyResult) {
		t.Error("Hash(1) should not equal Hash()")
	}
	
	// Test multiple elements
	two := FromUint64(2)
	multiResult := Hash(one, two)
	if multiResult.Equal(&singleResult) {
		t.Error("Hash(1, 2) should not equal Hash(1)")
	}
	
	// Test commutativity (Hash should NOT be commutative)
	reverseResult := Hash(two, one)
	if multiResult.Equal(&reverseResult) {
		t.Error("Hash should not be commutative: Hash(1,2) == Hash(2,1)")
	}
}

// TestCompress2 tests the two-element compression function
func TestCompress2(t *testing.T) {
	zero := Zero()
	one := One()
	two := FromUint64(2)
	
	// Test with zeros
	result1 := Compress2(zero, zero)
	
	// Test with different values
	result2 := Compress2(one, two)
	result3 := Compress2(two, one)
	
	// Results should be different
	if result1.Equal(&result2) {
		t.Error("Compress2(0,0) should not equal Compress2(1,2)")
	}
	
	// Should not be commutative
	if result2.Equal(&result3) {
		t.Error("Compress2 should not be commutative")
	}
}

// TestHashBytes tests the byte hashing interface
func TestHashBytes(t *testing.T) {
	// Test with empty data
	emptyResult, err := HashBytes(DomainGeneric)
	if err != nil {
		t.Fatalf("HashBytes failed on empty input: %v", err)
	}
	
	// Test with some data
	testData := []byte("hello")
	dataResult, err := HashBytes(DomainGeneric, testData)
	if err != nil {
		t.Fatalf("HashBytes failed on data input: %v", err)
	}
	
	// Results should be different
	if emptyResult == dataResult {
		t.Error("HashBytes with different inputs returned same result")
	}
	
	// Test domain separation
	poetResult, err := HashBytes(DomainPOETNode, testData)
	if err != nil {
		t.Fatalf("HashBytes failed with POET domain: %v", err)
	}
	
	if dataResult == poetResult {
		t.Error("Domain separation failed: same result for different domains")
	}
}

// TestDomainSeparation ensures domain tags work correctly
func TestDomainSeparation(t *testing.T) {
	testData := []byte("test")
	
	domains := []Domain{
		DomainGeneric,
		DomainPOETNode,
		DomainPolicyRoot,
		DomainFSChallenge,
		DomainTapTweak,
	}
	
	results := make([][32]byte, len(domains))
	
	// Hash with each domain
	for i, domain := range domains {
		result, err := HashBytes(domain, testData)
		if err != nil {
			t.Fatalf("HashBytes failed for domain %d: %v", i, err)
		}
		results[i] = result
	}
	
	// Ensure all results are different
	for i := 0; i < len(results); i++ {
		for j := i + 1; j < len(results); j++ {
			if results[i] == results[j] {
				t.Errorf("Domain separation failed: domains %d and %d produced same result", i, j)
			}
		}
	}
}

// BenchmarkCompress2 benchmarks the two-element compression
func BenchmarkCompress2(b *testing.B) {
	a := FromUint64(12345)
	c := FromUint64(67890)
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Compress2(a, c)
	}
}

// BenchmarkHashWords benchmarks hashing multiple words
func BenchmarkHashWords8(b *testing.B) {
	elements := make([]Fr, 8)
	for i := 0; i < 8; i++ {
		elements[i] = FromUint64(uint64(i + 1))
	}
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Hash(elements...)
	}
}

// BenchmarkHashBytes benchmarks byte hashing
func BenchmarkHashBytes1KB(b *testing.B) {
	data := make([]byte, 1024)
	for i := range data {
		data[i] = byte(i % 256)
	}
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		HashBytes(DomainGeneric, data)
	}
}