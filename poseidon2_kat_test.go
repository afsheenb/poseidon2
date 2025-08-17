package poseidon2

import (
	"encoding/hex"
	"encoding/json"
	"io/ioutil"
	"os"
	"strconv"
	"testing"
)

// KAT test vector structures
type PermutationKATVector struct {
	Description string   `json:"description"`
	Input       []string `json:"input"`
	Expected    []string `json:"expected"`
}

type HashKATVector struct {
	Description string   `json:"description"`
	Input       []string `json:"input"`
	Expected    string   `json:"expected"`
}

type Compress2KATVector struct {
	Description string `json:"description"`
	A           string `json:"a"`
	B           string `json:"b"`
	Expected    string `json:"expected"`
}

type BytesHashKATVector struct {
	Description string `json:"description"`
	Domain      string `json:"domain"`
	Data        string `json:"data"`
	Expected    string `json:"expected"`
}

type PoseidonKATVectors struct {
	Poseidon2TestVectors struct {
		FieldModulus     string                   `json:"field_modulus"`
		Parameters       map[string]int          `json:"parameters"`
		PermutationTests []PermutationKATVector  `json:"permutation_tests"`
		HashTests        []HashKATVector         `json:"hash_tests"`
		Compress2Tests   []Compress2KATVector    `json:"compress2_tests"`
		BytesHashTests   []BytesHashKATVector    `json:"bytes_hash_tests"`
	} `json:"poseidon2_test_vectors"`
}

// loadKATVectors loads the KAT vectors from JSON file
func loadKATVectors(t *testing.T) *PoseidonKATVectors {
	file, err := os.Open("kat/kat.json")
	if err != nil {
		t.Fatalf("Failed to open KAT vectors file: %v", err)
	}
	defer file.Close()

	data, err := ioutil.ReadAll(file)
	if err != nil {
		t.Fatalf("Failed to read KAT vectors: %v", err)
	}

	var vectors PoseidonKATVectors
	err = json.Unmarshal(data, &vectors)
	if err != nil {
		t.Fatalf("Failed to unmarshal KAT vectors: %v", err)
	}

	return &vectors
}

// TestPoseidon2PermutationKAT tests the Poseidon2 permutation against known answer test vectors
func TestPoseidon2PermutationKAT(t *testing.T) {
	vectors := loadKATVectors(t)

	for _, tv := range vectors.Poseidon2TestVectors.PermutationTests {
		t.Run(tv.Description, func(t *testing.T) {
			// Parse input hex strings to Fr elements
			inputState, err := hexSliceToFrSlice(tv.Input)
			if err != nil {
				t.Fatalf("Failed to parse input hex strings: %v", err)
			}

			// Parse expected hex strings to Fr elements
			expectedState, err := hexSliceToFrSlice(tv.Expected)
			if err != nil {
				t.Fatalf("Failed to parse expected hex strings: %v", err)
			}

			// Convert to state array and apply permutation
			if len(inputState) != T {
				t.Fatalf("Input state has wrong length: got %d, want %d", len(inputState), T)
			}
			
			var state [T]Fr
			copy(state[:], inputState)

			// Apply the actual Poseidon2 permutation
			ProductionPermutation(&state)

			// Compare with expected results
			if len(expectedState) != T {
				t.Fatalf("Expected state has wrong length: got %d, want %d", len(expectedState), T)
			}

			for i := 0; i < T; i++ {
				if !state[i].Equal(&expectedState[i]) {
					t.Errorf("State element at index %d does not match.\nExpected: %s\nGot:      %s",
						i, frToHex(expectedState[i]), frToHex(state[i]))
				}
			}
		})
	}
}

// TestPoseidon2HashKAT tests the Hash function against KAT vectors
func TestPoseidon2HashKAT(t *testing.T) {
	vectors := loadKATVectors(t)

	for _, tv := range vectors.Poseidon2TestVectors.HashTests {
		t.Run(tv.Description, func(t *testing.T) {
			// Parse input elements
			var inputElements []Fr
			if len(tv.Input) > 0 {
				var err error
				inputElements, err = hexSliceToFrSlice(tv.Input)
				if err != nil {
					t.Fatalf("Failed to parse input elements: %v", err)
				}
			}

			// Parse expected result
			expectedResult, err := hexToFr(tv.Expected)
			if err != nil {
				t.Fatalf("Failed to parse expected result: %v", err)
			}

			// Compute hash using actual implementation
			var computedResult Fr
			if len(inputElements) == 0 {
				computedResult = Hash()
			} else {
				computedResult = Hash(inputElements...)
			}

			// Compare results
			if !computedResult.Equal(&expectedResult) {
				t.Errorf("Hash result does not match.\nExpected: %s\nGot:      %s",
					frToHex(expectedResult), frToHex(computedResult))
			}
		})
	}
}

// TestPoseidon2Compress2KAT tests the Compress2 function against KAT vectors
func TestPoseidon2Compress2KAT(t *testing.T) {
	vectors := loadKATVectors(t)

	for _, tv := range vectors.Poseidon2TestVectors.Compress2Tests {
		t.Run(tv.Description, func(t *testing.T) {
			// Parse input elements
			a, err := hexToFr(tv.A)
			if err != nil {
				t.Fatalf("Failed to parse element A: %v", err)
			}

			b, err := hexToFr(tv.B)
			if err != nil {
				t.Fatalf("Failed to parse element B: %v", err)
			}

			// Parse expected result
			expectedResult, err := hexToFr(tv.Expected)
			if err != nil {
				t.Fatalf("Failed to parse expected result: %v", err)
			}

			// Compute using actual implementation
			computedResult := Compress2(a, b)

			// Compare results
			if !computedResult.Equal(&expectedResult) {
				t.Errorf("Compress2 result does not match.\nExpected: %s\nGot:      %s",
					frToHex(expectedResult), frToHex(computedResult))
			}
		})
	}
}

// TestPoseidon2BytesHashKAT tests the HashBytes function against KAT vectors
func TestPoseidon2BytesHashKAT(t *testing.T) {
	vectors := loadKATVectors(t)

	for _, tv := range vectors.Poseidon2TestVectors.BytesHashTests {
		t.Run(tv.Description, func(t *testing.T) {
			// Parse domain
			domainStr := tv.Domain
			if len(domainStr) > 2 && domainStr[:2] == "0x" {
				domainStr = domainStr[2:]
			}
			domainVal, err := strconv.ParseUint(domainStr, 16, 64)
			if err != nil {
				t.Fatalf("Failed to parse domain: %v", err)
			}
			domain := Domain(domainVal)

			// Parse data
			var data []byte
			if tv.Data != "" {
				data, err = hex.DecodeString(tv.Data)
				if err != nil {
					t.Fatalf("Failed to parse data: %v", err)
				}
			}

			// Parse expected result
			expectedStr := tv.Expected
			if len(expectedStr) > 2 && expectedStr[:2] == "0x" {
				expectedStr = expectedStr[2:]
			}
			expected, err := hex.DecodeString(expectedStr)
			if err != nil {
				t.Fatalf("Failed to parse expected result: %v", err)
			}

			// Compute using actual implementation
			var computed [32]byte
			if len(data) == 0 {
				computed, err = HashBytes(domain)
			} else {
				computed, err = HashBytes(domain, data)
			}
			if err != nil {
				t.Fatalf("HashBytes failed: %v", err)
			}

			// Compare results
			if len(expected) != 32 {
				t.Fatalf("Expected result has wrong length: got %d, want 32", len(expected))
			}
			
			var expectedArray [32]byte
			copy(expectedArray[:], expected)
			
			if computed != expectedArray {
				t.Errorf("HashBytes result does not match.\nExpected: %x\nGot:      %x",
					expectedArray, computed)
			}
		})
	}
}

// TestKATIntegrity verifies the integrity of the KAT vectors themselves
func TestKATIntegrity(t *testing.T) {
	vectors := loadKATVectors(t)

	// Check field modulus matches
	expectedModulus := "0x30644e72e131a029b85045b68181585d2833e84879b97091b85045b68181585d"
	if vectors.Poseidon2TestVectors.FieldModulus != expectedModulus {
		t.Errorf("Field modulus mismatch: got %s, want %s",
			vectors.Poseidon2TestVectors.FieldModulus, expectedModulus)
	}

	// Check parameters match our constants
	params := vectors.Poseidon2TestVectors.Parameters
	if params["t"] != T {
		t.Errorf("Parameter t mismatch: got %d, want %d", params["t"], T)
	}
	if params["d"] != D {
		t.Errorf("Parameter d mismatch: got %d, want %d", params["d"], D)
	}
	if params["F"] != F {
		t.Errorf("Parameter F mismatch: got %d, want %d", params["F"], F)
	}
	if params["P"] != P {
		t.Errorf("Parameter P mismatch: got %d, want %d", params["P"], P)
	}

	// Verify we have test vectors
	if len(vectors.Poseidon2TestVectors.PermutationTests) == 0 {
		t.Error("No permutation test vectors found")
	}
	if len(vectors.Poseidon2TestVectors.HashTests) == 0 {
		t.Error("No hash test vectors found")
	}
	if len(vectors.Poseidon2TestVectors.Compress2Tests) == 0 {
		t.Error("No compress2 test vectors found")
	}
	if len(vectors.Poseidon2TestVectors.BytesHashTests) == 0 {
		t.Error("No bytes hash test vectors found")
	}

	t.Logf("KAT vectors loaded successfully:")
	t.Logf("  Permutation tests: %d", len(vectors.Poseidon2TestVectors.PermutationTests))
	t.Logf("  Hash tests: %d", len(vectors.Poseidon2TestVectors.HashTests))
	t.Logf("  Compress2 tests: %d", len(vectors.Poseidon2TestVectors.Compress2Tests))
	t.Logf("  BytesHash tests: %d", len(vectors.Poseidon2TestVectors.BytesHashTests))
}

// BenchmarkKATTests provides performance baseline for KAT operations
func BenchmarkPermutationKAT(b *testing.B) {
	// Use the first permutation test vector
	inputState := [T]Fr{Zero(), Zero(), Zero()}
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		state := inputState
		ProductionPermutation(&state)
	}
}

func BenchmarkHashKAT(b *testing.B) {
	one := One()
	two := FromUint64(2)
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Hash(one, two)
	}
}

func BenchmarkCompress2KAT(b *testing.B) {
	one := One()
	two := FromUint64(2)
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Compress2(one, two)
	}
}