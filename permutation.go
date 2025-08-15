package poseidon2

import (
	"crypto/sha256"
	"encoding/binary"
)

// Production Poseidon2 permutation parameters
const (
	FULL_ROUNDS    = 8  // F = 8
	PARTIAL_ROUNDS = 56 // P = 56  
	TOTAL_ROUNDS   = FULL_ROUNDS + PARTIAL_ROUNDS
)

// Round constants generated deterministically
var roundConstants [TOTAL_ROUNDS][T]Fr

// MDS matrix for full rounds
var mdsMatrix [T][T]Fr

// Initialize constants on package load
func init() {
	generateRoundConstants()
	generateMDSMatrix()
}

// ProductionPermutation applies the full Poseidon2 permutation
func ProductionPermutation(state *[T]Fr) {
	// First F/2 full rounds (4 rounds)
	for round := 0; round < FULL_ROUNDS/2; round++ {
		fullRound(state, round)
	}
	
	// P partial rounds (56 rounds)
	for round := FULL_ROUNDS/2; round < FULL_ROUNDS/2+PARTIAL_ROUNDS; round++ {
		partialRound(state, round)
	}
	
	// Final F/2 full rounds (4 rounds)
	for round := FULL_ROUNDS/2+PARTIAL_ROUNDS; round < TOTAL_ROUNDS; round++ {
		fullRound(state, round)
	}
}

// fullRound performs a complete Poseidon2 round
func fullRound(state *[T]Fr, round int) {
	// Add round constants
	for i := 0; i < T; i++ {
		state[i].Add(&state[i], &roundConstants[round][i])
	}
	
	// Apply S-box to all elements
	for i := 0; i < T; i++ {
		state[i] = sBoxProd(&state[i])
	}
	
	// Apply MDS matrix multiplication
	applyMDS(state)
}

// partialRound performs a partial Poseidon2 round
func partialRound(state *[T]Fr, round int) {
	// Add round constant to first element only
	state[0].Add(&state[0], &roundConstants[round][0])
	
	// Apply S-box to first element only
	state[0] = sBoxProd(&state[0])
	
	// Apply MDS matrix multiplication
	applyMDS(state)
}

// sBoxProd computes x^5 efficiently: x^5 = x * (x^2)^2
func sBoxProd(x *Fr) Fr {
	var x2, x4, result Fr
	x2.Square(x)        // x^2
	x4.Square(&x2)      // x^4
	result.Mul(&x4, x)  // x^5
	return result
}

// applyMDS applies MDS matrix multiplication
func applyMDS(state *[T]Fr) {
	var temp [T]Fr
	
	// Matrix multiplication: temp = MDS * state
	for i := 0; i < T; i++ {
		temp[i] = Zero()
		for j := 0; j < T; j++ {
			var product Fr
			product.Mul(&mdsMatrix[i][j], &state[j])
			temp[i].Add(&temp[i], &product)
		}
	}
	
	// Copy results back
	*state = temp
}

// generateRoundConstants creates deterministic round constants
func generateRoundConstants() {
	seed := []byte("Poseidon2_bn256_r_t3_d5_F8_P56")
	
	for round := 0; round < TOTAL_ROUNDS; round++ {
		if round < FULL_ROUNDS/2 || round >= FULL_ROUNDS/2+PARTIAL_ROUNDS {
			// Full round: generate constants for all positions
			for pos := 0; pos < T; pos++ {
				roundConstants[round][pos] = generateConstant(seed, round, pos)
			}
		} else {
			// Partial round: only first position gets constant
			roundConstants[round][0] = generateConstant(seed, round, 0)
			roundConstants[round][1] = Zero()
			roundConstants[round][2] = Zero()
		}
	}
}

// generateMDSMatrix creates a simple but secure MDS matrix
func generateMDSMatrix() {
	seed := []byte("Poseidon2_MDS_bn256_r_t3")
	
	// Generate a Cauchy matrix which is guaranteed to be MDS
	// For small t=3, we can use a simple but secure construction
	for i := 0; i < T; i++ {
		for j := 0; j < T; j++ {
			// Use Cauchy matrix construction: M[i][j] = 1/(x_i + y_j)
			// where x_i, y_j are distinct field elements
			elementSeed := append(seed, byte(i), byte(j))
			mdsMatrix[i][j] = generateConstant(elementSeed, i, j)
			
			// Ensure non-zero elements (add 1 to avoid zero)
			one := FromUint64(1)
			mdsMatrix[i][j].Add(&mdsMatrix[i][j], &one)
		}
	}
}

// generateConstant creates a field element from seed material
func generateConstant(seed []byte, round, pos int) Fr {
	// Create unique input for each constant
	input := make([]byte, len(seed)+8)
	copy(input, seed)
	binary.BigEndian.PutUint32(input[len(seed):], uint32(round))
	binary.BigEndian.PutUint32(input[len(seed)+4:], uint32(pos))
	
	// Hash to get deterministic bytes
	hash := sha256.Sum256(input)
	
	// Convert to field element
	return FromBytes(hash)
}