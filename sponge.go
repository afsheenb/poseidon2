package poseidon2

// Hasher represents the Poseidon2 sponge state for production use
// For t=3: rate=2, capacity=1
type Hasher struct {
	state    [T]Fr // Sponge state
	absorbed int   // Number of elements absorbed in current block
}

// NewHasher creates a new Poseidon2 hasher instance
func NewHasher() *Hasher {
	return &Hasher{
		state:    [T]Fr{Zero(), Zero(), Zero()},
		absorbed: 0,
	}
}

// Absorb absorbs a single field element into the sponge
func (h *Hasher) Absorb(element Fr) {
	// Add element to the appropriate position in the rate portion
	h.state[h.absorbed].Add(&h.state[h.absorbed], &element)
	h.absorbed++
	
	// If rate is full, apply permutation and reset
	if h.absorbed >= 2 { // rate = 2 for t=3
		ProductionPermutation(&h.state)
		h.absorbed = 0
	}
}

// AbsorbMany absorbs multiple field elements
func (h *Hasher) AbsorbMany(elements []Fr) {
	for _, element := range elements {
		h.Absorb(element)
	}
}

// Squeeze extracts one field element from the sponge
// Applies permutation if no elements have been absorbed since last squeeze
func (h *Hasher) Squeeze() Fr {
	// If we've absorbed something since last permutation, apply it now
	if h.absorbed > 0 {
		ProductionPermutation(&h.state)
		h.absorbed = 0
	}
	
	// Return first element of the state (index 0)
	return h.state[0]
}

// Finalize completes the sponge absorption and returns the hash
func (h *Hasher) Finalize() Fr {
	// Apply final permutation if needed
	if h.absorbed > 0 {
		ProductionPermutation(&h.state)
	}
	
	// Return the first element as the hash result
	return h.state[0]
}

// Reset resets the hasher to initial state
func (h *Hasher) Reset() {
	h.state = [T]Fr{Zero(), Zero(), Zero()}
	h.absorbed = 0
}