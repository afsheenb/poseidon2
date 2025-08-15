package poseidon2

// Poseidon2 configuration constants
const (
	T = 3  // Sponge width (rate=2, capacity=1)
	D = 5  // S-box degree (x^5)
	F = 8  // Full rounds
	P = 56 // Partial rounds
)

// Domain represents a domain separation tag
type Domain uint64

// Domain separation constants for EMZA platform
const (
	DomainGeneric     Domain = 0x53494742 // "SIGB"
	DomainPOETNode    Domain = 0x5347504e // "SGPN" 
	DomainPolicyRoot  Domain = 0x53475052 // "SGPR"
	DomainFSChallenge Domain = 0x53474653 // "SGFS"
	DomainTapTweak    Domain = 0x53475454 // "SGTT"
)