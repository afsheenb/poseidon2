# Poseidon2 Hash Function

A greenfield implementation of the Poseidon2 cryptographic hash function optimized for the EMZA platform.

## Overview

This package provides a production-grade Poseidon2 hash function operating over the bn256 scalar field (order r). It replaces the heavy `iden3/go-iden3-crypto` dependency with a minimal, purpose-built implementation that achieves cryptographic consistency with our Bulletproofs++ zero-knowledge proof system.

## Features

- **Field-Consistent**: Operates in same field as Bulletproofs++ (bn256-r)
- **Modern Security**: Poseidon2 improvements over original Poseidon
- **Zero Dependencies**: Stdlib only, no external cryptographic libraries
- **TinyGo Compatible**: Compiles with TinyGo for WASM targets
- **Domain Separation**: Built-in domain tagging for different use cases

## Configuration

- **Parameters**: t=3, d=5, F=8, P=56 (optimized for security/performance)
- **Field**: bn256 scalar field (r = 21888242871839275222246405745257275088548364400416034343698204186575808495617)
- **Sponge**: rate=2, capacity=1

## API

### Core Functions

```go
// Hash multiple field elements
func Hash(elements ...Fr) Fr

// Two-to-one compression for Merkle trees  
func Compress2(a, b Fr) Fr

// Hash arbitrary bytes with domain separation
func HashBytes(tag Domain, data ...[]byte) ([32]byte, error)
```

### Domain Separation

```go
const (
    DomainGeneric     Domain = 0x53494742 // "SIGB"
    DomainPOETNode    Domain = 0x5347504e // "SGPN" 
    DomainPolicyRoot  Domain = 0x53475052 // "SGPR"
    DomainFSChallenge Domain = 0x53474653 // "SGFS"
    DomainTapTweak    Domain = 0x53475454 // "SGTT"
)
```

### Field Element Operations

```go
// Create field elements
zero := Zero()
one := One()
x := FromUint64(42)
y := FromBytes([32]byte{...})

// Field arithmetic
sum := x.Add(y)
product := x.Mul(y)
squared := x.Square()
negated := x.Neg()

// Convert back to bytes
bytes := x.ToBytes32()
```

## Usage Examples

### Basic Hashing

```go
// Hash field elements
a := FromUint64(1)
b := FromUint64(2)
result := Hash(a, b)

// Hash bytes with domain separation
data := []byte("hello world")
hash, err := HashBytes(DomainGeneric, data)
if err != nil {
    // handle error
}
```

### Merkle Tree Operations

```go
// Compress two nodes
left := FromBytes([32]byte{...})
right := FromBytes([32]byte{...})
parent := Compress2(left, right)

// Or use byte interface
leftBytes := [32]byte{...}
rightBytes := [32]byte{...}
parentBytes := HashPair(leftBytes, rightBytes)
```

### POET Integration

```go
// Hash policy data with POET domain
policyData := []byte("policy_serialization")
policyHash, err := HashBytes(DomainPOETNode, policyData)

// Generate policy root
nodeHashes := []Fr{...} // POET node hashes
rootHash := HashMany(DomainPolicyRoot, nodeHashes...)
```

## Performance

- **Compress2**: ~X μs per operation
- **HashBytes (1KB)**: ~Y μs per operation  
- **WASM Size**: Contributes ~Z KB to final binary

## Migration from iden3

The new API provides domain separation and field consistency improvements:

```go
// Old (iden3):
hash, err := iden3Poseidon.HashBytes(data)

// New (poseidon2):
hash, err := poseidon2.HashBytes(DomainGeneric, data)
```

## Security Properties

- **Preimage Resistance**: Computationally infeasible to find input for given hash
- **Collision Resistance**: Computationally infeasible to find two inputs with same hash
- **Domain Separation**: Different domains produce independent hash functions
- **Field Consistency**: All operations work in bn256-r field

## Testing

Run the test suite:

```bash
go test -v ./poseidon2
```

Run benchmarks:

```bash
go test -bench=. ./poseidon2
```

Load test vectors:

```bash
go test -v ./poseidon2 -run TestKAT
```

## Integration Notes

- All public functions never mutate input parameters
- Domain separation is enforced - always specify appropriate domain
- Error handling for malformed inputs (no panics in production code)
- Thread-safe by design (no global mutable state)