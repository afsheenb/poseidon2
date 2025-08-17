package poseidon2

import (
	"encoding/hex"
	"fmt"
	"strings"
)

// hexToFr converts a hex string (with or without "0x" prefix) to a Fr element
func hexToFr(hexStr string) (Fr, error) {
	// Remove "0x" prefix if present
	if strings.HasPrefix(hexStr, "0x") || strings.HasPrefix(hexStr, "0X") {
		hexStr = hexStr[2:]
	}
	
	// Pad to 64 characters (32 bytes) if needed
	if len(hexStr) < 64 {
		hexStr = strings.Repeat("0", 64-len(hexStr)) + hexStr
	}
	
	// Convert hex string to bytes
	bytes, err := hex.DecodeString(hexStr)
	if err != nil {
		return Fr{}, fmt.Errorf("failed to decode hex string '%s': %w", hexStr, err)
	}
	
	// Convert to 32-byte array
	var arr [32]byte
	copy(arr[:], bytes)
	
	// Convert to field element
	return FromBytes(arr), nil
}

// hexSliceToFrSlice converts a slice of hex strings to a slice of Fr elements
func hexSliceToFrSlice(hexSlice []string) ([]Fr, error) {
	frSlice := make([]Fr, len(hexSlice))
	for i, hexStr := range hexSlice {
		el, err := hexToFr(hexStr)
		if err != nil {
			return nil, fmt.Errorf("failed to convert element %d: %w", i, err)
		}
		frSlice[i] = el
	}
	return frSlice, nil
}

// frToHex converts a Fr element to a hex string (with 0x prefix)
func frToHex(fr Fr) string {
	bytes := fr.ToBytes32()
	return "0x" + hex.EncodeToString(bytes[:])
}

// frSliceToHexSlice converts a slice of Fr elements to hex strings
func frSliceToHexSlice(frSlice []Fr) []string {
	hexSlice := make([]string, len(frSlice))
	for i, fr := range frSlice {
		hexSlice[i] = frToHex(fr)
	}
	return hexSlice
}