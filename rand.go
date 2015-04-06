package main

import (
	"crypto/rand"
)

// CryptoRandomReader generates cryptographically random data
type CryptoRandomReader struct{}

// Read will put random data into p, it will try to fill p entirely with random data
func (r *CryptoRandomReader) Read(p []byte) (n int, err error) {
	return rand.Read(p)
}
